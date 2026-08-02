'use strict';
// ─────────────────────────────────────────────────────────────────────────────
// MULTI-TENANT — isolamento entre restaurantes
//
// A regra de ouro: NENHUMA consulta a tabela de dado pode ser escrita sem o
// tenant. Como o backend usa a service key (que passa por cima do RLS do
// Supabase), o isolamento tem que ser garantido no código — e a única forma de
// isso não falhar é tornar impossível esquecer.
//
// Por isso o acesso ao banco passa por tdb(req), que:
//   • select/update/delete → injeta .eq('tenant_id', ...) automaticamente
//   • insert/upsert        → injeta tenant_id no payload
//   • recusa a operação se o tenant não estiver resolvido
//
// Chamar supabase.from('produtos') direto em rota de dado é bug, não estilo.
// ─────────────────────────────────────────────────────────────────────────────

// Tabelas que pertencem a um restaurante. Qualquer tabela nova de DADO entra aqui.
const TABELAS_POR_TENANT = new Set([
  'produtos', 'categorias', 'movimentacoes', 'fechamentos_diarios',
  'pagamentos_comprovantes', 'conta_pendencias', 'conta_memoria',
  'nota_pendencias', 'sinonimos', 'inventarios', 'inventario_itens', 'audit_logs',
]);

// Tabelas globais da plataforma — não têm dono e NÃO devem receber filtro.
const TABELAS_GLOBAIS = new Set(['tenants', 'users', 'produtos_modelo']);

class TenantError extends Error {
  constructor(msg) { super(msg); this.name = 'TenantError'; }
}

// Envelope em volta do query builder do supabase-js. Só existe para garantir o
// tenant; tudo que não for filtrável passa direto para o builder original.
function envolver(builder, tenantId, tabela) {
  const metodosFiltraveis = new Set(['select', 'update', 'delete']);
  return new Proxy(builder, {
    get(alvo, prop) {
      const valor = alvo[prop];
      if (typeof valor !== 'function') return valor;
      return (...args) => {
        const r = valor.apply(alvo, args);
        // Depois de select/update/delete o builder aceita .eq() — é aqui que o
        // tenant entra, antes de qualquer filtro que a rota queira aplicar.
        if (metodosFiltraveis.has(prop) && r && typeof r.eq === 'function') {
          return envolver(r.eq('tenant_id', tenantId), tenantId, tabela);
        }
        return (r && typeof r.then === 'function') ? r : envolver(r, tenantId, tabela);
      };
    },
  });
}

const comTenant = (linha, tenantId) => ({ ...linha, tenant_id: tenantId });

/**
 * Acesso ao banco já preso ao restaurante da requisição.
 * @param {object} supabase cliente supabase-js
 * @param {number} tenantId id do restaurante
 */
function criarAcesso(supabase, tenantId) {
  if (!tenantId) throw new TenantError('Operação sem restaurante definido.');
  return {
    tenantId,
    from(tabela) {
      if (TABELAS_GLOBAIS.has(tabela)) {
        throw new TenantError(`"${tabela}" é global — use o cliente direto, não tdb().`);
      }
      if (!TABELAS_POR_TENANT.has(tabela)) {
        throw new TenantError(`Tabela "${tabela}" não está declarada em TABELAS_POR_TENANT.`);
      }
      const base = supabase.from(tabela);
      return new Proxy(base, {
        get(alvo, prop) {
          if (prop === 'insert' || prop === 'upsert') {
            return (dados, opts) => {
              const comDono = Array.isArray(dados)
                ? dados.map(d => comTenant(d, tenantId))
                : comTenant(dados, tenantId);
              return envolver(alvo[prop](comDono, opts), tenantId, tabela);
            };
          }
          const valor = alvo[prop];
          if (typeof valor !== 'function') return valor;
          return (...args) => {
            const r = valor.apply(alvo, args);
            if ((prop === 'select' || prop === 'update' || prop === 'delete')
                && r && typeof r.eq === 'function') {
              return envolver(r.eq('tenant_id', tenantId), tenantId, tabela);
            }
            return (r && typeof r.then === 'function') ? r : envolver(r, tenantId, tabela);
          };
        },
      });
    },
  };
}

/**
 * Resolve o restaurante da requisição a partir do usuário autenticado.
 * superadmin não tem tenant fixo: escolhe via header, para dar suporte sem
 * precisar do login do cliente. Fora isso, o tenant vem SÓ do banco — nunca de
 * algo que o cliente possa mandar.
 */
function middlewareTenant(req, res, next) {
  const u = req.user;
  if (!u) return res.status(401).json({ erro: 'Sessão expirada.' });

  if (u.role === 'superadmin') {
    // Sem restaurante escolhido ele ainda opera a plataforma (abrir conta, listar,
    // suspender). Só não consegue tocar em dado de restaurante — quem barra isso é o
    // próprio cliente do banco, que recusa consulta sem contexto.
    req.tenantId = Number(req.headers['x-tenant-id'] || req.query?.tenant_id || 0) || null;
    req.superadmin = true;
    return next();
  }
  if (!u.tenant_id) return res.status(403).json({ erro: 'Usuário sem restaurante vinculado.' });
  req.tenantId = Number(u.tenant_id);
  return next();
}

// ─────────────────────────────────────────────────────────────────────────────
// CLIENTE GLOBAL COM TENANT AUTOMÁTICO
//
// O app tem ~200 chamadas `supabase.from(...)` espalhadas. Reescrever uma por uma
// seria demorado e — pior — deixaria a porta aberta para alguém esquecer uma.
// Em vez disso, o tenant viaja no contexto da requisição (AsyncLocalStorage) e o
// próprio cliente aplica o filtro. Toda consulta fica isolada de uma vez, e
// consulta nova nasce isolada sem ninguém precisar lembrar.
// ─────────────────────────────────────────────────────────────────────────────
const { AsyncLocalStorage } = require('async_hooks');
const contexto = new AsyncLocalStorage();

const tenantAtual = () => (contexto.getStore() || {}).tenantId || null;

/** Roda um trecho preso a um restaurante (usado pelo middleware e por jobs). */
function comContexto(tenantId, fn) {
  return contexto.run({ tenantId }, fn);
}

/**
 * Envolve o cliente supabase-js: tabela de dado ganha o tenant do contexto,
 * tabela global passa direto. Sem contexto, tabela de dado é recusada — assim um
 * job que rodar fora de requisição falha alto em vez de vazar dado entre lojas.
 */
function clienteMultiTenant(supabase) {
  return new Proxy(supabase, {
    get(alvo, prop) {
      if (prop !== 'from') {
        const v = alvo[prop];
        return typeof v === 'function' ? v.bind(alvo) : v;
      }
      return (tabela) => {
        if (!TABELAS_POR_TENANT.has(tabela)) return alvo.from(tabela); // global: sem filtro
        const id = tenantAtual();
        if (!id) throw new TenantError(`Consulta a "${tabela}" fora do contexto de um restaurante.`);
        return criarAcesso(alvo, id).from(tabela);
      };
    },
  });
}

/** Middleware: prende a requisição ao restaurante do usuário logado. */
function middlewareContexto(req, res, next) {
  middlewareTenant(req, res, () => {
    // Superadmin pode não ter restaurante escolhido — segue sem contexto e só as rotas
    // de plataforma funcionam. Rota de dado falha no cliente, com mensagem clara.
    if (!req.tenantId) return next();
    return comContexto(req.tenantId, next);
  });
}

module.exports = {
  TABELAS_POR_TENANT, TABELAS_GLOBAIS, TenantError,
  criarAcesso, middlewareTenant,
  clienteMultiTenant, comContexto, middlewareContexto, tenantAtual,
};
