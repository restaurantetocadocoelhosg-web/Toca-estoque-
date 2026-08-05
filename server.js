process.env.TZ = 'America/Sao_Paulo';

const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

// ==================== REDE DE SEGURANÇA POR REQUISIÇÃO ====================
// Achado em 05/08 testando multi-tenant: tenant.js lança TenantError SÍNCRONO
// (não devolve {data,error} como o supabase-js normal) quando falta contexto de
// restaurante -- ex.: superadmin acessando rota de dado sem ter escolhido um
// cliente. A maioria das ~94 rotas nunca precisou de try/catch porque antes do
// multi-tenant nada dentro delas lançava exceção. Express 4 NÃO encaminha erro de
// handler async sozinho pro middleware de erro -- sem isso, a conexão fica
// pendurada pra sempre (o cliente nunca recebe resposta) e o único sinal é um
// unhandledRejection no log, sem ninguém do lado do usuário saber o que houve.
// Envolve toda rota registrada daqui pra frente: throw ou promise rejeitada vira
// next(err) em vez de conexão pendurada.
for (const metodo of ['get', 'post', 'put', 'delete', 'patch']) {
  const original = app[metodo].bind(app);
  app[metodo] = (caminho, ...handlers) => original(caminho, ...handlers.map(h =>
    typeof h === 'function'
      ? (req, res, next) => Promise.resolve(h(req, res, next)).catch(next)
      : h
  ));
}

// ==================== REDE DE SEGURANÇA GLOBAL ====================
// Impede que UMA requisição com erro derrube o processo inteiro (Node 22 mata o
// processo em unhandledRejection por padrão). Loga e mantém o servidor vivo.
process.on('unhandledRejection', (err) => {
  console.error('⚠️ unhandledRejection (servidor segue vivo):', err && err.stack || err);
});
process.on('uncaughtException', (err) => {
  console.error('⚠️ uncaughtException (servidor segue vivo):', err && err.stack || err);
});

// ==================== SUPABASE ====================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ SUPABASE_URL e SUPABASE_SERVICE_KEY são obrigatórios!');
  process.exit(1);
}
// ── MULTI-RESTAURANTE ────────────────────────────────────────────────────────
// Duas variáveis INDEPENDENTES, e isso é proposital:
//   SUPABASE_SCHEMA  onde estão as tabelas   (public em produção, mt no ambiente isolado)
//   MULTI_TENANT     liga o isolamento       (on/off)
//
// Elas precisam ser separadas porque na implantação real o schema continua sendo
// `public` COM o multi-tenant ligado. E porque é isso que dá o rollback: se algo
// der errado depois do deploy, MULTI_TENANT=off devolve o comportamento de hoje na
// hora — as colunas tenant_id ficam no banco, apenas ignoradas.
const { clienteMultiTenant, comContexto, middlewareContexto } = require('./tenant');
const SCHEMA = process.env.SUPABASE_SCHEMA || 'public';
// Restaurante de referência: de onde saem as categorias ao abrir um novo.
const TENANT_MODELO = Number(process.env.TENANT_MODELO || 1);
const MULTI_TENANT = /^(1|on|true|sim)$/i.test(String(process.env.MULTI_TENANT || ''));
const supabaseRaw = createClient(SUPABASE_URL, SUPABASE_KEY, SCHEMA !== 'public' ? { db: { schema: SCHEMA } } : undefined);
const supabase = MULTI_TENANT ? clienteMultiTenant(supabaseRaw) : supabaseRaw;

app.use(cors({ origin: process.env.ALLOWED_ORIGIN || true }));
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, p) => {
    if (p.endsWith('index.html') || p.endsWith('sw.js')) res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  }
}));

// ==================== HELPERS ====================
function nowSP() {
  // Returns ISO 8601 with -03:00 so PostgreSQL TIMESTAMPTZ stores correct UTC
  const partes = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  }).formatToParts(new Date());
  const get = (type) => partes.find(p => p.type === type)?.value || '';
  return `${get('year')}-${get('month')}-${get('day')}T${get('hour')}:${get('minute')}:${get('second')}-03:00`;
}

function dateSP() { return nowSP().slice(0, 10); }

function dateAgoDias(dias) {
  const d = new Date(Date.now() - dias * 86400000);
  const partes = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(d);
  const get = (type) => partes.find(p => p.type === type)?.value || '';
  return `${get('year')}-${get('month')}-${get('day')}`;
}

function normalizeSearch(str) {
  return String(str || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').trim();
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${h}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, original] = stored.split(':');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(original, 'hex'));
}

function sanitizeText(value, max = 120) {
  return String(value ?? '').normalize('NFC').replace(/\s+/g, ' ').trim().slice(0, max);
}

function parsePositiveNumber(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return null;
  return n;
}

function parseNonNegativeNumber(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  return n;
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || '';
}

// Registra erros REAIS do app na agenda da IA (tipo 'erro') para o gestor acompanhar.
async function logErroAgenda(contexto, err, user) {
  try {
    await supabase.from('ia_agenda').insert({
      tipo: 'erro',
      texto: `[${contexto}] ${String((err && err.message) || err || 'erro desconhecido').slice(0, 400)}`,
      usuario_nome: (user && user.nome) ? user.nome : 'sistema',
      criado_em: nowSP()
    });
  } catch(e) {}
}

// ==================== PERMISSÕES (liberações por usuário) ====================
const PERM_KEYS = ['lancar','dia','planilha','contas','exportar','ia','auditoria','alertas','agenda','pendencias','admin','cardapio'];
function permsPorRole(role) {
  // 'pendencias' (resolver itens em dúvida da nota do WhatsApp): admin-only por padrão;
  // admin libera por pessoa no painel de liberações.
  if (role === 'admin')   return { lancar:true, dia:true, planilha:true, contas:true, exportar:true, ia:true, auditoria:true, alertas:true, agenda:true, pendencias:true, admin:true, cardapio:true };
  if (role === 'gerente') return { lancar:true, dia:true, planilha:true, contas:true, exportar:true, ia:true, auditoria:true, alertas:true, agenda:true, pendencias:false, admin:false, cardapio:true };
  return { lancar:true, dia:true, planilha:true, contas:true, exportar:true, ia:false, auditoria:false, alertas:true, agenda:true, pendencias:false, admin:false, cardapio:true }; // operador (padrão = acesso que já tinha; admin libera IA/auditoria/pendencias por pessoa)
}

// No multi-restaurante, o que era único no sistema passa a ser único POR RESTAURANTE.
// Todo upsert precisa refletir isso na chave de conflito, senão o Postgres reclama
// ("no unique constraint matching the ON CONFLICT specification") ou — pior — dois
// restaurantes disputariam a mesma linha.
const chaveConflito = (cols) => MULTI_TENANT ? 'tenant_id,' + cols : cols;

function permsEfetivas(role, permissoes) {
  // superadmin administra a PLATAFORMA, não o restaurante. Sem isso ele caía no
  // fallback de operador e recebia acesso ao app do cliente sem ter escolhido nenhum.
  if (role === 'superadmin') return Object.fromEntries(PERM_KEYS.map(k => [k, false]));
  const base = permsPorRole(role);
  if (permissoes && typeof permissoes === 'object') {
    for (const k of PERM_KEYS) if (typeof permissoes[k] === 'boolean') base[k] = permissoes[k];
  }
  return base;
}

// ==================== SESSÕES ====================
// Usa Supabase se a tabela 'sessions' existir, caso contrário usa memória.
// Para ativar persistência: crie a tabela no dashboard Supabase:
//   CREATE TABLE sessions (token TEXT PRIMARY KEY, user_id INTEGER, username TEXT,
//     nome TEXT, role TEXT, created_at TIMESTAMPTZ DEFAULT NOW(),
//     last_activity TIMESTAMPTZ DEFAULT NOW());
const IDLE_TIMEOUT_MS = 60 * 60 * 1000;
const THRESHOLDS_ALERTA = {
  'Hortifruti': 7, 'Aves': 7, 'Massa Fresca': 7,
  'Carnes Bovinas': 10, 'Carnes Suínas': 10, 'Pescados': 10, 'Laticínios': 10, 'Outras Proteínas': 10,
  'Bebidas': 15, 'Sorvetes': 15,
  'Secos e Grãos': 20, 'Embutidos': 20,
  'Óleos': 30, 'Especiarias': 30,
  'Descartáveis': 45, 'Limpeza': 45,
};
const THRESHOLD_PADRAO = 30;
const memSessions = new Map();
let useSupabaseSessions = false;

async function initSessionsBackend() {
  const { error } = await supabase.from('sessions').select('token').limit(1);
  if (!error) {
    useSupabaseSessions = true;
    console.log('💾 Sessões persistidas no Supabase.');
  } else {
    useSupabaseSessions = false;
    console.log('⚠️  Tabela sessions não encontrada — usando memória. Crie a tabela para persistência.');
  }
}

async function createSession(user) {
  const token = crypto.randomBytes(24).toString('hex');
  if (useSupabaseSessions) {
    await supabase.from('sessions').insert({
      token, user_id: user.id, username: user.username, nome: user.nome,
      role: user.role, last_activity: new Date().toISOString(),
    });
  } else {
    memSessions.set(token, {
      user_id: user.id, username: user.username, nome: user.nome,
      role: user.role, last_activity: Date.now(),
    });
  }
  return token;
}

async function getSession(token) {
  if (useSupabaseSessions) {
    const { data } = await supabase.from('sessions').select('*').eq('token', token).single();
    return data;
  }
  const s = memSessions.get(token);
  if (!s) return null;
  return { ...s, last_activity: new Date(s.last_activity).toISOString() };
}

async function touchSession(token) {
  if (useSupabaseSessions) {
    await supabase.from('sessions').update({ last_activity: new Date().toISOString() }).eq('token', token);
  } else {
    const s = memSessions.get(token);
    if (s) s.last_activity = Date.now();
  }
}

async function deleteSession(token) {
  if (useSupabaseSessions) {
    await supabase.from('sessions').delete().eq('token', token);
  } else {
    memSessions.delete(token);
  }
}

setInterval(async () => {
  if (useSupabaseSessions) {
    const cutoff = new Date(Date.now() - IDLE_TIMEOUT_MS).toISOString();
    await supabase.from('sessions').delete().lt('last_activity', cutoff);
  } else {
    const now = Date.now();
    for (const [token, s] of memSessions.entries()) {
      if (now - s.last_activity > IDLE_TIMEOUT_MS) memSessions.delete(token);
    }
  }
}, 60 * 1000);

function getToken(req) {
  const bearer = req.headers.authorization || '';
  if (bearer.startsWith('Bearer ')) return bearer.slice(7);
  return req.headers['x-auth-token'] || '';
}

// ==================== AUDIT ====================
async function audit(action, details = {}, user = null, ip = '') {
  await supabase.from('audit_logs').insert({
    usuario_id: user?.id || null,
    usuario_nome: user?.nome || user?.username || '',
    role: user?.role || '',
    acao: action,
    detalhes: JSON.stringify(details),
    ip: sanitizeText(ip, 80),
  });
}

// ==================== AUTH MIDDLEWARE ====================
async function auth(req, res, next) {
  const token = getToken(req);
  if (!token) return res.status(401).json({ erro: 'Sessão expirada. Faça login novamente.' });

  const session = await getSession(token);
  if (!session) return res.status(401).json({ erro: 'Sessão expirada. Faça login novamente.' });

  const idleMs = Date.now() - new Date(session.last_activity).getTime();
  if (idleMs > IDLE_TIMEOUT_MS) {
    await deleteSession(token);
    return res.status(401).json({ erro: 'Sessão encerrada por inatividade. Faça login novamente.' });
  }

  const { data: user } = await supabase
    .from('users').select(MULTI_TENANT ? 'id, username, nome, role, active, tenant_id' : 'id, username, nome, role, active')
    .eq('id', session.user_id).single();
  if (!user || !user.active) {
    await deleteSession(token);
    return res.status(401).json({ erro: 'Usuário inativo ou inválido.' });
  }

  await touchSession(token);
  req.user = user;
  req.token = token;
  // No modo multi-restaurante, tudo daqui pra frente roda preso ao restaurante do
  // usuário — inclusive as consultas que as rotas fazem sem saber que ele existe.
  if (MULTI_TENANT) return middlewareContexto(req, res, next);
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role))
      return res.status(403).json({ erro: 'Você não tem permissão para esta ação.' });
    next();
  };
}

async function permsDoRequest(req) {
  let permsCol = null;
  if (req.user && req.user.role !== 'admin') {
    try { const { data: u } = await supabase.from('users').select('permissoes').eq('id', req.user.id).single(); permsCol = u && u.permissoes; } catch(e) {}
  }
  return permsEfetivas(req.user ? req.user.role : null, permsCol);
}

async function usuarioTemPerm(req, key) {
  if (!req.user) return false; // sem usuário logado nunca acessa .role (evita crash de req.user undefined)
  if (req.user.role === 'admin') return true;
  const perms = await permsDoRequest(req);
  return !!perms[key];
}

// Enforcement de liberações no servidor (admin sempre passa).
function requirePerm(key) {
  return async (req, res, next) => {
    if (await usuarioTemPerm(req, key)) return next();
    return res.status(403).json({ erro: 'Acesso não liberado para este recurso. Fale com o administrador.' });
  };
}

// ==================== SEED ====================
// Segurança: SEM senhas default no código (as antigas ficaram no histórico do git).
// Se a env não existir no primeiro boot, gera senha aleatória e imprime UMA vez no log
// do Railway para o responsável anotar e trocar.
function seedPass(envVal, username) {
  if (envVal) return envVal;
  const gerada = require('crypto').randomBytes(9).toString('base64url');
  console.log(`🔑 Senha gerada para "${username}" (anote e troque no primeiro login): ${gerada}`);
  return gerada;
}
async function seed() {
  const { count } = await supabase.from('users').select('id', { count: 'exact', head: true });
  if (count === 0) {
    const seedUsers = [
      { username: 'admin', nome: 'Administrador', role: 'admin', password_hash: hashPassword(seedPass(process.env.ADMIN_PASSWORD, 'admin')), active: 1 },
      { username: 'nayara.admin', nome: 'Nayara', role: 'admin', password_hash: hashPassword(seedPass(process.env.SEED_PASSWORD_NAYARA, 'nayara.admin')), active: 1 },
      { username: 'simone.gerente', nome: 'Simone', role: 'gerente', password_hash: hashPassword(seedPass(process.env.SEED_PASSWORD_SIMONE, 'simone.gerente')), active: 1 },
      { username: 'estoque.operacao', nome: 'Estoque', role: 'operador', password_hash: hashPassword(seedPass(process.env.SEED_PASSWORD_ESTOQUE, 'estoque.operacao')), active: 1 },
    ];
    await supabase.from('users').insert(seedUsers);
    console.log('🔐 Usuários iniciais criados');
  }

  const { count: prodCount } = await supabase.from('produtos').select('id', { count: 'exact', head: true });
  if (prodCount === 0) {
    const seedPath = path.join(__dirname, 'produtos_seed.json');
    if (fs.existsSync(seedPath)) {
      const produtos = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
      for (let i = 0; i < produtos.length; i += 500) {
        const batch = produtos.slice(i, i + 500).map(p => ({ ...p, nome_search: normalizeSearch(p.nome), ativo: 1 }));
        await supabase.from('produtos').insert(batch);
      }
      console.log(`✅ ${produtos.length} produtos carregados no Supabase.`);
    }
  }

  const { data: semNorm } = await supabase.from('produtos').select('id, nome').or('nome_search.is.null,nome_search.eq.');
  if (semNorm && semNorm.length > 0) {
    for (const p of semNorm)
      await supabase.from('produtos').update({ nome_search: normalizeSearch(p.nome) }).eq('id', p.id);
    console.log(`✅ nome_search populado para ${semNorm.length} produtos`);
  }
}

// ==================== RATE LIMITERS ====================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { erro: 'Muitas tentativas de login. Aguarde 15 minutos.' },
});

// Chat IA: cada pergunta pode gerar até 12 chamadas à API Anthropic — limita custo por usuário.
const chatLimiter = rateLimit({
  windowMs: 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => (req.user && String(req.user.id)) || req.ip,
  message: { erro: 'Muitas perguntas seguidas. Aguarde 1 minuto.' },
});

// Webhooks (bot WhatsApp/n8n): protege contra spam de lançamentos e de chamadas à IA.
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { erro: 'Muitas requisições. Aguarde 1 minuto.' },
});

// ==================== AUTH ROUTES ====================
app.post('/api/login', loginLimiter, async (req, res) => {
  const username = sanitizeText(req.body?.username, 40).toLowerCase();
  const password = String(req.body?.password || '');
  if (!username || !password) return res.status(400).json({ erro: 'Usuário e senha são obrigatórios.' });

  const { data: user } = await supabase.from('users').select('*').ilike('username', username).eq('active', 1).single();
  if (!user || !verifyPassword(password, user.password_hash))
    return res.status(401).json({ erro: 'Usuário ou senha inválidos.' });

  // Restaurante suspenso (inadimplência, encerramento) não entra — e a mensagem diz o
  // motivo real em vez de "senha inválida", que faria o cliente achar que é problema dele.
  if (MULTI_TENANT && user.tenant_id) {
    const { data: t } = await supabaseRaw.from('tenants').select('ativo, nome').eq('id', user.tenant_id).maybeSingle();
    if (t && t.ativo === false) {
      return res.status(403).json({ erro: 'Acesso suspenso. Fale com a administração da plataforma para reativar.' });
    }
  }

  const token = await createSession(user);
  // O login acontece ANTES de existir contexto de restaurante (é ele que descobre qual é).
  // Então a auditoria roda explicitamente presa ao restaurante do usuário que acabou de entrar.
  if (MULTI_TENANT && user.tenant_id) {
    await comContexto(Number(user.tenant_id), () => audit('login', { username: user.username }, user, getClientIp(req)));
  } else if (!MULTI_TENANT) {
    await audit('login', { username: user.username }, user, getClientIp(req));
  }
  res.json({ token, user: { id: user.id, username: user.username, nome: user.nome, role: user.role } });
});

app.post('/api/logout', auth, async (req, res) => {
  await deleteSession(req.token);
  await audit('logout', {}, req.user, getClientIp(req));
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  let permsCol = null;
  try { const { data: u } = await supabase.from('users').select('permissoes').eq('id', req.user.id).single(); permsCol = u && u.permissoes; } catch(e) {}
  const perms = permsEfetivas(req.user.role, permsCol);
  res.json({
    user: { id: req.user.id, username: req.user.username, nome: req.user.nome, role: req.user.role },
    permissions: {
      pode_resetar: req.user.role === 'admin',
      pode_editar_produto: ['admin', 'gerente'].includes(req.user.role),
      pode_exportar: perms.exportar,
      pode_lancar: perms.lancar,
      pode_dia: perms.dia,
      pode_planilha: perms.planilha,
      pode_contas: perms.contas,
    },
    permissoes: perms,
  });
});

app.put('/api/me', auth, async (req, res) => {
  const nome = sanitizeText(req.body?.nome, 60);
  if (!nome || nome.length < 2) return res.status(400).json({ erro: 'Nome inválido.' });
  await supabase.from('users').update({ nome }).eq('id', req.user.id);
  await audit('editar_perfil', { nome_anterior: req.user.nome, nome_novo: nome }, req.user, getClientIp(req));
  res.json({ ok: true, nome });
});

app.post('/api/change-password', auth, async (req, res) => {
  const current = String(req.body?.current_password || '');
  const next = String(req.body?.new_password || '');
  const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!verifyPassword(current, user.password_hash)) return res.status(400).json({ erro: 'Senha atual incorreta.' });
  if (next.length < 6) return res.status(400).json({ erro: 'A nova senha precisa ter pelo menos 6 caracteres.' });
  await supabase.from('users').update({ password_hash: hashPassword(next) }).eq('id', req.user.id);
  await audit('change_password', {}, req.user, getClientIp(req));
  res.json({ ok: true });
});

// ==================== ROTAS PRODUTOS ====================
app.get('/api/produtos', auth, async (req, res) => {
  const { cat, status, q, arquivados } = req.query;
  const arquivar = arquivados === '1' && req.user.role === 'admin';
  const comFiltroAtivo = (query) => arquivar ? query.eq('ativo', 0) : query.or('ativo.eq.1,ativo.is.null');

  let rows;
  if (q) {
    const qq = sanitizeText(q, 100);
    const qn = normalizeSearch(qq);
    // Apelido/sinônimo cadastrado — mesma correção da busca de Lançar (commit 2b0ae95): sem
    // isso, a aba Estoque e o Admin (gestão de produtos) TAMBÉM não achavam produto por
    // apelido, só por pedaço do nome. Junta o match de apelido (se houver) com a busca normal.
    const { data: sino } = await supabase.from('sinonimos').select('produto_nome').eq('termo', qn).limit(1);
    let viaApelido = [];
    if (sino && sino.length) {
      const { data } = await comFiltroAtivo(supabase.from('produtos').select('*').eq('nome', sino[0].produto_nome));
      viaApelido = data || [];
    }
    let qResto = comFiltroAtivo(supabase.from('produtos').select('*').or(`nome_search.ilike.%${qn}%,codigo.ilike.%${qq.toUpperCase()}%`));
    if (cat) qResto = qResto.eq('categoria', sanitizeText(cat, 80));
    const { data: resto, error } = await qResto.order('categoria').order('nome');
    if (error) return res.status(500).json({ erro: 'Erro ao buscar produtos.' });
    const vistos = new Set(viaApelido.map(p => p.id));
    rows = [...viaApelido, ...(resto || []).filter(p => !vistos.has(p.id))];
  } else {
    let query = comFiltroAtivo(supabase.from('produtos').select('*'));
    if (cat) query = query.eq('categoria', sanitizeText(cat, 80));
    const { data, error } = await query.order('categoria').order('nome');
    if (error) return res.status(500).json({ erro: 'Erro ao buscar produtos.' });
    rows = data;
  }

  let filtered = rows;
  if (status === 'zerado') filtered = rows.filter(r => r.qtd === 0);
  else if (status === 'critico') filtered = rows.filter(r => r.qtd > 0 && r.qtd <= r.minimo * 0.5);
  else if (status === 'atencao') filtered = rows.filter(r => r.qtd > r.minimo * 0.5 && r.qtd < r.minimo);
  else if (status === 'ok') filtered = rows.filter(r => r.qtd >= r.minimo);
  res.json(filtered);
});

app.get('/api/produtos/buscar', auth, async (req, res) => {
  const q = sanitizeText(req.query?.q, 100);
  if (!q || q.length < 2) return res.json([]);
  const qn = normalizeSearch(q);
  const SEL_BUSCA = 'id, nome, codigo, categoria, unidade, qtd, minimo, custo';

  // Apelido/sinônimo cadastrado (ex.: "pf frango" -> "File de Frango") — SEM isso, a busca
  // manual da tela de Lançar só achava por pedaço do nome, enquanto a IA/WhatsApp já
  // resolviam apelido (buscarProdutos()). Medido: 221 dos 305 apelidos cadastrados (72%)
  // não são substring do nome real do produto — ou seja, a maioria dos apelidos que a
  // equipe "ensinou" ao sistema simplesmente não funcionava aqui. Suspeita forte de ser a
  // causa real de "procurei e não achei, então não lancei".
  const { data: sino } = await supabase.from('sinonimos').select('produto_nome').eq('termo', qn).limit(1);
  let viaApelido = [];
  if (sino && sino.length) {
    const { data } = await supabase.from('produtos').select(SEL_BUSCA).eq('nome', sino[0].produto_nome).or('ativo.eq.1,ativo.is.null').limit(1);
    viaApelido = data || [];
  }

  const { data: resto } = await supabase.from('produtos').select(SEL_BUSCA)
    .or(`nome_search.ilike.%${qn}%,codigo.ilike.%${q.toUpperCase()}%`).or('ativo.eq.1,ativo.is.null').order('nome').limit(15);

  // Apelido primeiro (é o mais específico), sem duplicar; completa até 15.
  const vistos = new Set(viaApelido.map(p => p.id));
  const combinado = [...viaApelido, ...(resto || []).filter(p => !vistos.has(p.id))].slice(0, 15);
  res.json(combinado);
});

// Lista categorias: tabela `categorias` (criadas no Admin) + as derivadas dos produtos ativos.
app.get('/api/categorias', auth, async (req, res) => {
  try {
    const [{ data: tab }, { data: dosProds }] = await Promise.all([
      supabase.from('categorias').select('nome'),
      supabase.from('produtos').select('categoria').or('ativo.eq.1,ativo.is.null'),
    ]);
    const cats = [...new Set([...(tab || []).map(r => r.nome), ...(dosProds || []).map(r => r.categoria)].filter(Boolean))]
      .sort((a, b) => a.localeCompare(b, 'pt-BR'));
    res.json(cats);
  } catch(e) { res.status(500).json({ erro: 'Erro ao listar categorias.' }); }
});

// ==================== GESTÃO DE CATEGORIAS (Admin) ====================
// CATEGORIA é ESTRUTURA, não dado do cliente: é ela que liga produto → conta do
// plano de contas (MAPA_CONTA_COMPRA). Se o dono do restaurante criar 'Carnes XYZ' ou
// renomear 'Hortifruti', a compra dele para de classificar e o CMV/Prime Cost quebram
// em silêncio. Por isso, no modo plataforma, só a administração mexe nisso — foi o que
// o Rubens pediu: 'ele não poderia mudar coisas que interferem no relatório'.
function requireEstrutura(...roles) {
  return (req, res, next) => {
    if (MULTI_TENANT && req.user?.role !== 'superadmin') {
      return res.status(403).json({ erro: 'As categorias fazem parte da estrutura do relatório e são definidas pela plataforma. Fale com a administração se precisar de uma nova.' });
    }
    return requireRole(...roles)(req, res, next);
  };
}

app.post('/api/categorias', auth, requireEstrutura('admin', 'gerente'), async (req, res) => {
  const nome = sanitizeText(req.body?.nome, 80);
  if (!nome || nome.length < 2) return res.status(400).json({ erro: 'Nome de categoria inválido.' });
  const { error } = await supabase.from('categorias').insert({ nome });
  if (error) {
    if (error.code === '23505') return res.status(400).json({ erro: 'Esta categoria já existe.' });
    return res.status(500).json({ erro: 'Erro ao criar categoria.' });
  }
  await audit('criar_categoria', { nome }, req.user, getClientIp(req));
  res.json({ ok: true, nome });
});

app.put('/api/categorias/renomear', auth, requireEstrutura('admin'), async (req, res) => {
  const de = sanitizeText(req.body?.de, 80);
  const para = sanitizeText(req.body?.para, 80);
  if (!de || !para || de === para) return res.status(400).json({ erro: 'Informe a categoria atual e o novo nome.' });
  const { data: afetados } = await supabase.from('produtos').select('id').eq('categoria', de);
  await supabase.from('produtos').update({ categoria: para }).eq('categoria', de);
  await supabase.from('categorias').delete().eq('nome', de);
  await supabase.from('categorias').upsert({ nome: para }, { onConflict: chaveConflito('nome') });
  await audit('renomear_categoria', { de, para, produtos_afetados: (afetados || []).length }, req.user, getClientIp(req));
  res.json({ ok: true, produtos_afetados: (afetados || []).length });
});

app.delete('/api/categorias/:nome', auth, requireEstrutura('admin'), async (req, res) => {
  const nome = sanitizeText(req.params.nome, 80);
  const { count } = await supabase.from('produtos').select('id', { count: 'exact', head: true }).eq('categoria', nome).or('ativo.eq.1,ativo.is.null');
  if (count > 0) return res.status(400).json({ erro: `Categoria em uso por ${count} produto(s). Mova-os antes de excluir.` });
  await supabase.from('categorias').delete().eq('nome', nome);
  await audit('excluir_categoria', { nome }, req.user, getClientIp(req));
  res.json({ ok: true });
});

// ==================== GRUPOS DE TROCA (produtos que se substituem) ====================
// Ex.: Alcatra ↔ Coxão Mole — compra alterna pelo preço. Alerta de parado e lista de
// compras passam a olhar o GRUPO: se um irmão girou/tem estoque, o outro não alarma.
app.get('/api/grupos', auth, async (req, res) => {
  const { data } = await supabase.from('produtos').select('id, nome, codigo, categoria, qtd, unidade, grupo_troca')
    .not('grupo_troca', 'is', null).or('ativo.eq.1,ativo.is.null').order('grupo_troca').order('nome');
  const grupos = {};
  for (const p of (data || [])) {
    if (!grupos[p.grupo_troca]) grupos[p.grupo_troca] = [];
    grupos[p.grupo_troca].push(p);
  }
  res.json(Object.entries(grupos).map(([nome, produtos]) => ({ nome, produtos })));
});

app.post('/api/grupos', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const nome = sanitizeText(req.body?.nome, 60);
  const ids = Array.isArray(req.body?.produto_ids) ? req.body.produto_ids.map(Number).filter(Number.isFinite) : [];
  if (!nome || nome.length < 2) return res.status(400).json({ erro: 'Nome do grupo inválido.' });
  if (ids.length < 1) return res.status(400).json({ erro: 'Selecione ao menos 1 produto.' });
  await supabase.from('produtos').update({ grupo_troca: nome }).in('id', ids);
  await audit('grupo_troca', { nome, produto_ids: ids }, req.user, getClientIp(req));
  res.json({ ok: true, nome, total: ids.length });
});

app.post('/api/grupos/remover-produto', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const id = Number(req.body?.produto_id);
  if (!Number.isFinite(id)) return res.status(400).json({ erro: 'Produto inválido.' });
  await supabase.from('produtos').update({ grupo_troca: null }).eq('id', id);
  res.json({ ok: true });
});

app.delete('/api/grupos/:nome', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const nome = sanitizeText(req.params.nome, 60);
  await supabase.from('produtos').update({ grupo_troca: null }).eq('grupo_troca', nome);
  await audit('grupo_troca_excluir', { nome }, req.user, getClientIp(req));
  res.json({ ok: true });
});

app.post('/api/produtos', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const nome = sanitizeText(req.body?.nome, 120);
  const categoria = sanitizeText(req.body?.categoria, 80);
  const unidade = sanitizeText(req.body?.unidade, 20);
  const minimo = parseNonNegativeNumber(req.body?.minimo ?? 1);
  const custo = parseNonNegativeNumber(req.body?.custo ?? 0);
  const qtd = parseNonNegativeNumber(req.body?.qtd ?? 0);
  if (!nome || !categoria || !unidade) return res.status(400).json({ erro: 'Nome, categoria e unidade são obrigatórios.' });
  const { data: novo, error } = await supabase.from('produtos').insert({
    nome, nome_search: normalizeSearch(nome), categoria, unidade,
    qtd: qtd ?? 0, minimo: minimo ?? 1, custo: custo ?? 0, ativo: 1,
  }).select().single();
  if (error) {
    if (error.code === '23505') return res.status(400).json({ erro: 'Produto já cadastrado com este nome.' });
    return res.status(500).json({ erro: 'Erro ao cadastrar produto.' });
  }
  await audit('criar_produto', { nome, categoria, unidade }, req.user, getClientIp(req));
  res.json({ ok: true, produto: novo });
});

app.put('/api/produtos/:id', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const { data: produto } = await supabase.from('produtos').select('*').eq('id', req.params.id).single();
  if (!produto) return res.status(404).json({ erro: 'Produto não encontrado.' });
  const nome = req.body?.nome !== undefined ? sanitizeText(req.body.nome, 120) : produto.nome;
  const categoria = req.body?.categoria !== undefined ? sanitizeText(req.body.categoria, 80) : produto.categoria;
  const unidade = req.body?.unidade !== undefined ? sanitizeText(req.body.unidade, 20) : produto.unidade;
  const custo = req.body?.custo !== undefined ? parseNonNegativeNumber(req.body.custo) : produto.custo;
  const minimo = req.body?.minimo !== undefined ? parseNonNegativeNumber(req.body.minimo) : produto.minimo;
  if (!nome || !categoria || !unidade) return res.status(400).json({ erro: 'Nome, categoria e unidade são obrigatórios.' });
  if (custo === null || minimo === null) return res.status(400).json({ erro: 'Custo e mínimo devem ser números válidos.' });
  const updates = { nome, nome_search: normalizeSearch(nome), categoria, unidade, custo, minimo };
  if (req.body?.grupo_troca !== undefined) updates.grupo_troca = sanitizeText(req.body.grupo_troca, 60) || null;
  const { data: atualizado, error } = await supabase.from('produtos').update(updates).eq('id', req.params.id).select().single();
  if (error) {
    if (error.code === '23505') return res.status(400).json({ erro: 'Já existe um produto com este nome.' });
    return res.status(500).json({ erro: 'Erro ao atualizar produto.' });
  }
  await audit('produto_update', { id: produto.id, nome_anterior: produto.nome, nome, categoria, unidade, custo, minimo }, req.user, getClientIp(req));
  res.json({ ok: true, produto: atualizado });
});

app.put('/api/produtos/:id/arquivar', auth, requireRole('admin'), async (req, res) => {
  const { data: prod } = await supabase.from('produtos').select('*').eq('id', req.params.id).single();
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });
  const novoAtivo = prod.ativo === 0 ? 1 : 0;
  await supabase.from('produtos').update({ ativo: novoAtivo }).eq('id', req.params.id);
  await audit('produto_arquivar', { produto_id: prod.id, nome: prod.nome, ativo: novoAtivo }, req.user, getClientIp(req));
  res.json({ ok: true, ativo: novoAtivo });
});

app.get('/api/produtos/:id/historico', auth, async (req, res) => {
  const { data: prod } = await supabase.from('produtos').select('nome, qtd, unidade, ativo').eq('id', req.params.id).single();
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });
  const { data: movs } = await supabase.from('movimentacoes')
    .select('tipo, qtd, unidade, motivo, responsavel, obs, created_at')
    .eq('produto_id', req.params.id).order('id', { ascending: false }).limit(20);
  res.json({ produto: prod, movimentacoes: movs || [] });
});

// Resumo rico de um produto para a tela de detalhe (ao clicar na aba Produtos).
app.get('/api/produtos/:id/resumo', auth, async (req, res) => {
  const id = req.params.id;
  const { data: p } = await supabase.from('produtos').select('*').eq('id', id).single();
  if (!p) return res.status(404).json({ erro: 'Produto não encontrado.' });
  const desde30 = dateAgoDias(30);
  const [ultEnt, ultSai, m30q, timeline] = await Promise.all([
    supabase.from('movimentacoes').select('qtd, unidade, responsavel, created_at').eq('produto_id', id).eq('tipo', 'Entrada').order('created_at', { ascending: false }).limit(1),
    supabase.from('movimentacoes').select('qtd, unidade, responsavel, created_at').eq('produto_id', id).in('tipo', ['Saída', 'Perda']).order('created_at', { ascending: false }).limit(1),
    supabase.from('movimentacoes').select('tipo, qtd, valor').eq('produto_id', id).gte('created_at', desde30 + 'T00:00:00-03:00'),
    supabase.from('movimentacoes').select('tipo, qtd, unidade, motivo, responsavel, obs, created_at').eq('produto_id', id).order('id', { ascending: false }).limit(15),
  ]);
  const m30 = m30q.data || [];
  const agg = { entrada: 0, saida: 0, perda: 0, ajuste: 0, n_entrada: 0, n_saida: 0, n_perda: 0, n_ajuste: 0, valor_entrada: 0 };
  for (const m of m30) {
    if (m.tipo === 'Entrada') { agg.entrada += Number(m.qtd); agg.n_entrada++; agg.valor_entrada += Number(m.valor || 0); }
    else if (m.tipo === 'Saída') { agg.saida += Number(m.qtd); agg.n_saida++; }
    else if (m.tipo === 'Perda') { agg.perda += Number(m.qtd); agg.n_perda++; }
    else if (m.tipo === 'Ajuste') { agg.ajuste += Number(m.qtd); agg.n_ajuste++; }
  }
  const consumo30 = agg.saida + agg.perda;
  const mediaDiaria = consumo30 / 30;
  const qtd = Number(p.qtd), minimo = Number(p.minimo);
  const status = qtd === 0 ? 'ZERADO' : qtd <= minimo * 0.5 ? 'CRITICO' : qtd < minimo ? 'ATENCAO' : 'OK';
  const cobertura = mediaDiaria > 0 ? Math.floor(qtd / mediaDiaria) : null; // dias que o estoque atual dura
  res.json({
    produto: { id: p.id, nome: p.nome, codigo: p.codigo || null, categoria: p.categoria, unidade: p.unidade,
      qtd, minimo, custo: Number(p.custo || 0), grupo_troca: p.grupo_troca || null,
      valor_em_estoque: Number((qtd * Number(p.custo || 0)).toFixed(2)), status, ativo: p.ativo },
    ultima_entrada: (ultEnt.data && ultEnt.data[0]) || null,
    ultima_saida: (ultSai.data && ultSai.data[0]) || null,
    resumo30: { ...agg, entrada: Number(agg.entrada.toFixed(3)), saida: Number(agg.saida.toFixed(3)),
      perda: Number(agg.perda.toFixed(3)), consumo: Number(consumo30.toFixed(3)),
      media_diaria: Number(mediaDiaria.toFixed(2)), valor_entrada: Number(agg.valor_entrada.toFixed(2)) },
    cobertura_dias: cobertura,
    timeline: timeline.data || [],
  });
});

// ==================== ROTAS MOVIMENTAÇÕES ====================
app.post('/api/movimentacoes', auth, async (req, res) => {
  const produto_id = Number(req.body?.produto_id || 0);
  const produto_nome = sanitizeText(req.body?.produto_nome, 120);
  const tipo = sanitizeText(req.body?.tipo, 20);
  const motivo = sanitizeText(req.body?.motivo, 80);
  let obs = sanitizeText(req.body?.obs, 200);
  const qtdInput = req.body?.qtd;

  if ((!produto_id && !produto_nome) || !['Entrada', 'Saída', 'Perda', 'Ajuste'].includes(tipo))
    return res.status(400).json({ erro: 'Produto e tipo válidos são obrigatórios.' });

  const { prod, opcoes } = await acharProdutoPorIdOuNome(produto_id, produto_nome);
  if (opcoes) return res.status(400).json({ erro: `Vários produtos batem com "${produto_nome}". Seja mais específico: ${opcoes.slice(0, 5).map(p => p.nome).join(' | ')}` });
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado. Pesquise e selecione o item novamente na lista.' });

  let qtd = tipo === 'Ajuste' ? parseNonNegativeNumber(qtdInput) : parsePositiveNumber(qtdInput);
  if (qtd === null)
    return res.status(400).json({ erro: tipo === 'Ajuste' ? 'Ajuste deve ser zero ou maior.' : 'Quantidade deve ser maior que zero.' });

  const custoBody = req.body?.custo === '' || req.body?.custo === null || req.body?.custo === undefined
    ? null : parseNonNegativeNumber(req.body?.custo);
  if (req.body?.custo !== '' && req.body?.custo !== null && req.body?.custo !== undefined && custoBody === null)
    return res.status(400).json({ erro: 'Custo informado é inválido.' });

  // Trava de contagem desatualizada: Ajuste em produto que se movimentou há pouco.
  // A causa nº1 de "produto que volta": contagem feita ANTES das saídas da noite,
  // digitada depois — o ajuste apaga as saídas. Avisa e pede confirmação (forcar).
  if (tipo === 'Ajuste' && !req.body.forcar) {
    const corte = new Date(Date.now() - 6 * 3600000).toISOString();
    const { data: recentes } = await supabase.from('movimentacoes')
      .select('tipo, qtd, unidade, responsavel, created_at').eq('produto_id', prod.id)
      .in('tipo', ['Entrada', 'Saída', 'Perda']).gte('created_at', corte)
      .order('created_at', { ascending: false }).limit(10);
    if (recentes && recentes.length) {
      const resumo = recentes.slice(0, 5).map(r => {
        const h = new Date(r.created_at).toLocaleTimeString('pt-BR', { timeZone: 'America/Sao_Paulo', hour: '2-digit', minute: '2-digit' });
        return `${r.tipo} de ${r.qtd} ${r.unidade || ''} às ${h} (${r.responsavel || '?'})`;
      }).join('; ');
      return res.status(409).json({
        alerta: true, codigo: 'AJUSTE_COM_MOVIMENTO_RECENTE',
        msg: `${prod.nome} teve ${recentes.length} movimentação(ões) nas últimas 6 horas: ${resumo}. Se a sua contagem foi feita ANTES disso, este ajuste vai APAGAR esses lançamentos. Confirme só se contou AGORA.`
      });
    }
  }

  // Detecção de anomalia para Saída/Perda
  if (tipo === 'Saída' || tipo === 'Perda') {
    const trintaDias = dateAgoDias(30);
    const { data: hist } = await supabase.from('movimentacoes')
      .select('qtd').eq('produto_id', prod.id)
      .in('tipo', ['Saída', 'Perda']).gte('created_at', trintaDias + 'T00:00:00-03:00');
    if (hist && hist.length >= 5) {
      const totalConsumo = hist.reduce((s, m) => s + Number(m.qtd), 0);
      const mediaDiaria = totalConsumo / 30;
      if (mediaDiaria > 0 && qtd > mediaDiaria * 3) {
        if (req.user.role === 'operador') {
          // Bloqueio SEM bypass por `forcar` — antes o operador conseguia auto-confirmar o
          // próprio alerta pelo mesmo diálogo genérico do app, o que anulava a exigência de
          // "chamar o gerente". Agora só passa se quem lançar de fato tiver role gerente/admin.
          return res.status(409).json({
            alerta: true, codigo: 'QUANTIDADE_SUSPEITA',
            media_diaria: Number(mediaDiaria.toFixed(2)), qtd_lancada: qtd, unidade: prod.unidade,
            msg: `Quantidade ${qtd} ${prod.unidade} é ${(qtd/mediaDiaria).toFixed(1)}× acima da média diária (${mediaDiaria.toFixed(1)} ${prod.unidade}). Peça pra um gerente ou admin lançar esse item.`
          });
        } else if (!req.body.forcar) {
          req.body.obs = (req.body.obs ? req.body.obs + ' | ' : '') +
            `⚠️ Anomalia: ${qtd} ${prod.unidade} = ${(qtd/mediaDiaria).toFixed(1)}× média diária`;
          obs = sanitizeText(req.body.obs, 200);
        }
      }
    }
  }

  // Blindagem de concorrência: trava otimista com retry — duas baixas/entradas
  // simultâneas do mesmo produto não se sobrescrevem (sem perda de dado).
  let novaQtd, valor, qtdAntes, custoUnit, prodAtual = prod, sucesso = false;
  for (let tent = 0; tent < 4 && !sucesso; tent++) {
    qtdAntes = Number(prodAtual.qtd);
    if (tipo === 'Entrada') novaQtd = Number((qtdAntes + qtd).toFixed(3));
    else if (tipo === 'Saída' || tipo === 'Perda') {
      if (qtd > qtdAntes) return res.status(400).json({ erro: `Estoque insuficiente. Disponível: ${prodAtual.qtd} ${prodAtual.unidade}.` });
      novaQtd = Number((qtdAntes - qtd).toFixed(3));
    } else if (tipo === 'Ajuste') novaQtd = Number(qtd.toFixed(3));
    custoUnit = custoBody !== null ? custoBody : Number(prodAtual.custo || 0);
    const valorBase = tipo === 'Ajuste' ? Math.abs(novaQtd - qtdAntes) : qtd;
    valor = Number((custoUnit * valorBase).toFixed(2));
    const updateData = { qtd: novaQtd };
    if (tipo === 'Entrada' && custoBody !== null) updateData.custo = custoUnit;
    const { data: upd } = await supabase.from('produtos').update(updateData).eq('id', prodAtual.id).eq('qtd', prodAtual.qtd).select('id');
    if (upd && upd.length) { sucesso = true; break; }
    const { data: re } = await supabase.from('produtos').select('*').eq('id', prod.id).single();
    if (!re) return res.status(500).json({ erro: 'Erro ao atualizar estoque.' });
    prodAtual = re;
  }
  if (!sucesso) return res.status(409).json({ erro: 'Outro lançamento simultâneo alterou o estoque. Tente novamente.' });

  const { data: movIns, error: movErr } = await supabase.from('movimentacoes').insert({
    produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
    tipo, qtd: tipo === 'Ajuste' ? novaQtd : qtd, unidade: prod.unidade,
    custo: custoUnit, valor, motivo, responsavel: req.user.nome, obs,
    qtd_antes: qtdAntes, qtd_depois: novaQtd,
    created_at: nowSP(),
  }).select('id').single();
  if (movErr) {
    await supabase.from('produtos').update({ qtd: qtdAntes, custo: prodAtual.custo }).eq('id', prod.id).eq('qtd', novaQtd);
    return res.status(500).json({ erro: 'Erro ao registrar movimentação.' });
  }

  await audit('movimentacao', { produto_id: prod.id, produto_nome: prod.nome, tipo, qtd, nova_qtd: novaQtd, motivo }, req.user, getClientIp(req));
  if (tipo === 'Entrada' && motivo === 'Compra') {
    await lancarCompraNasContas({ produto: prod, qtd, custoUnit, responsavel: req.user.nome, obs, movId: movIns?.id });
  }
  const { data: prodAtualizado } = await supabase.from('produtos').select('*').eq('id', prod.id).single();
  res.json({ ok: true, produto: prodAtualizado });
});

app.delete('/api/movimentacoes/:id', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const { data: mov } = await supabase.from('movimentacoes').select('*').eq('id', req.params.id).single();
  if (!mov) return res.status(404).json({ erro: 'Movimentação não encontrada.' });
  const { data: prod } = await supabase.from('produtos').select('*').eq('id', mov.produto_id).single();
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });
  let novaQtd = Number(prod.qtd);
  if (mov.tipo === 'Entrada') {
    novaQtd = Number((novaQtd - Number(mov.qtd)).toFixed(3));
    if (novaQtd < 0) return res.status(400).json({ erro: `Não é possível cancelar: estoque ficaria negativo (${prod.qtd} disponível).` });
  } else if (mov.tipo === 'Saída' || mov.tipo === 'Perda') {
    novaQtd = Number((novaQtd + Number(mov.qtd)).toFixed(3));
  } else if (mov.tipo === 'Ajuste') {
    return res.status(400).json({ erro: 'Ajustes não podem ser cancelados. Use um novo Ajuste para corrigir.' });
  }
  // Trava otimista com retry (mesmo padrão do lançamento): cancelamento simultâneo a
  // outro lançamento não sobrescreve estoque. Delete só depois do update confirmado.
  let prodAtual = prod, sucesso = false;
  for (let tent = 0; tent < 4 && !sucesso; tent++) {
    const base = Number(prodAtual.qtd);
    if (mov.tipo === 'Entrada') {
      novaQtd = Number((base - Number(mov.qtd)).toFixed(3));
      if (novaQtd < 0) return res.status(400).json({ erro: `Não é possível cancelar: estoque ficaria negativo (${prodAtual.qtd} disponível).` });
    } else {
      novaQtd = Number((base + Number(mov.qtd)).toFixed(3));
    }
    const { data: upd } = await supabase.from('produtos').update({ qtd: novaQtd }).eq('id', prodAtual.id).eq('qtd', prodAtual.qtd).select('id');
    if (upd && upd.length) { sucesso = true; break; }
    const { data: re } = await supabase.from('produtos').select('*').eq('id', prod.id).single();
    if (!re) return res.status(500).json({ erro: 'Erro ao atualizar estoque.' });
    prodAtual = re;
  }
  if (!sucesso) return res.status(409).json({ erro: 'Outro lançamento simultâneo alterou o estoque. Tente novamente.' });
  const { error: delErr } = await supabase.from('movimentacoes').delete().eq('id', mov.id);
  if (delErr) {
    // Reverte o estoque se não conseguiu apagar a movimentação (operação não pode ficar pela metade).
    await supabase.from('produtos').update({ qtd: prodAtual.qtd }).eq('id', prod.id).eq('qtd', novaQtd);
    return res.status(500).json({ erro: 'Erro ao cancelar movimentação. Estoque não foi alterado.' });
  }
  // Cancelou a compra → some também das Contas/Planilha/Relatórios (só lançamentos
  // automáticos vinculados; pagamento digitado na mão na aba Contas nunca é tocado).
  try {
    await supabase.from('pagamentos_comprovantes').delete()
      .eq('mov_id', mov.id).in('origem', ['estoque-auto', 'estoque-backfill']);
  } catch (e) { console.error('contas-auto delete:', e.message); }
  await audit('cancelar_movimentacao', { mov_id: mov.id, produto: mov.produto_nome, tipo: mov.tipo, qtd: mov.qtd }, req.user, getClientIp(req));
  res.json({ ok: true, novaQtd });
});

app.get('/api/movimentacoes', auth, async (req, res) => {
  const tipo = sanitizeText(req.query?.tipo, 20);
  const q = sanitizeText(req.query?.q, 100);
  const limit = Math.min(Math.max(parseInt(req.query?.limit || '200', 10), 1), 500);
  let query = supabase.from('movimentacoes').select('*');
  if (tipo) query = query.eq('tipo', tipo);
  if (q) {
    // Busca acento-insensível: o termo é normalizado (filé→file) e o histórico já está
    // sem acento; ainda acha por código/apelido (matcher) e por motivo/obs/responsável.
    const qNorm = normalizeSearch(q);
    const qSafe = q.replace(/[,()]/g, ' ').trim();
    const { produtos: prov } = await buscarProdutos(q);
    const ids = (prov || []).map(p => p.id).filter(Boolean);
    const ors = [`produto_nome.ilike.%${qNorm}%`, `motivo.ilike.%${qSafe}%`, `obs.ilike.%${qSafe}%`, `responsavel.ilike.%${qSafe}%`];
    if (ids.length) ors.push(`produto_id.in.(${ids.join(',')})`);
    query = query.or(ors.join(','));
  }
  const dataInicio = req.query?.data_inicio;
  const dataFim = req.query?.data_fim;
  if (dataInicio) query = query.gte('created_at', dataInicio + 'T00:00:00-03:00');
  if (dataFim) query = query.lte('created_at', dataFim + 'T23:59:59-03:00');
  query = query.order('id', { ascending: false }).limit(limit);
  const { data } = await query;
  res.json(data || []);
});

// ==================== SNAPSHOT DIÁRIO ====================
async function ensureSnapshotDiario() {
  try {
    const hoje = dateSP();
    const { count } = await supabase.from('snapshots_diarios')
      .select('id', { count: 'exact', head: true }).eq('data', hoje);
    if (count > 0) return;
    const { data: prods } = await supabase.from('produtos')
      .select('id, nome, categoria, qtd, unidade').or('ativo.eq.1,ativo.is.null');
    if (!prods?.length) return;
    const rows = prods.map(p => ({
      produto_id: p.id, produto_nome: p.nome, categoria: p.categoria,
      qtd: p.qtd, unidade: p.unidade, data: hoje,
    }));
    await supabase.from('snapshots_diarios').upsert(rows,
      { onConflict: chaveConflito('produto_id,data'), ignoreDuplicates: true });
  } catch(e) { console.error('Snapshot diario erro:', e.message); }
}

// ==================== DASHBOARD ====================
app.get('/api/dashboard', auth, async (req, res) => {
  ensureSnapshotDiario().catch(() => {});
  // Mesmo filtro de ativo que /api/produtos e a aba Estoque usam — sem isso, produto
  // arquivado/descontinuado (ativo=0) entrava na contagem e inflava "Zerados"/"Críticos"
  // no dashboard, sem bater com o que a pessoa via ao entrar na lista de verdade.
  const { data: produtos } = await supabase.from('produtos').select('qtd, minimo, custo').or('ativo.eq.1,ativo.is.null');
  const all = produtos || [];
  const zerados = all.filter(p => Number(p.qtd) === 0).length;
  const criticos = all.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5).length;
  const atencao = all.filter(p => Number(p.qtd) > Number(p.minimo) * 0.5 && Number(p.qtd) < Number(p.minimo)).length;
  const valorTotal = all.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0);
  const hojeSP = dateSP();
  const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true })
    .gte('created_at', hojeSP + 'T00:00:00-03:00').lte('created_at', hojeSP + 'T23:59:59-03:00');
  const { data: ultimos } = await supabase.from('movimentacoes').select('*').order('id', { ascending: false }).limit(8);
  res.json({ zerados, criticos, atencao, valorTotal, lancHoje: lancHoje || 0, ultimos: ultimos || [] });
});

// ==================== REALIDADE DO DIA ====================
function validarDataISO(data) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(data || '')) ? String(data) : dateSP();
}

function isDataISO(data) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(data || ''));
}

function dataISOOuNull(data) {
  const s = String(data || '').slice(0, 10);
  return isDataISO(s) ? s : null;
}

function addDiasISO(data, dias) {
  const [y, m, d] = String(data).split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d + dias)).toISOString().slice(0, 10);
}

function dataBR(data) {
  return String(data).split('-').reverse().join('/');
}

function mesAtualISO() {
  return dateSP().slice(0, 7);
}

function validarMesISO(mes) {
  return /^\d{4}-\d{2}$/.test(String(mes || '')) ? String(mes) : mesAtualISO();
}

function fimMesISO(mes) {
  const [ano, mesNum] = String(mes).split('-').map(Number);
  return new Date(Date.UTC(ano, mesNum, 0)).toISOString().slice(0, 10);
}

function datasEntreISO(inicio, fim) {
  const out = [];
  for (let d = inicio; d <= fim; d = addDiasISO(d, 1)) out.push(d);
  return out;
}

function diaSemanaBR(data) {
  const dt = new Date(String(data) + 'T12:00:00Z');
  return new Intl.DateTimeFormat('pt-BR', { weekday: 'short', timeZone: 'UTC' }).format(dt).replace('.', '');
}

function dataISOFromTimestampSP(ts) {
  if (!ts) return '';
  const dt = new Date(ts);
  if (Number.isNaN(dt.getTime())) return String(ts).slice(0, 10);
  return new Intl.DateTimeFormat('sv-SE', { timeZone: 'America/Sao_Paulo' }).format(dt);
}

function pct(valor, total) {
  const v = Number(valor || 0), t = Number(total || 0);
  if (!t) return null;
  return Number(((v / t) * 100).toFixed(2));
}

function isTabelaFechamentoMissing(error) {
  const msg = String(error?.message || error?.details || '');
  return error && (
    error.code === '42P01' ||
    error.code === 'PGRST205' ||
    /fechamentos_diarios|schema cache|does not exist|relation|column/i.test(msg)
  );
}

function isTabelaPagamentosMissing(error) {
  const msg = String(error?.message || error?.details || '');
  return error && (
    error.code === '42P01' ||
    error.code === 'PGRST205' ||
    /pagamentos_comprovantes|schema cache|does not exist|relation|column/i.test(msg)
  );
}

function parseMoneyNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  let s = String(value).trim().replace(/[R$\s]/g, '');
  if (!s) return null;
  if (s.includes(',') && s.includes('.')) s = s.replace(/\./g, '').replace(',', '.');
  else if (s.includes(',')) s = s.replace(',', '.');
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

function parseNonNegativeMoney(value) {
  const n = parseMoneyNumber(value);
  if (n === null || n < 0) return null;
  return Number(n.toFixed(2));
}

function parseNonNegativeInteger(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function sanitizeLongText(value, max = 6000) {
  return String(value ?? '')
    .normalize('NFC')
    .replace(/\r\n/g, '\n')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .trim()
    .slice(0, max);
}

function arrayFromMaybeJson(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch(e) {
      return [];
    }
  }
  return [];
}

function normalizarLinhasFinanceiras(value, opts = {}) {
  const rows = arrayFromMaybeJson(value);
  return rows.slice(0, 60).map(row => {
    const descricao = sanitizeText(row?.descricao || row?.nome || row?.forma || '', 90);
    const qtdRaw = row?.qtd ?? row?.quantidade ?? '';
    const qtd = qtdRaw === '' || qtdRaw === null || qtdRaw === undefined ? null : parseNonNegativeInteger(qtdRaw);
    const valor = parseNonNegativeMoney(row?.valor) ?? 0;
    const obs = sanitizeText(row?.obs || row?.observacao || '', 160);
    return {
      descricao,
      ...(opts.comQtd ? { qtd } : {}),
      valor,
      ...(obs ? { obs } : {}),
    };
  }).filter(row => row.valor > 0 || (opts.comQtd && row.qtd > 0));
}

function somaLinhasFinanceiras(rows) {
  return Number((arrayFromMaybeJson(rows).reduce((s, row) => s + Number(row?.valor || 0), 0)).toFixed(2));
}

function linhaFinanceiraTexto(row, comQtd = false) {
  const qtd = comQtd && row.qtd !== null && row.qtd !== undefined ? `${String(row.qtd).padStart(2, '0')} ` : '';
  const obs = row.obs ? ` ${row.obs}` : '';
  return `${qtd}${row.descricao} ${fmtBRL(row.valor)}${obs}`;
}

// Classificação por TIPO de pagamento (pedido do Rubens 18/07): o que importa é
// Dinheiro/Crédito/Débito/Voucher/PIX somando as duas maquininhas — não a maquininha.
// Formato novo do movimento: "CRED STONE", "DEB PAG BANK", "VOUCHER STONE", "PIX PAG BANK"...
// A ORDEM dos testes importa: "CRED STONE" tem que cair em Crédito ANTES do teste de
// maquininha. Dias antigos (só "STONE"/"PAGBANK", sem tipo — 69 dias de mai-jul/26) caem
// no balde "Cartão (maq.)" pra continuarem aparecendo e somando certo na Planilha.
function formaPagamentoInfo(descricao) {
  const n = normalizeSearch(descricao);
  if (/dinheiro|especie/.test(n)) return { key: 'dinheiro', label: 'Dinheiro' };
  if (/voucher|vale\s*refeicao|alelo|sodexo|pluxee|\bvr\b|\bva\b/.test(n)) return { key: 'voucher', label: 'Voucher' };
  if (/\bcred(ito)?\b/.test(n)) return { key: 'credito', label: 'Crédito' };
  if (/\bdeb(ito)?\b/.test(n)) return { key: 'debito', label: 'Débito' };
  if (/pix/.test(n)) return { key: 'pix', label: 'Pix' };
  if (/ifood|i-food|entrega|delivery/.test(n)) return { key: 'ifood', label: 'Ifood/Entrega' };
  if (/stone|pag\s*bank|pagbank|cartao|visa|master|elo|hipercard|amex/.test(n)) return { key: 'cartao', label: 'Cartão (maq.)' };
  return { key: 'outros', label: 'Outros' };
}

function resumoFormasPagamento(pagamentos) {
  const base = {
    dinheiro: { key: 'dinheiro', forma: 'Dinheiro', qtd: 0, valor: 0 },
    credito: { key: 'credito', forma: 'Crédito', qtd: 0, valor: 0 },
    debito: { key: 'debito', forma: 'Débito', qtd: 0, valor: 0 },
    voucher: { key: 'voucher', forma: 'Voucher', qtd: 0, valor: 0 },
    pix: { key: 'pix', forma: 'Pix', qtd: 0, valor: 0 },
    cartao: { key: 'cartao', forma: 'Cartão (maq.)', qtd: 0, valor: 0 },
    ifood: { key: 'ifood', forma: 'Ifood/Entrega', qtd: 0, valor: 0 },
    outros: { key: 'outros', forma: 'Outros', qtd: 0, valor: 0 },
  };
  for (const p of normalizarLinhasFinanceiras(pagamentos, { comQtd: true })) {
    const info = formaPagamentoInfo(p.descricao);
    const row = base[info.key] || base.outros;
    row.qtd += Number(p.qtd || 0);
    row.valor += Number(p.valor || 0);
  }
  for (const row of Object.values(base)) row.valor = Number(row.valor.toFixed(2));
  return base;
}

// ── TAXAS DE CARTÃO / PIX ────────────────────────────────────────────────────
// Taxas da maquininha informadas pelo Rubens (01/08/2026). Elas nunca eram lançadas:
// a conta "Taxas de Cartão" existia no plano e ficava vazia, então o custo total do
// restaurante saía menor do que é — num mês em que ~72% do recebimento vem de cartão,
// isso some com uns 2% do faturamento.
//
// TABELA_TAXAS é a referência por bandeira (o que a operadora cobra de fato).
// TAXA_POR_FORMA é o que dá pra APLICAR: o fechamento diário registra por TIPO
// (crédito/débito/voucher/pix), não por bandeira, então usa-se a taxa da bandeira
// dominante de cada tipo. Visa e Mastercard têm a mesma taxa, o que torna o padrão
// seguro; quando o dia for majoritariamente Elo ou Amex, a taxa real é maior.
const TABELA_TAXAS = [
  { tipo: 'Crédito', bandeira: 'Voucher Master/Visa/Elo', taxa: 3.99 },
  { tipo: 'Crédito', bandeira: 'Elo', taxa: 3.37 },
  { tipo: 'Crédito', bandeira: 'American Express', taxa: 3.62 },
  { tipo: 'Crédito', bandeira: 'Mastercard', taxa: 2.71 },
  { tipo: 'Crédito', bandeira: 'Visa', taxa: 2.71 },
  { tipo: 'Crédito', bandeira: 'Hipercard', taxa: 2.49 },
  { tipo: 'Débito', bandeira: 'Elo', taxa: 2.13 },
  { tipo: 'Débito', bandeira: 'Mastercard', taxa: 1.75 },
  { tipo: 'Débito', bandeira: 'Visa', taxa: 1.75 },
  { tipo: 'Pix', bandeira: 'Pix', taxa: 0.75 },
];
const TAXA_POR_FORMA = {
  credito: { taxa: 2.71, conta: 'Taxas de Cartão', ref: 'Visa/Mastercard' },
  debito:  { taxa: 1.75, conta: 'Taxas de Cartão', ref: 'Visa/Mastercard' },
  voucher: { taxa: 3.99, conta: 'Taxas de Cartão', ref: 'Voucher Master/Visa/Elo' },
  cartao:  { taxa: 2.71, conta: 'Taxas de Cartão', ref: 'Visa/Mastercard (balde legado)' },
  pix:     { taxa: 0.75, conta: 'Taxa Pix',        ref: 'Pix' },
};

// Lança as taxas do dia em Despesas Financeiras. Idempotente: apaga as do mesmo dia
// antes de gravar, então re-salvar o fechamento não duplica. Dinheiro não paga taxa.
async function lancarTaxasDoDia(dataDia, formas, responsavel) {
  try {
    // Limpa também a origem do backfill: sem isso, re-salvar um dia de julho deixaria a
    // linha do backfill E criaria a nova = custo duplicado naquele dia.
    await supabase.from('pagamentos_comprovantes').delete().eq('data', dataDia).in('origem', ['taxa-auto', 'taxa-backfill']);
    const linhas = [];
    // Cada restaurante negocia a taxa dele com a maquininha — usar a taxa de outro
    // faria o custo sair errado todo mês. A config do restaurante manda; a constante
    // do código é só o padrão de quem ainda não configurou.
    let taxasDoRestaurante = null;
    if (MULTI_TENANT) {
      try {
        const id = require('./tenant').tenantAtual();
        if (id) {
          const { data: t } = await supabaseRaw.from('tenants').select('config').eq('id', id).maybeSingle();
          taxasDoRestaurante = t?.config?.taxas || null;
        }
      } catch (e) { /* sem config: cai no padrão */ }
    }
    for (const [key, cfg] of Object.entries(TAXA_POR_FORMA)) {
      const bruto = Number(formas?.[key]?.valor || 0);
      if (bruto <= 0) continue;
      const pctTaxa = Number(taxasDoRestaurante?.[key] ?? cfg.taxa);
      const valor = Number((bruto * pctTaxa / 100).toFixed(2));
      if (valor <= 0) continue;
      linhas.push({
        data: dataDia, grupo: 'Despesas Financeiras', categoria: cfg.conta,
        forma: 'taxa_operadora', valor_bruto: valor, taxa: 0, valor_liquido: valor, parcelas: 0,
        descricao: sanitizeText(`Taxa ${formas[key].forma} ${pctTaxa}% sobre ${fmtBRL(bruto)} (${cfg.ref})`, 180),
        origem: 'taxa-auto', responsavel: responsavel || 'sistema',
        created_at: nowSP(), updated_at: nowSP(),
      });
    }
    if (linhas.length) await supabase.from('pagamentos_comprovantes').insert(linhas);
    return linhas.length;
  } catch (e) { console.error('taxa-auto:', e.message); return 0; }
}

// Despesa anotada no fechamento do dia (passagem, pão, sacolão, retirada) vivia só em
// fechamentos_diarios.despesas: entrava no "Resultado do dia" da Planilha, mas ficava fora
// de TODO grupo do plano de contas — logo, invisível nos Índices. Em julho/2026 foram
// R$2.733,21 lançados com disciplina todo dia e que nenhum índice enxergava (R$1.359,80
// só de passagem, que é Vale Transporte e devia estar no CMO).
// Não gera dupla contagem: a Planilha soma fechamentos_diarios.despesas e os Índices somam
// pagamentos_comprovantes — nenhum total mistura as duas fontes.
async function lancarDespesasDoCaixaNasContas(dataDia, despesas, responsavel) {
  try {
    // Idem taxas: limpa a origem do backfill junto, senão re-salvar o dia duplica a despesa.
    await supabase.from('pagamentos_comprovantes').delete().eq('data', dataDia).in('origem', ['caixa-auto', 'caixa-backfill']);
    const linhas = [];
    for (const d of (despesas || [])) {
      const valor = Number(d.valor || 0);
      if (valor <= 0) continue;
      const conta = inferirContaPagamentoPorTexto(d.descricao) || acharContaPagamento('Outros');
      if (!conta) continue;
      // Retirada de sócio nem chega nas Contas (Rubens, 01/08: "remove também as
      // retiradas"). O registro continua no fechamento do dia, que é a fonte — aqui ele
      // só não vira lançamento financeiro, porque distribuição de resultado não é despesa.
      if (ehNaoOperacional(conta.grupo, conta.categoria)) continue;
      linhas.push({
        data: dataDia, grupo: conta.grupo, categoria: conta.categoria, forma: 'despesa_caixa',
        valor_bruto: valor, taxa: 0, valor_liquido: valor, parcelas: 0,
        descricao: sanitizeText(`Despesa do caixa: ${d.descricao}${d.obs ? ' — ' + d.obs : ''}`, 180),
        origem: 'caixa-auto', responsavel: responsavel || 'caixa',
        created_at: nowSP(), updated_at: nowSP(),
      });
    }
    if (linhas.length) await supabase.from('pagamentos_comprovantes').insert(linhas);
    return linhas.length;
  } catch (e) { console.error('caixa-auto:', e.message); return 0; }
}

function somarResumoFormas(destino, origem) {
  for (const [key, row] of Object.entries(origem || {})) {
    if (!destino[key]) destino[key] = { key, forma: row.forma || key, qtd: 0, valor: 0 };
    destino[key].qtd += Number(row.qtd || 0);
    destino[key].valor = Number((Number(destino[key].valor || 0) + Number(row.valor || 0)).toFixed(2));
  }
}

function normalizarFormaPagamentoTexto(value) {
  const raw = sanitizeText(value || '', 40);
  const n = normalizeSearch(raw);
  if (/boleto/.test(n)) return 'Boleto';
  if (/debito automatico|debito em conta/.test(n)) return 'Débito automático';
  if (/transferencia|ted|doc/.test(n)) return 'Transferência';
  if (/stone/.test(n)) return 'Stone';
  if (/pag\s*bank|pagbank/.test(n)) return 'PagBank';
  if (/pix/.test(n)) return 'Pix';
  if (/dinheiro|especie/.test(n)) return 'Dinheiro';
  if (/debito/.test(n)) return 'Débito';
  if (/credito/.test(n)) return 'Crédito';
  if (/cartao|visa|master|elo|hipercard|amex/.test(n)) return 'Cartão';
  return raw || 'Outro';
}

const CONTAS_PLANILHA_PAGAMENTOS = [
  { grupo: 'Despesas Variáveis - CMV', contas: ['Condimentos', 'Embutidos', 'Estoque Congelado', 'Estoque Seco (Farinha)', 'Hortifruti', 'Kit (descartáveis)', 'Lácteos', 'Massa Fresca', 'Óleos', 'Pescados', 'Proteína Aves', 'Proteína Bovina', 'Proteína Suína'] },
  { grupo: 'CMV Bebidas', contas: ['Cerveja', 'Destilados', 'Não Alcoólicos', 'Vinho'] },
  { grupo: 'Despesas Fixas / CMO', contas: ['Almoço Funcionários', 'Auxílio Uniforme', 'Combustível', 'Décimo Terceiro Salário', 'Despesas com Admissão e Demissão', 'Férias', 'FGTS', 'Freelance', 'Gorjeta / Gratificação', 'INSS', 'IRRF', 'Plano de Saúde', 'Pró-labore', 'Salários', 'Seguro de Vida', 'Vale Refeição', 'Vale Transporte'] },
  { grupo: 'Contas Públicas', contas: ['Água', 'Eletricidade', 'Internet', 'Lixo', 'Telefone'] },
  { grupo: 'Despesas de Produção', contas: ['Embalagens (guardanapos, palito, sal, açúcar em sachê)', 'Gás', 'Gelo', 'Higiene, Limpeza', 'Sistema'] },
  { grupo: 'Custos de Ocupação', contas: ['Aluguel', 'IPTU', 'Condomínio'] },
  { grupo: 'Despesas com Marketing', contas: ['Ações de Marketing', 'Anúncios', 'Guia', 'Mídias Sociais'] },
  { grupo: 'Despesas de Manutenção', contas: ['Máquinas e Equipamentos', 'Predial', 'Preventiva'] },
  { grupo: 'Despesas Eventuais', contas: ['Cardápio', 'Despesas com Veículo (IPVA, multas, manutenção)', 'Frete', 'Material de Escritório e Informática', 'Utensílios e Equipamentos', 'Taxa de Incêndio'] },
  { grupo: 'Despesas Administrativas', contas: ['Contador', 'Taxa Ifood 12%'] },
  { grupo: 'Despesas Financeiras', contas: ['Alvará', 'Parcelamento', 'Renegociação de Dívida', 'Simples / MEI', 'Tarifa Bancária', 'Taxa de Antecipação', 'Empréstimo Bancário', 'Taxas de Cartão', 'Taxa Pix'] },
  { grupo: 'Outras Despesas', contas: ['Boleto / Conta avulsa', 'Retirada', 'Outros'] },
];

// Retirada de sócio é distribuição de resultado, não despesa operacional (decisão do
// Rubens, 01/08). Não vira lançamento nas Contas e fica fora do custo total e da sobra —
// senão o restaurante parece gastar mais do que gasta. O registro continua no fechamento
// do dia, que é a fonte. Em julho/2026 eram R$536 inflando o custo.
const CONTAS_NAO_OPERACIONAIS = [{ grupo: 'Outras Despesas', categoria: 'Retirada' }];
const ehNaoOperacional = (grupo, categoria) => CONTAS_NAO_OPERACIONAIS
  .some(c => c.grupo === grupo && c.categoria === categoria);

const CONTAS_PLANILHA_FLAT = CONTAS_PLANILHA_PAGAMENTOS.flatMap(g =>
  g.contas.map((conta, ordem) => ({ grupo: g.grupo, categoria: conta, ordem }))
);

// Categoria do produto no estoque → (grupo, conta) do plano de contas da aba Contas.
const MAPA_CONTA_COMPRA = {
  'Hortifruti':       ['Despesas Variáveis - CMV', 'Hortifruti'],
  'Carnes Bovinas':   ['Despesas Variáveis - CMV', 'Proteína Bovina'],
  'Carnes Suínas':    ['Despesas Variáveis - CMV', 'Proteína Suína'],
  'Aves':             ['Despesas Variáveis - CMV', 'Proteína Aves'],
  'Pescados':         ['Despesas Variáveis - CMV', 'Pescados'],
  'Secos e Grãos':    ['Despesas Variáveis - CMV', 'Estoque Seco (Farinha)'],
  'Laticínios':       ['Despesas Variáveis - CMV', 'Lácteos'],
  'Embutidos':        ['Despesas Variáveis - CMV', 'Embutidos'],
  'Especiarias':      ['Despesas Variáveis - CMV', 'Condimentos'],
  'Óleos':            ['Despesas Variáveis - CMV', 'Óleos'],
  'Massa Fresca':     ['Despesas Variáveis - CMV', 'Massa Fresca'],
  'Outras Proteínas': ['Despesas Variáveis - CMV', 'Estoque Congelado'],
  'Descartáveis':     ['Despesas Variáveis - CMV', 'Kit (descartáveis)'],
  'Congelados':       ['Despesas Variáveis - CMV', 'Estoque Congelado'],
  // Estas duas NÃO são CMV: o plano de contas põe embalagem em Produção e caneta/etiqueta
  // em Eventuais. Antes caíam em Descartáveis (CMV > Kit) e inchavam o CMV com item que
  // não é insumo de prato.
  'Embalagens':       ['Despesas de Produção', 'Embalagens (guardanapos, palito, sal, açúcar em sachê)'],
  'Escritório':       ['Despesas Eventuais', 'Material de Escritório e Informática'],
  'Bebidas':          ['CMV Bebidas', 'Não Alcoólicos'], // refinado por contaBebida() — ver abaixo
  'Limpeza':          ['Despesas de Produção', 'Higiene, Limpeza'],
};

// Categoria "Bebidas" é grossa demais pro plano de contas, que separa CMV Bebidas em
// Cerveja / Destilados / Vinho / Não Alcoólicos. Sem isto TODA bebida caía em "Não
// Alcoólicos" e o Rubens nunca conseguia ver quanto o álcool representa (auditoria
// 01/08: 3 meses de compras tinham R$566 de cerveja e R$266 de destilado/vinho
// escondidos dentro de "Não Alcoólicos"). Classifica pelo nome do produto.
function contaBebida(nome) {
  const n = normalizeSearch(nome);
  if (/cerveja|brahma|budweiser|corona|heineken|stella|imperio|antartica|skol|original|eisenbahn|chopp/.test(n)) return 'Cerveja';
  if (/vinho/.test(n)) return 'Vinho';
  if (/cachaca|vodka|whisky|uisque|gin|rum|sake|licor|tequila|conhaque|aperitivo/.test(n)) return 'Destilados';
  return 'Não Alcoólicos';
}

// Categoria de produto sem mapa não pode inventar conta: 'Outros' NÃO existe no grupo
// "Despesas Variáveis - CMV" e o lançamento virava uma linha órfã que nenhum índice
// somava (bug real: o produto com categoria digitada 'Embutidosi' gerou CMV > Outros).
// Estoque Congelado é a conta guarda-chuva legítima do grupo.
const CONTA_COMPRA_FALLBACK = ['Despesas Variáveis - CMV', 'Estoque Congelado'];

// Compra que entra no estoque vira lançamento automático na aba Contas — organiza o
// financeiro por categoria sem depender de lançamento manual. Falha aqui NUNCA derruba
// a movimentação (best-effort). origem='estoque-auto' identifica os lançamentos
// automáticos e os separa dos digitados na aba Contas.
async function lancarCompraNasContas({ produto, qtd, custoUnit, responsavel, obs, movId }) {
  try {
    const v = Number((Number(custoUnit) * Number(qtd)).toFixed(2));
    if (!v || v <= 0) return;                          // sem preço real não polui as Contas
    const cat = produto.categoria || '';
    if (/^qa robo/i.test(cat)) return;                 // produtos de teste do robô ficam fora
    let [grupo, conta] = MAPA_CONTA_COMPRA[cat] || CONTA_COMPRA_FALLBACK;
    if (grupo === 'CMV Bebidas') conta = contaBebida(produto.nome);
    await supabase.from('pagamentos_comprovantes').insert({
      data: dateSP(), grupo, categoria: conta, forma: 'compra_estoque',
      valor_bruto: v, taxa: 0, valor_liquido: v, parcelas: 0,
      descricao: sanitizeText(`Compra estoque: ${produto.nome} × ${qtd}${obs ? ' — ' + obs : ''}`, 180),
      origem: 'estoque-auto', responsavel: responsavel || 'estoque',
      mov_id: movId || null,                           // vínculo: cancelou a movimentação → apaga aqui também
      created_at: nowSP(), updated_at: nowSP(),
    });
  } catch (e) { console.error('contas-auto:', e.message); }
}

function acharContaPagamento(categoria) {
  const alvo = normalizeSearch(categoria);
  if (!alvo) return null;
  return CONTAS_PLANILHA_FLAT.find(c => normalizeSearch(c.categoria) === alvo) || null;
}

function inferirContaPagamentoPorTexto(texto) {
  const n = normalizeSearch(texto);
  const regras = [
    [/agua|sabesp|cedae/, 'Água'],
    [/eletric|energia|enel|light|edp/, 'Eletricidade'],
    [/internet|wifi|wi-fi|vivo fibra|claro net/, 'Internet'],
    [/\blixo\b|coleta/, 'Lixo'],
    [/telefone|celular|vivo|claro|tim|oi\b/, 'Telefone'],
    [/\bgas\b|botijao|botijão/, 'Gás'],
    [/\bgelo\b/, 'Gelo'],
    [/higiene|limpeza|detergente|sanit|desinfet|papel/, 'Higiene, Limpeza'],
    [/sistema|software|mensalidade sistema|pdv|gestao|gestão/, 'Sistema'],
    [/aluguel|locacao|locação/, 'Aluguel'],
    [/iptu/, 'IPTU'],
    [/condominio|condomínio/, 'Condomínio'],
    [/salario|salários|salarios|folha/, 'Salários'],
    // "Treinamento"/"diária"/"extra" no caixa é pagamento a freelance (Rubens, 01/08:
    // "denis, leandro, pessoas em treinamento" são freelance). Vem antes de Retirada
    // porque "RETIRADA ... TREINAMENTO" é pagamento, não distribuição.
    [/freela|freelance|treinamento|diarista|\bdiaria\b|\bextra\b/, 'Freelance'],
    [/gratific|gorjeta|caixinha/, 'Gorjeta / Gratificação'],
    [/pro labore|pro-labore|pró-labore/, 'Pró-labore'],
    [/\binss\b/, 'INSS'],
    [/\birrf\b|imposto de renda/, 'IRRF'],
    [/\bfgts\b/, 'FGTS'],
    [/ferias|férias/, 'Férias'],
    [/decimo terceiro|decimo salario|13o salario|13 salario/, 'Décimo Terceiro Salário'],
    [/vale transporte|passagem|transporte/, 'Vale Transporte'],
    [/vale refeicao|vale refeição|vr\b/, 'Vale Refeição'],
    [/uniforme/, 'Auxílio Uniforme'],
    [/almoco funcionario|almoço funcionário|refeicao funcionario|refeição funcionário/, 'Almoço Funcionários'],
    [/contador|contabilidade/, 'Contador'],
    [/ifood|i-food/, 'Taxa Ifood 12%'],
    [/simples|mei\b|das\b/, 'Simples / MEI'],
    [/alvara|alvará/, 'Alvará'],
    [/parcelamento/, 'Parcelamento'],
    [/renegociacao|renegociação|divida|dívida/, 'Renegociação de Dívida'],
    [/tarifa bancaria|tarifa bancária|cesta bancaria|cesta bancária/, 'Tarifa Bancária'],
    [/antecipacao|antecipação/, 'Taxa de Antecipação'],
    [/emprestimo|empréstimo|financiamento/, 'Empréstimo Bancário'],
    [/taxa.*cartao|cartao.*taxa|credito|debito|master|visa|elo|stone|pagbank/, 'Taxas de Cartão'],
    [/taxa.*pix|pix.*taxa/, 'Taxa Pix'],
    [/condimento|tempero/, 'Condimentos'],
    [/embutido|presunto|mortadela|linguica|linguiça/, 'Embutidos'],
    [/congelado/, 'Estoque Congelado'],
    [/farinha|estoque seco|seco/, 'Estoque Seco (Farinha)'],
    [/hortifruti|verdura|legume|fruta|sacolao|sacolão/, 'Hortifruti'],
    // Compra avulsa paga pelo caixa do dia (o Rubens anota assim no fechamento): é insumo,
    // tem que cair no CMV e não no balde "Outros".
    [/\bpao\b|\bpaes\b|padaria/, 'Estoque Seco (Farinha)'],
    [/mercado|feira|quitanda|atacad/, 'Hortifruti'],
    [/uva passa|uvas passa|fruta seca/, 'Estoque Seco (Farinha)'],
    [/descartavel|descartáveis|kit|embalagem descartavel/, 'Kit (descartáveis)'],
    [/leite|lacteo|lácteo|queijo|mussarela|manteiga/, 'Lácteos'],
    [/massa fresca|massa/, 'Massa Fresca'],
    [/oleo|óleo/, 'Óleos'],
    [/peixe|pescado/, 'Pescados'],
    [/frango|aves|ave\b/, 'Proteína Aves'],
    [/carne|boi|bovina|acém|alcatra|patinho/, 'Proteína Bovina'],
    [/suina|suína|porco|linguica|linguiça/, 'Proteína Suína'],
    [/cerveja/, 'Cerveja'],
    [/destilado|vodka|whisky|gin|cachaca|cachaça/, 'Destilados'],
    [/refrigerante|suco|agua mineral|água mineral|nao alcoolico|não alcoólico/, 'Não Alcoólicos'],
    [/vinho/, 'Vinho'],
    [/marketing|acao|ação/, 'Ações de Marketing'],
    [/anuncio|anúncio|trafego|tráfego/, 'Anúncios'],
    [/guia/, 'Guia'],
    [/midia|mídia|instagram|facebook/, 'Mídias Sociais'],
    [/maquina|máquina|equipamento/, 'Máquinas e Equipamentos'],
    [/predial|obra|reparo/, 'Predial'],
    [/preventiva|manutencao preventiva|manutenção preventiva/, 'Preventiva'],
    [/cardapio|cardápio/, 'Cardápio'],
    [/veiculo|veículo|ipva|multa|carro/, 'Despesas com Veículo (IPVA, multas, manutenção)'],
    [/frete|entrega/, 'Frete'],
    [/escritorio|escritório|informatica|informática|papelaria|computador/, 'Material de Escritório e Informática'],
    [/utensilio|utensílio|panela|talher|equipamento cozinha/, 'Utensílios e Equipamentos'],
    [/incendio|incêndio/, 'Taxa de Incêndio'],
    [/boleto|conta avulsa/, 'Boleto / Conta avulsa'],
    [/retirada|socio|sócio|nayara|nay/, 'Retirada'],
  ];
  for (const [re, categoria] of regras) {
    if (re.test(n)) return acharContaPagamento(categoria);
  }
  return acharContaPagamento('Outros');
}

function normalizarContaPagamentoInput(input = {}) {
  const categoriaRaw = sanitizeText(input.categoria || input.conta || input.tipo_conta || '', 120);
  const grupoRaw = sanitizeText(input.grupo || input.grupo_conta || '', 90);
  const achada = acharContaPagamento(categoriaRaw) || inferirContaPagamentoPorTexto([
    categoriaRaw,
    grupoRaw,
    input.fornecedor,
    input.descricao,
    input.comprovante_texto,
    input.texto,
  ].join(' '));
  return {
    grupo: achada?.grupo || grupoRaw || 'Outras Despesas',
    categoria: achada?.categoria || categoriaRaw || 'Outros',
  };
}

function normalizarPagamentoInput(input = {}) {
  const data = validarDataISO(input.data);
  const forma = normalizarFormaPagamentoTexto(input.forma || input.tipo || input.meio || input.operadora || '');
  const conta = normalizarContaPagamentoInput(input);
  const operadora = sanitizeText(input.operadora || '', 40);
  const bandeira = sanitizeText(input.bandeira || '', 40);
  let valorBruto = parseNonNegativeMoney(input.valor_bruto ?? input.valor ?? input.total) ?? 0;
  const taxa = parseNonNegativeMoney(input.taxa) ?? 0;
  let valorLiquido = parseNonNegativeMoney(input.valor_liquido ?? input.liquido) ?? null;
  if (valorLiquido === null) valorLiquido = Math.max(0, Number((valorBruto - taxa).toFixed(2)));
  if (!valorBruto && valorLiquido) valorBruto = Number((valorLiquido + taxa).toFixed(2));
  const parcelas = parseNonNegativeInteger(input.parcelas || 0);
  const nsu = sanitizeText(input.nsu || '', 60);
  const autorizacao = sanitizeText(input.autorizacao || input.aut || '', 60);
  const fornecedor = sanitizeText(input.fornecedor || input.beneficiario || input.favorecido || '', 120);
  const descricao = sanitizeText(input.descricao || input.observacao || '', 180);
  const comprovanteTexto = sanitizeLongText(input.comprovante_texto || input.texto || '', 3000);
  const origem = sanitizeText(input.origem || '', 30);

  return {
    data,
    grupo: conta.grupo,
    categoria: conta.categoria,
    forma,
    operadora,
    bandeira,
    valor_bruto: Number(valorBruto.toFixed(2)),
    taxa: Number(taxa.toFixed(2)),
    valor_liquido: Number(valorLiquido.toFixed(2)),
    fornecedor,
    vencimento: dataISOOuNull(input.vencimento || input.data_vencimento),
    competencia: sanitizeText(input.competencia || '', 20),
    nsu,
    autorizacao,
    parcelas,
    descricao,
    comprovante_texto: comprovanteTexto,
    origem,
  };
}

function normalizarPagamentoDb(row) {
  return {
    id: row.id,
    data: String(row.data || '').slice(0, 10),
    data_br: dataBR(String(row.data || '').slice(0, 10)),
    grupo: row.grupo || 'Outras Despesas',
    categoria: row.categoria || 'Outros',
    forma: row.forma || '',
    operadora: row.operadora || '',
    bandeira: row.bandeira || '',
    valor_bruto: Number(row.valor_bruto || 0),
    taxa: Number(row.taxa || 0),
    valor_liquido: Number(row.valor_liquido || 0),
    fornecedor: row.fornecedor || '',
    vencimento: row.vencimento ? String(row.vencimento).slice(0, 10) : '',
    vencimento_br: row.vencimento ? dataBR(String(row.vencimento).slice(0, 10)) : '',
    competencia: row.competencia || '',
    nsu: row.nsu || '',
    autorizacao: row.autorizacao || '',
    parcelas: Number(row.parcelas || 0),
    descricao: row.descricao || '',
    comprovante_texto: row.comprovante_texto || '',
    origem: row.origem || '',
    responsavel: row.responsavel || '',
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
  };
}

function ordemGrupoPagamento(grupo) {
  const idx = CONTAS_PLANILHA_PAGAMENTOS.findIndex(g => g.grupo === grupo);
  return idx >= 0 ? idx : 999;
}

function ordemContaPagamento(conta) {
  const found = CONTAS_PLANILHA_FLAT.find(c => c.grupo === conta.grupo && c.categoria === conta.categoria);
  return found ? found.ordem : 999;
}

function agruparPagamentos(rows, campo) {
  const out = {};
  for (const p of rows) {
    const key = p[campo] || 'Não informado';
    if (!out[key]) out[key] = { nome: key, qtd: 0, valor_bruto: 0, taxa: 0, valor_liquido: 0 };
    out[key].qtd++;
    out[key].valor_bruto += Number(p.valor_bruto || 0);
    out[key].taxa += Number(p.taxa || 0);
    out[key].valor_liquido += Number(p.valor_liquido || 0);
  }
  return Object.values(out)
    .map(r => ({
      ...r,
      valor_bruto: Number(r.valor_bruto.toFixed(2)),
      taxa: Number(r.taxa.toFixed(2)),
      valor_liquido: Number(r.valor_liquido.toFixed(2)),
    }))
    .sort((a, b) => b.valor_bruto - a.valor_bruto);
}

function agruparPagamentosPorConta(rows) {
  const out = {};
  for (const p of rows) {
    const grupo = p.grupo || 'Outras Despesas';
    const categoria = p.categoria || 'Outros';
    const key = `${grupo}|||${categoria}`;
    if (!out[key]) out[key] = { grupo, categoria, qtd: 0, valor_bruto: 0, taxa: 0, valor_liquido: 0 };
    out[key].qtd++;
    out[key].valor_bruto += Number(p.valor_bruto || 0);
    out[key].taxa += Number(p.taxa || 0);
    out[key].valor_liquido += Number(p.valor_liquido || 0);
  }
  return Object.values(out)
    .map(r => ({
      ...r,
      valor_bruto: Number(r.valor_bruto.toFixed(2)),
      taxa: Number(r.taxa.toFixed(2)),
      valor_liquido: Number(r.valor_liquido.toFixed(2)),
    }))
    .sort((a, b) =>
      (ordemGrupoPagamento(a.grupo) - ordemGrupoPagamento(b.grupo)) ||
      (ordemContaPagamento(a) - ordemContaPagamento(b)) ||
      a.categoria.localeCompare(b.categoria, 'pt-BR')
    );
}

function csvMoneyBR(value) {
  return Number(value || 0).toFixed(2).replace('.', ',');
}

function montarRowsExportPagamentos(d) {
  const datas = datasEntreISO(`${d.mes}-01`, fimMesISO(d.mes));
  const porConta = new Map();
  for (const p of d.pagamentos || []) {
    const grupo = p.grupo || 'Outras Despesas';
    const categoria = p.categoria || 'Outros';
    const key = `${grupo}|||${categoria}`;
    if (!porConta.has(key)) {
      porConta.set(key, {
        grupo,
        categoria,
        valores: Object.fromEntries(datas.map(data => [data, 0])),
        total: 0,
      });
    }
    const row = porConta.get(key);
    if (row.valores[p.data] !== undefined) row.valores[p.data] += Number(p.valor_bruto || 0);
    row.total += Number(p.valor_bruto || 0);
  }
  const contas = Array.from(porConta.values())
    .map(r => ({
      ...r,
      total: Number(r.total.toFixed(2)),
      valores: Object.fromEntries(Object.entries(r.valores).map(([data, valor]) => [data, Number(valor.toFixed(2))])),
    }))
    .sort((a, b) =>
      (ordemGrupoPagamento(a.grupo) - ordemGrupoPagamento(b.grupo)) ||
      (ordemContaPagamento(a) - ordemContaPagamento(b)) ||
      a.categoria.localeCompare(b.categoria, 'pt-BR')
    );

  const rows = [
    ['RELATÓRIO DE CONTAS PAGAS', `Mês ${d.mes_label}`],
    [],
    ['RESUMO GERAL'],
    ['Lançamentos', d.totais.qtd || 0],
    ['Total pago', csvMoneyBR(d.totais.valor_bruto)],
    ['Taxas/descontos', csvMoneyBR(d.totais.taxa)],
    ['Valor líquido', csvMoneyBR(d.totais.valor_liquido)],
    [],
    ['RESUMO POR GRUPO'],
    ['Grupo', 'Qtd', 'Total pago', 'Taxas/descontos', 'Valor líquido'],
  ];

  if (d.por_grupo?.length) {
    for (const g of d.por_grupo) rows.push([g.nome, g.qtd, csvMoneyBR(g.valor_bruto), csvMoneyBR(g.taxa), csvMoneyBR(g.valor_liquido)]);
  } else {
    rows.push(['Sem lançamentos', '', '', '', '']);
  }

  rows.push(
    [],
    ['RESUMO POR CONTA'],
    ['Grupo', 'Conta', 'Qtd', 'Total pago', 'Taxas/descontos', 'Valor líquido']
  );
  if (d.por_categoria?.length) {
    for (const c of d.por_categoria) rows.push([c.grupo, c.categoria, c.qtd, csvMoneyBR(c.valor_bruto), csvMoneyBR(c.taxa), csvMoneyBR(c.valor_liquido)]);
  } else {
    rows.push(['Sem lançamentos', '', '', '', '', '']);
  }

  rows.push(
    [],
    ['FLUXO POR DIA E CONTA'],
    ['Grupo', 'Conta', ...datas.map(data => data.slice(8, 10)), 'Total']
  );
  if (contas.length) {
    const grupos = [...new Set(contas.map(c => c.grupo))];
    for (const grupo of grupos) {
      const linhas = contas.filter(c => c.grupo === grupo);
      const subtotalDias = datas.map(data => linhas.reduce((s, c) => s + Number(c.valores[data] || 0), 0));
      const subtotal = subtotalDias.reduce((s, v) => s + v, 0);
      rows.push([grupo, 'SUBTOTAL', ...subtotalDias.map(csvMoneyBR), csvMoneyBR(subtotal)]);
      for (const c of linhas) {
        rows.push([c.grupo, c.categoria, ...datas.map(data => csvMoneyBR(c.valores[data])), csvMoneyBR(c.total)]);
      }
    }
  } else {
    rows.push(['Sem lançamentos', '', ...datas.map(() => ''), '']);
  }

  rows.push(
    [],
    ['LANÇAMENTOS DETALHADOS'],
    ['Data', 'Grupo', 'Conta', 'Fornecedor/Pessoa', 'Descrição', 'Forma de pagamento', 'Operadora', 'Valor pago', 'Taxa/desconto', 'Valor líquido', 'Vencimento', 'Responsável', 'Origem', 'NSU', 'Autorização']
  );
  for (const p of d.pagamentos || []) {
    rows.push([
      p.data_br,
      p.grupo,
      p.categoria,
      p.fornecedor,
      p.descricao,
      p.forma,
      p.operadora,
      csvMoneyBR(p.valor_bruto),
      csvMoneyBR(p.taxa),
      csvMoneyBR(p.valor_liquido),
      p.vencimento_br,
      p.responsavel,
      p.origem,
      p.nsu,
      p.autorizacao,
    ]);
  }
  return rows;
}

async function montarPagamentosMensal(mesParam) {
  const mes = validarMesISO(mesParam);
  const inicio = `${mes}-01`;
  const fim = fimMesISO(mes);
  const { data, error } = await supabase.from('pagamentos_comprovantes')
    .select('*')
    .gte('data', inicio)
    .lte('data', fim)
    .order('data', { ascending: false })
    .order('id', { ascending: false });
  if (error) {
    if (isTabelaPagamentosMissing(error)) {
      return {
        mes,
        mes_label: mes.split('-').reverse().join('/'),
        configuracao_pendente: true,
        totais: { qtd: 0, valor_bruto: 0, taxa: 0, valor_liquido: 0, ticket_medio: null },
        por_grupo: [],
        por_categoria: [],
        por_forma: [],
        por_operadora: [],
        pagamentos: [],
        contas_modelo: CONTAS_PLANILHA_PAGAMENTOS,
      };
    }
    throw error;
  }
  const pagamentos = (data || []).map(normalizarPagamentoDb);
  const totais = pagamentos.reduce((acc, p) => {
    acc.qtd++;
    acc.valor_bruto += Number(p.valor_bruto || 0);
    acc.taxa += Number(p.taxa || 0);
    acc.valor_liquido += Number(p.valor_liquido || 0);
    return acc;
  }, { qtd: 0, valor_bruto: 0, taxa: 0, valor_liquido: 0, ticket_medio: null });
  totais.valor_bruto = Number(totais.valor_bruto.toFixed(2));
  totais.taxa = Number(totais.taxa.toFixed(2));
  totais.valor_liquido = Number(totais.valor_liquido.toFixed(2));
  totais.ticket_medio = totais.qtd ? Number((totais.valor_bruto / totais.qtd).toFixed(2)) : null;
  return {
    mes,
    mes_label: mes.split('-').reverse().join('/'),
    configuracao_pendente: false,
    totais,
    por_grupo: agruparPagamentos(pagamentos, 'grupo'),
    por_categoria: agruparPagamentosPorConta(pagamentos),
    por_forma: agruparPagamentos(pagamentos, 'forma'),
    por_operadora: agruparPagamentos(pagamentos, 'operadora'),
    pagamentos,
    contas_modelo: CONTAS_PLANILHA_PAGAMENTOS,
  };
}

function extrairValoresFinanceirosTexto(texto) {
  const matches = String(texto || '').match(/(?:R\$?\s*)?\d{1,3}(?:\.\d{3})*,\d{2}|(?:R\$?\s*)?\d+[,.]\d{2}/g) || [];
  return matches.map(raw => ({ raw, valor: parseMoneyNumber(raw) })).filter(v => v.valor !== null);
}

function extrairValorPorRotulo(texto, rotulos) {
  const escaped = rotulos.map(r => r.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  const re = new RegExp(`(?:${escaped})[^\\n\\dR$]{0,40}((?:R\\$?\\s*)?\\d{1,3}(?:\\.\\d{3})*,\\d{2}|(?:R\\$?\\s*)?\\d+[,.]\\d{2})`, 'i');
  const m = String(texto || '').match(re);
  return m ? parseMoneyNumber(m[1]) : null;
}

function extrairPagamentoTextoLocal(texto, dataPadrao) {
  const s = String(texto || '');
  const sNorm = normalizeSearch(s);
  const dataMatch = s.match(/\b(\d{1,2})[\/.-](\d{1,2})(?:[\/.-](\d{2,4}))?\b/);
  let data = validarDataISO(dataPadrao);
  if (dataMatch) {
    const dia = Number(dataMatch[1]);
    const mes = Number(dataMatch[2]);
    let ano = dataMatch[3] ? Number(dataMatch[3]) : Number(data.slice(0, 4));
    if (ano < 100) ano += 2000;
    const dt = new Date(Date.UTC(ano, mes - 1, dia));
    if (dt.getUTCFullYear() === ano && dt.getUTCMonth() === mes - 1 && dt.getUTCDate() === dia) {
      data = `${ano}-${String(mes).padStart(2, '0')}-${String(dia).padStart(2, '0')}`;
    }
  }

  const valores = extrairValoresFinanceirosTexto(s);
  let valorBruto =
    extrairValorPorRotulo(s, ['valor da venda', 'valor total', 'valor', 'total', 'bruto']) ??
    (valores.length ? Math.max(...valores.map(v => v.valor)) : 0);
  const taxa = extrairValorPorRotulo(s, ['taxa', 'tarifa', 'desconto']) ?? 0;
  const valorLiquido = extrairValorPorRotulo(s, ['valor liquido', 'valor líquido', 'liquido', 'líquido', 'a receber', 'repasse']) ?? Math.max(0, valorBruto - taxa);

  const forma = normalizarFormaPagamentoTexto(
    /boleto/.test(sNorm) ? 'Boleto' :
    /debito automatico|debito em conta/.test(sNorm) ? 'Débito automático' :
    /transferencia|ted|doc/.test(sNorm) ? 'Transferência' :
    /stone/.test(sNorm) ? 'Stone' :
    /pag\s*bank|pagbank/.test(sNorm) ? 'PagBank' :
    /pix/.test(sNorm) ? 'Pix' :
    /dinheiro|especie/.test(sNorm) ? 'Dinheiro' :
    /debito/.test(sNorm) ? 'Débito' :
    /credito/.test(sNorm) ? 'Crédito' :
    /cartao/.test(sNorm) ? 'Cartão' : ''
  );
  const operadora = /stone/.test(sNorm) ? 'Stone' : (/pag\s*bank|pagbank/.test(sNorm) ? 'PagBank' : '');
  const bandeira = (s.match(/\b(VISA|MASTERCARD|MASTER|ELO|HIPERCARD|AMEX|AMERICAN EXPRESS)\b/i)?.[1] || '').replace(/MASTER$/i, 'Mastercard');
  const nsu = sanitizeText(s.match(/\bNSU[:\s-]*([A-Z0-9.-]+)/i)?.[1] || '', 60);
  const autorizacao = sanitizeText(s.match(/\b(?:AUT|AUTORIZA(?:CAO|ÇÃO)|COD\.?\s*AUT)[:\s-]*([A-Z0-9.-]+)/i)?.[1] || '', 60);
  const conta = normalizarContaPagamentoInput({ comprovante_texto: s });

  return normalizarPagamentoInput({
    data,
    grupo: conta.grupo,
    categoria: conta.categoria,
    forma,
    operadora,
    bandeira,
    valor_bruto: valorBruto,
    taxa,
    valor_liquido: valorLiquido,
    nsu,
    autorizacao,
    comprovante_texto: s,
    origem: 'texto',
  });
}

async function lerComprovantePagamentoComIA({ imagens = [], mediaType, texto = '', dataPadrao }, userLog) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    if (texto) return extrairPagamentoTextoLocal(texto, dataPadrao);
    const err = new Error('ANTHROPIC_API_KEY não configurada no servidor.');
    err.status = 500;
    throw err;
  }

  const contasModelo = CONTAS_PLANILHA_PAGAMENTOS
    .map(g => `${g.grupo}: ${g.contas.join(', ')}`)
    .join('\n');
  const prompt = `Você está lendo um comprovante de pagamento ou conta paga de restaurante brasileiro (boleto, conta de água/luz, imposto, salário, freelance, Pix, cartão, Stone, PagBank ou recibo).
Extraia os campos financeiros e responda SOMENTE JSON válido, sem markdown:
{
  "data":"YYYY-MM-DD",
  "grupo":"grupo da planilha",
  "categoria":"conta da planilha",
  "forma":"Boleto|Pix|Transferência|Débito automático|Dinheiro|Crédito|Débito|Cartão|Stone|PagBank|Outro",
  "operadora":"Stone|PagBank|...",
  "bandeira":"Visa|Mastercard|Elo|Hipercard|...",
  "valor_bruto":0.00,
  "taxa":0.00,
  "valor_liquido":0.00,
  "fornecedor":"",
  "vencimento":"YYYY-MM-DD",
  "nsu":"",
  "autorizacao":"",
  "parcelas":0,
  "descricao":""
}

Regras:
- Valor bruto é o valor pago/total da conta.
- Taxa é tarifa/desconto quando aparecer; se não aparecer, use 0.
- Valor líquido é o valor efetivamente baixado; se não aparecer, use valor_bruto - taxa.
- Se a data não aparecer, use ${validarDataISO(dataPadrao)}.
- Se vencimento não aparecer, deixe vazio.
- Escolha grupo e categoria SOMENTE entre estas contas da planilha. Se não tiver certeza, use Outras Despesas > Boleto / Conta avulsa:
${contasModelo}
- Forma é como foi pago (Boleto, Pix, Transferência, Débito automático etc.). Não confunda forma com categoria.
- NSU e autorização são códigos, preserve como texto.
${texto ? `\nTexto copiado do comprovante:\n${texto.slice(0, 5000)}` : ''}`;

  const content = [
    ...imagens.map(b64 => ({ type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: b64 } })),
    { type: 'text', text: prompt }
  ];
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 2048,
      messages: [{ role: 'user', content }]
    })
  });
  if (!response.ok) {
    const body = (await response.text()).slice(0, 500);
    await logErroAgenda('ler-comprovante pagamento api', body, userLog);
    const err = new Error('Erro na leitura do comprovante (' + response.status + ').');
    err.status = 502;
    throw err;
  }
  const data = await response.json();
  const raw = (data.content || []).map(b => b.text || '').join('').replace(/```json|```/g, '').trim();
  let parsed = null;
  try { parsed = JSON.parse(raw); }
  catch(e) {
    const ini = raw.indexOf('{'), fim = raw.lastIndexOf('}');
    if (ini >= 0 && fim > ini) {
      try { parsed = JSON.parse(raw.slice(ini, fim + 1)); } catch(_) {}
    }
  }
  if (!parsed) {
    await logErroAgenda('ler-comprovante pagamento parse', raw.slice(0, 180), userLog);
    const err = new Error('Não consegui ler os dados do comprovante. Tente uma imagem mais nítida ou cole o texto.');
    err.status = 422;
    throw err;
  }
  return normalizarPagamentoInput({
    ...parsed,
    data: parsed.data || dataPadrao,
    comprovante_texto: texto,
    origem: imagens.length ? 'imagem_ia' : 'texto_ia',
  });
}

function resumirResponsaveis(porResp) {
  return Object.entries(porResp || {})
    .sort((a, b) => b[1].total - a[1].total)
    .map(([nome, d]) => {
      const partes = [];
      if (d.entradas) partes.push(`${d.entradas} ent`);
      if (d.saidas) partes.push(`${d.saidas} saí`);
      if (d.perdas) partes.push(`${d.perdas} perda`);
      if (d.ajustes) partes.push(`${d.ajustes} ajuste`);
      return `• ${nome}: ${d.total}${partes.length ? ` (${partes.join(', ')})` : ''}`;
    }).join('\n');
}

async function resumoMovimentosDia(dataDia) {
  const { data, error } = await supabase.from('movimentacoes')
    .select('tipo, qtd, valor, responsavel, produto_nome, unidade, motivo, obs')
    .gte('created_at', dataDia + 'T00:00:00-03:00')
    .lte('created_at', dataDia + 'T23:59:59-03:00');
  if (error) throw error;

  const resumo = {
    total: 0,
    compras: 0, consumo: 0, perdas: 0, ajustes: 0,
    n_compras: 0, n_consumo: 0, n_perdas: 0, n_ajustes: 0,
    anomalias: 0,
    por_responsavel: {},
    perdas_itens: [],
  };
  const perdasPorItem = {};

  for (const m of (data || [])) {
    const tipo = m.tipo || '';
    const valor = Number(m.valor || 0);
    const qtd = Number(m.qtd || 0);
    const resp = m.responsavel || 'Não identificado';
    if (!resumo.por_responsavel[resp]) {
      resumo.por_responsavel[resp] = { total: 0, entradas: 0, saidas: 0, perdas: 0, ajustes: 0 };
    }
    const pr = resumo.por_responsavel[resp];
    pr.total++;
    resumo.total++;
    if (m.obs && /anomalia/i.test(m.obs)) resumo.anomalias++;

    if (tipo === 'Entrada') {
      resumo.compras += valor; resumo.n_compras++; pr.entradas++;
    } else if (tipo === 'Saída') {
      resumo.consumo += valor; resumo.n_consumo++; pr.saidas++;
    } else if (tipo === 'Perda') {
      resumo.perdas += valor; resumo.n_perdas++; pr.perdas++;
      const key = `${m.produto_nome || '?'}|${m.unidade || ''}`;
      if (!perdasPorItem[key]) perdasPorItem[key] = {
        produto_nome: m.produto_nome || '?',
        unidade: m.unidade || '',
        qtd: 0,
        valor: 0,
        motivos: new Set(),
      };
      perdasPorItem[key].qtd += qtd;
      perdasPorItem[key].valor += valor;
      if (m.motivo) perdasPorItem[key].motivos.add(m.motivo);
    } else if (tipo === 'Ajuste') {
      resumo.ajustes += valor; resumo.n_ajustes++; pr.ajustes++;
    }
  }

  resumo.compras = Number(resumo.compras.toFixed(2));
  resumo.consumo = Number(resumo.consumo.toFixed(2));
  resumo.perdas = Number(resumo.perdas.toFixed(2));
  resumo.ajustes = Number(resumo.ajustes.toFixed(2));
  resumo.perdas_itens = Object.values(perdasPorItem)
    .map(p => ({
      produto_nome: p.produto_nome,
      unidade: p.unidade,
      qtd: Number(p.qtd.toFixed(3)),
      valor: Number(p.valor.toFixed(2)),
      motivos: Array.from(p.motivos).slice(0, 3),
    }))
    .sort((a, b) => b.valor - a.valor)
    .slice(0, 10);
  return resumo;
}

async function buscarFechamentoDia(dataDia) {
  const { data, error } = await supabase.from('fechamentos_diarios')
    .select('data, vendas, observacao, responsavel, updated_at, created_at, pratos_vendidos, pagamentos, cortes, despesas, relatorio_texto, lixo_buffet_g')
    .eq('data', dataDia)
    .maybeSingle();
  if (error) {
    if (isTabelaFechamentoMissing(error)) return { row: null, configuracao_pendente: true };
    throw error;
  }
  return { row: data || null, configuracao_pendente: false };
}

async function montarRealidadeDia(dataDiaParam) {
  const dataDia = validarDataISO(dataDiaParam);
  const ontem = addDiasISO(dataDia, -1);
  const [mov, fechamento, movOntem] = await Promise.all([
    resumoMovimentosDia(dataDia),
    buscarFechamentoDia(dataDia),
    resumoMovimentosDia(ontem).catch(() => null),
  ]);

  let fechamentoOntem = { row: null, configuracao_pendente: fechamento.configuracao_pendente };
  if (!fechamento.configuracao_pendente) {
    fechamentoOntem = await buscarFechamentoDia(ontem).catch(() => ({ row: null, configuracao_pendente: false }));
  }

  const row = fechamento.row || null;
  const pagamentos = normalizarLinhasFinanceiras(row?.pagamentos || [], { comQtd: true });
  const cortes = normalizarLinhasFinanceiras(row?.cortes || [], { comQtd: true });
  const despesasLista = normalizarLinhasFinanceiras(row?.despesas || [], { comQtd: false });
  const totalPagamentos = somaLinhasFinanceiras(pagamentos);
  const totalCortes = somaLinhasFinanceiras(cortes);
  const despesasCaixa = somaLinhasFinanceiras(despesasLista);
  const vendas = Number(row?.vendas || totalPagamentos || 0);
  const pratosVendidos = parseNonNegativeInteger(row?.pratos_vendidos || 0);
  const lucroBruto = Number((vendas - mov.consumo - mov.perdas).toFixed(2));
  const resultadoDia = Number((lucroBruto - despesasCaixa).toFixed(2));
  const fluxoCaixa = Number((vendas - despesasCaixa).toFixed(2));
  const vendasOntem = Number(fechamentoOntem.row?.vendas || 0);
  const despesasOntem = somaLinhasFinanceiras(fechamentoOntem.row?.despesas || []);
  const lucroOntem = movOntem ? Number((vendasOntem - movOntem.consumo - movOntem.perdas).toFixed(2)) : 0;
  const resultadoOntem = Number((lucroOntem - despesasOntem).toFixed(2));

  return {
    data: dataDia,
    data_br: dataBR(dataDia),
    vendas,
    venda_lancada: !!fechamento.row,
    observacao: row?.observacao || '',
    responsavel: row?.responsavel || '',
    atualizado_em: row?.updated_at || row?.created_at || null,
    pratos_vendidos: pratosVendidos,
    ticket_medio: pratosVendidos > 0 ? Number((vendas / pratosVendidos).toFixed(2)) : null,
    pagamentos,
    total_pagamentos: totalPagamentos,
    cortes,
    total_cortes: totalCortes,
    despesas_lista: despesasLista,
    despesas: despesasCaixa,
    relatorio_texto: row?.relatorio_texto || '',
    // Lixo do buffet é ANOTAÇÃO (gramas): não entra em venda, despesa nem estoque.
    lixo_buffet_g: row?.lixo_buffet_g ?? null,
    configuracao_pendente: fechamento.configuracao_pendente,
    compras_estoque: mov.compras,
    consumo_estoque: mov.consumo,
    perdas_estoque: mov.perdas,
    perdas: mov.perdas,
    ajustes: mov.ajustes,
    lucro_bruto_estimado: lucroBruto,
    resultado_dia_estimado: resultadoDia,
    fluxo_caixa: fluxoCaixa,
    consumo_sobre_vendas_pct: pct(mov.consumo, vendas),
    perdas_sobre_vendas_pct: pct(mov.perdas, vendas),
    despesas_sobre_vendas_pct: pct(despesasCaixa, vendas),
    compras_sobre_vendas_pct: pct(mov.compras, vendas),
    movimentos: mov,
    comparativo: {
      ontem: {
        data: ontem,
        data_br: dataBR(ontem),
        vendas: vendasOntem,
        lucro_bruto_estimado: lucroOntem,
        resultado_dia_estimado: resultadoOntem,
        despesas: despesasOntem,
        perdas: movOntem ? movOntem.perdas : 0,
        consumo_estoque: movOntem ? movOntem.consumo : 0,
        dif_vendas: Number((vendas - vendasOntem).toFixed(2)),
        dif_lucro: Number((lucroBruto - lucroOntem).toFixed(2)),
        dif_resultado: Number((resultadoDia - resultadoOntem).toFixed(2)),
        dif_perdas: Number((mov.perdas - (movOntem ? movOntem.perdas : 0)).toFixed(2)),
        dif_despesas: Number((despesasCaixa - despesasOntem).toFixed(2)),
      }
    }
  };
}

function movimentoVazioDia() {
  return {
    total: 0,
    compras: 0, consumo: 0, perdas: 0, ajustes: 0,
    n_compras: 0, n_consumo: 0, n_perdas: 0, n_ajustes: 0,
    anomalias: 0,
  };
}

// Supabase/PostgREST corta QUALQUER select em 1000 linhas por request. Busca de
// PERÍODO (planilha, relatórios, inventário, export, reconciliação) precisa paginar —
// senão o mês "para no dia 11" (bug real 18/07: julho tinha 2.169 movimentações e a
// Planilha só somava as 1.000 primeiras → compras/consumo zerados do dia 11 em diante).
// buildQuery deve retornar a query JÁ com .order() estável (id) pra paginação determinística.
async function fetchTodas(buildQuery, pageSize = 1000) {
  const todas = [];
  for (let from = 0; ; from += pageSize) {
    const { data, error } = await buildQuery().range(from, from + pageSize - 1);
    if (error) throw error;
    todas.push(...(data || []));
    if (!data || data.length < pageSize) break;
  }
  return todas;
}

async function montarPlanilhaMensal(mesParam) {
  const mes = validarMesISO(mesParam);
  const inicio = `${mes}-01`;
  const fim = fimMesISO(mes);
  const datas = datasEntreISO(inicio, fim);
  const movPorDia = Object.fromEntries(datas.map(d => [d, movimentoVazioDia()]));
  let configuracaoPendente = false;

  const movimentos = await fetchTodas(() => supabase.from('movimentacoes')
    .select('created_at, tipo, valor, obs')
    .gte('created_at', inicio + 'T00:00:00-03:00')
    .lte('created_at', fim + 'T23:59:59-03:00')
    .order('id', { ascending: true }));

  for (const m of (movimentos || [])) {
    const dia = dataISOFromTimestampSP(m.created_at);
    if (!movPorDia[dia]) continue;
    const mov = movPorDia[dia];
    const valor = Number(m.valor || 0);
    const tipo = m.tipo || '';
    mov.total++;
    if (m.obs && /anomalia/i.test(m.obs)) mov.anomalias++;
    if (tipo === 'Entrada') { mov.compras += valor; mov.n_compras++; }
    else if (tipo === 'Saída') { mov.consumo += valor; mov.n_consumo++; }
    else if (tipo === 'Perda') { mov.perdas += valor; mov.n_perdas++; }
    else if (tipo === 'Ajuste') { mov.ajustes += valor; mov.n_ajustes++; }
  }
  for (const mov of Object.values(movPorDia)) {
    mov.compras = Number(mov.compras.toFixed(2));
    mov.consumo = Number(mov.consumo.toFixed(2));
    mov.perdas = Number(mov.perdas.toFixed(2));
    mov.ajustes = Number(mov.ajustes.toFixed(2));
  }

  let fechamentos = [];
  const { data: fechData, error: fechErr } = await supabase.from('fechamentos_diarios')
    .select('data, vendas, observacao, responsavel, updated_at, created_at, pratos_vendidos, pagamentos, cortes, despesas, relatorio_texto, lixo_buffet_g')
    .gte('data', inicio)
    .lte('data', fim)
    .order('data', { ascending: true });
  if (fechErr) {
    if (isTabelaFechamentoMissing(fechErr)) configuracaoPendente = true;
    else throw fechErr;
  } else {
    fechamentos = fechData || [];
  }

  const fechPorDia = Object.fromEntries(fechamentos.map(row => [String(row.data).slice(0, 10), row]));
  const formasMes = resumoFormasPagamento([]);
  const totais = {
    dias_mes: datas.length,
    dias_com_caixa: 0,
    dias_com_estoque: 0,
    dias_com_movimento: 0,
    dias_sem_caixa: 0,
    pratos_vendidos: 0,
    vendas: 0,
    total_pagamentos: 0,
    cortes: 0,
    despesas: 0,
    compras_estoque: 0,
    consumo_estoque: 0,
    perdas: 0,
    ajustes: 0,
    lucro_bruto_estimado: 0,
    resultado_dia_estimado: 0,
    fluxo_caixa: 0,
    anomalias: 0,
    ticket_medio: null,
    lixo_buffet_g: 0, // anotação acumulada do mês (gramas) — fora das somas financeiras
    dias_com_lixo: 0,
  };

  const dias = datas.map(dataDia => {
    const row = fechPorDia[dataDia] || null;
    const mov = movPorDia[dataDia] || movimentoVazioDia();
    const pagamentos = normalizarLinhasFinanceiras(row?.pagamentos || [], { comQtd: true });
    const cortes = normalizarLinhasFinanceiras(row?.cortes || [], { comQtd: true });
    const despesasLista = normalizarLinhasFinanceiras(row?.despesas || [], { comQtd: false });
    const formas = resumoFormasPagamento(pagamentos);
    somarResumoFormas(formasMes, formas);

    const totalPagamentos = somaLinhasFinanceiras(pagamentos);
    const vendas = Number(row?.vendas || totalPagamentos || 0);
    const totalCortes = somaLinhasFinanceiras(cortes);
    const despesas = somaLinhasFinanceiras(despesasLista);
    const pratosVendidos = parseNonNegativeInteger(row?.pratos_vendidos || 0);
    const lucroBruto = Number((vendas - mov.consumo - mov.perdas).toFixed(2));
    const resultadoDia = Number((lucroBruto - despesas).toFixed(2));
    const fluxoCaixa = Number((vendas - despesas).toFixed(2));
    const vendaLancada = !!row;
    const temEstoque = mov.total > 0;
    const temMovimento = vendaLancada || temEstoque;
    const status = vendaLancada ? (temEstoque ? 'fechado' : 'caixa') : (temEstoque ? 'sem_caixa' : 'vazio');

    totais.dias_com_caixa += vendaLancada ? 1 : 0;
    totais.dias_com_estoque += temEstoque ? 1 : 0;
    totais.dias_com_movimento += temMovimento ? 1 : 0;
    totais.pratos_vendidos += pratosVendidos;
    totais.vendas += vendas;
    totais.total_pagamentos += totalPagamentos;
    totais.cortes += totalCortes;
    totais.despesas += despesas;
    totais.compras_estoque += mov.compras;
    totais.consumo_estoque += mov.consumo;
    totais.perdas += mov.perdas;
    totais.ajustes += mov.ajustes;
    totais.lucro_bruto_estimado += lucroBruto;
    totais.resultado_dia_estimado += resultadoDia;
    totais.fluxo_caixa += fluxoCaixa;
    totais.anomalias += mov.anomalias;
    const lixoDia = row?.lixo_buffet_g != null ? Number(row.lixo_buffet_g) : null;
    if (lixoDia != null && lixoDia > 0) { totais.lixo_buffet_g += lixoDia; totais.dias_com_lixo += 1; }

    return {
      data: dataDia,
      data_br: dataBR(dataDia),
      dia_semana: diaSemanaBR(dataDia),
      status,
      venda_lancada: vendaLancada,
      tem_movimento: temMovimento,
      pratos_vendidos: pratosVendidos,
      vendas,
      pagamentos,
      formas,
      total_pagamentos: totalPagamentos,
      cortes,
      total_cortes: totalCortes,
      despesas_lista: despesasLista,
      despesas,
      compras_estoque: mov.compras,
      consumo_estoque: mov.consumo,
      perdas: mov.perdas,
      ajustes: mov.ajustes,
      lucro_bruto_estimado: lucroBruto,
      resultado_dia_estimado: resultadoDia,
      fluxo_caixa: fluxoCaixa,
      movimentos_total: mov.total,
      movimentos: mov,
      responsavel: row?.responsavel || '',
      observacao: row?.observacao || '',
      lixo_buffet_g: row?.lixo_buffet_g ?? null,
      atualizado_em: row?.updated_at || row?.created_at || null,
    };
  });

  for (const key of ['vendas','total_pagamentos','cortes','despesas','compras_estoque','consumo_estoque','perdas','ajustes','lucro_bruto_estimado','resultado_dia_estimado','fluxo_caixa']) {
    totais[key] = Number(totais[key].toFixed(2));
  }
  totais.dias_sem_caixa = dias.filter(d => d.movimentos_total > 0 && !d.venda_lancada).length;
  totais.ticket_medio = totais.pratos_vendidos > 0 ? Number((totais.vendas / totais.pratos_vendidos).toFixed(2)) : null;
  // Mesmos percentuais que o dia isolado já mostra (consumo/perdas/despesas/compras sobre
  // vendas), agora também pro mês inteiro — calculados a partir dos TOTAIS somados (não a
  // média dos percentuais diários, que seria matematicamente errado com dias de venda desigual).
  totais.consumo_sobre_vendas_pct = pct(totais.consumo_estoque, totais.vendas);
  totais.perdas_sobre_vendas_pct = pct(totais.perdas, totais.vendas);
  totais.despesas_sobre_vendas_pct = pct(totais.despesas, totais.vendas);
  totais.compras_sobre_vendas_pct = pct(totais.compras_estoque, totais.vendas);

  const formasPagamento = Object.values(formasMes)
    .map(row => ({ ...row, valor: Number(Number(row.valor || 0).toFixed(2)) }))
    .filter(row => row.valor > 0 || row.qtd > 0)
    .sort((a, b) => b.valor - a.valor);

  return {
    mes,
    mes_label: mes.split('-').reverse().join('/'),
    inicio,
    fim,
    configuracao_pendente: configuracaoPendente,
    totais,
    formas_pagamento: formasPagamento,
    pendencias: {
      sem_caixa: dias.filter(d => d.movimentos_total > 0 && !d.venda_lancada).map(d => d.data),
      vazios: dias.filter(d => !d.tem_movimento).map(d => d.data),
    },
    dias,
  };
}

// ÍNDICES GERENCIAIS (DRE de restaurante) — CMV, CMO, Prime Cost, custo total.
// Mostra SEMPRE duas colunas: o mês e a média dos últimos 3 meses. Motivo (Rubens,
// 01/08): item comprado em lote distorce o mês isolado — "tem mês que gasta muito com
// gás porque abasteceu 2x, e no outro não precisa". O mês serve pra conferir lançamento;
// a média de 3 meses é a que serve pra decidir. Percentual só fecha de verdade com a
// janela cheia, então o retorno diz quantos meses realmente têm dado.
const MESES_JANELA = 3;


function mesesAnteriores(mes, n) {
  const [ano, m] = mes.split('-').map(Number);
  const lista = [];
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(Date.UTC(ano, m - 1 - i, 1));
    lista.push(`${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`);
  }
  return lista;
}

async function montarIndices(mesParam) {
  const mes = validarMesISO(mesParam);
  const meses = mesesAnteriores(mes, MESES_JANELA);
  const inicioJanela = `${meses[0]}-01`;
  const fimMes = fimMesISO(mes);

  const [fechamentos, pagamentos, movimentos] = await Promise.all([
    supabase.from('fechamentos_diarios').select('data, vendas')
      .gte('data', inicioJanela).lte('data', fimMes)
      .then(r => { if (r.error && !isTabelaFechamentoMissing(r.error)) throw r.error; return r.data || []; }),
    fetchTodas(() => supabase.from('pagamentos_comprovantes').select('data, grupo, categoria, valor_bruto, quitacao, competencia')
      .gte('data', inicioJanela).lte('data', fimMes).order('id', { ascending: true }))
      .catch(e => { if (isTabelaPagamentosMissing(e)) return []; throw e; }),
    fetchTodas(() => supabase.from('movimentacoes').select('created_at, tipo, valor')
      .gte('created_at', inicioJanela + 'T00:00:00-03:00').lte('created_at', fimMes + 'T23:59:59-03:00')
      .order('id', { ascending: true })),
  ]);

  const noMes = d => String(d || '').slice(0, 7) === mes;
  const vendasPorMes = {};
  for (const f of fechamentos) {
    const m = String(f.data).slice(0, 7);
    vendasPorMes[m] = (vendasPorMes[m] || 0) + Number(f.vendas || 0);
  }
  const vendasMes = Number((vendasPorMes[mes] || 0).toFixed(2));

  // A janela é definida pelos meses com CUSTO lançado, não com venda. Sem isso o
  // percentual médio vira ficção: dividir 1 mês de contas por 3 meses de venda deu
  // "Prime Cost 21%" no primeiro teste (o certo era 72%). Hoje só julho/2026 tem contas
  // — a aba Contas nasceu no v52 (14/07) e o backfill cobriu só julho.
  const lancPorMes = {};
  for (const p of pagamentos) {
    const m = String(p.data || '').slice(0, 7);
    lancPorMes[m] = (lancPorMes[m] || 0) + 1;
  }
  const mesesComCusto = meses.filter(m => (lancPorMes[m] || 0) > 0);
  const mesesJanela = mesesComCusto.length ? mesesComCusto : [mes];
  const vendasJanela = Number(mesesJanela.reduce((s, m) => s + (vendasPorMes[m] || 0), 0).toFixed(2));

  // Consumo real do estoque: o CMV que de fato saiu pra cozinha. Serve de contraprova
  // do CMV por compras — os dois deveriam convergir; enquanto não convergem, o CMV
  // verdadeiro está do lado do consumo.
  let consumoMes = 0, consumoJanela = 0;
  for (const mv of movimentos) {
    if (mv.tipo !== 'Saída') continue;
    const v = Number(mv.valor || 0);
    consumoJanela += v;
    if (dataISOFromTimestampSP(mv.created_at).slice(0, 7) === mes) consumoMes += v;
  }

  const zero = () => ({ mes: 0, janela: 0, n_mes: 0, n_janela: 0 });
  const porGrupo = Object.fromEntries(CONTAS_PLANILHA_PAGAMENTOS.map(g => [g.grupo, zero()]));
  const dentroJanela = new Set(mesesJanela);
  const naoOperacional = { mes: 0, janela: 0, n_mes: 0 };
  const quitacoes = { mes: 0, n_mes: 0 };
  for (const p of pagamentos) {
    const g = p.grupo || 'Outras Despesas';
    const v = Number(p.valor_bruto || 0);
    const naJanela = dentroJanela.has(String(p.data || '').slice(0, 7));
    // Quitação (comprovante de pagamento da folha): o dinheiro saiu, mas o custo já foi
    // reconhecido pela folha na competência. Contar de novo dobraria o CMO.
    if (p.quitacao) {
      if (noMes(p.data)) { quitacoes.mes += v; quitacoes.n_mes++; }
      continue;
    }
    if (ehNaoOperacional(g, p.categoria)) {   // retirada: registrada, fora do custo
      if (naJanela) naoOperacional.janela += v;
      if (noMes(p.data)) { naoOperacional.mes += v; naoOperacional.n_mes++; }
      continue;
    }
    if (!porGrupo[g]) porGrupo[g] = zero();
    if (naJanela) { porGrupo[g].janela += v; porGrupo[g].n_janela++; }
    if (noMes(p.data)) { porGrupo[g].mes += v; porGrupo[g].n_mes++; }
  }

  const nMeses = mesesJanela.length;
  const grupos = CONTAS_PLANILHA_PAGAMENTOS.map(g => {
    const d = porGrupo[g.grupo] || zero();
    // "Nunca lançado" x "esqueceu este mês" são problemas diferentes e pedem ação diferente.
    const status = d.n_mes > 0 ? 'ok' : (d.n_janela > 0 ? 'faltando_mes' : 'nunca');
    return {
      grupo: g.grupo,
      valor_mes: Number(d.mes.toFixed(2)),
      pct_mes: pct(d.mes, vendasMes),
      valor_janela: Number(d.janela.toFixed(2)),
      media_mensal: Number((d.janela / nMeses).toFixed(2)),
      pct_janela: pct(d.janela, vendasJanela),
      lancamentos_mes: d.n_mes,
      lancamentos_janela: d.n_janela,
      status,
    };
  });

  const somaDe = (nomes, campo) => Number(grupos.filter(g => nomes.includes(g.grupo))
    .reduce((s, g) => s + g[campo], 0).toFixed(2));
  const GRUPOS_PRIME = ['Despesas Variáveis - CMV', 'CMV Bebidas', 'Despesas Fixas / CMO'];
  const todosGrupos = grupos.map(g => g.grupo);

  const derivado = (nomes, rotulo) => {
    const vMes = somaDe(nomes, 'valor_mes');
    const vJanela = somaDe(nomes, 'valor_janela');
    return {
      rotulo,
      valor_mes: vMes, pct_mes: pct(vMes, vendasMes),
      valor_janela: vJanela, pct_janela: pct(vJanela, vendasJanela),
      media_mensal: Number((vJanela / nMeses).toFixed(2)),
    };
  };
  const primeCost = derivado(GRUPOS_PRIME, 'Prime Cost');
  const custoTotal = derivado(todosGrupos, 'Custo total');
  const sobraMes = Number((vendasMes - custoTotal.valor_mes).toFixed(2));
  const sobraJanela = Number((vendasJanela - custoTotal.valor_janela).toFixed(2));

  return {
    mes,
    mes_label: mes.split('-').reverse().join('/'),
    janela: {
      meses,
      meses_com_custo: mesesJanela,
      n_meses: nMeses,
      completa: mesesComCusto.length >= MESES_JANELA,
      aviso: mesesComCusto.length >= MESES_JANELA ? null
        : `A média cobre ${nMeses} ${nMeses === 1 ? 'mês' : 'meses'} de contas lançadas, não ${MESES_JANELA}. Item comprado em lote (gás, óleo, descartável) distorce mês isolado — o percentual só estabiliza com a janela cheia.`,
    },
    vendas_mes: vendasMes,
    vendas_janela: vendasJanela,
    consumo_estoque: {
      valor_mes: Number(consumoMes.toFixed(2)), pct_mes: pct(consumoMes, vendasMes),
      valor_janela: Number(consumoJanela.toFixed(2)), pct_janela: pct(consumoJanela, vendasJanela),
    },
    grupos,
    prime_cost: primeCost,
    custo_total: custoTotal,
    sobra: {
      valor_mes: sobraMes, pct_mes: pct(sobraMes, vendasMes),
      valor_janela: sobraJanela, pct_janela: pct(sobraJanela, vendasJanela),
    },
    // Confronto folha x pagamento: a folha diz quanto CUSTOU (competência), os
    // comprovantes dizem quanto já SAIU. A diferença é o que ainda falta pagar.
    folha: (() => {
      const custo = grupos.find(g => g.grupo === 'Despesas Fixas / CMO')?.valor_mes || 0;
      const pago = Number(quitacoes.mes.toFixed(2));
      return {
        custo_mes: custo,
        pago_mes: pago,
        em_aberto: Number((custo - pago).toFixed(2)),
        comprovantes: quitacoes.n_mes,
      };
    })(),
    // Fora do custo, mostrado à parte: saiu do caixa mas é distribuição, não despesa.
    nao_operacional: {
      rotulo: 'Retiradas de sócio',
      valor_mes: Number(naoOperacional.mes.toFixed(2)),
      pct_mes: pct(naoOperacional.mes, vendasMes),
      valor_janela: Number(naoOperacional.janela.toFixed(2)),
      lancamentos_mes: naoOperacional.n_mes,
      sobra_apos_retiradas: Number((sobraMes - naoOperacional.mes).toFixed(2)),
    },
    sem_dado: grupos.filter(g => g.status !== 'ok').map(g => ({ grupo: g.grupo, status: g.status })),
  };
}

async function montarRelatorioPeriodo(inicioParam, fimParam) {
  let inicio = validarDataISO(inicioParam || dateAgoDias(6));
  let fim = validarDataISO(fimParam || dateSP());
  if (inicio > fim) [inicio, fim] = [fim, inicio];
  const datas = datasEntreISO(inicio, fim);
  const diasMap = Object.fromEntries(datas.map(data => [data, {
    data,
    data_br: dataBR(data),
    vendas: 0,
    pratos_vendidos: 0,
    despesas: 0,
    cortes: 0,
    compras_estoque: 0,
    consumo_estoque: 0,
    perdas: 0,
    ajustes: 0,
    contas_pagas: 0,
    movimentos_total: 0,
    venda_lancada: false,
  }]));

  // movimentacoes e pagamentos paginados (período pode passar de 1000 linhas fácil);
  // fechamentos são no máx. 1 por dia — sem risco de corte.
  const [movTodas, fechRes, pagResData] = await Promise.all([
    fetchTodas(() => supabase.from('movimentacoes')
      .select('tipo, valor, created_at')
      .gte('created_at', inicio + 'T00:00:00-03:00')
      .lte('created_at', fim + 'T23:59:59-03:00')
      .order('id', { ascending: true })),
    supabase.from('fechamentos_diarios')
      .select('data, vendas, pratos_vendidos, pagamentos, cortes, despesas')
      .gte('data', inicio)
      .lte('data', fim)
      .order('data', { ascending: true }),
    fetchTodas(() => supabase.from('pagamentos_comprovantes')
      .select('*')
      .gte('data', inicio)
      .lte('data', fim)
      .order('data', { ascending: false })
      .order('id', { ascending: false }))
      .then(data => ({ data, error: null }))
      .catch(error => ({ data: null, error })),
  ]);
  const movRes = { data: movTodas, error: null };
  const pagRes = pagResData;
  const configuracaoPendente = {
    fechamentos: false,
    pagamentos: false,
  };
  let fechamentos = [];
  if (fechRes.error) {
    if (isTabelaFechamentoMissing(fechRes.error)) configuracaoPendente.fechamentos = true;
    else throw fechRes.error;
  } else {
    fechamentos = fechRes.data || [];
  }

  let pagamentosContas = [];
  if (pagRes.error) {
    if (isTabelaPagamentosMissing(pagRes.error)) configuracaoPendente.pagamentos = true;
    else throw pagRes.error;
  } else {
    pagamentosContas = (pagRes.data || []).map(normalizarPagamentoDb);
  }

  const formasMes = resumoFormasPagamento([]);
  const totais = {
    dias_periodo: datas.length,
    dias_com_caixa: 0,
    vendas: 0,
    total_pagamentos: 0,
    pratos_vendidos: 0,
    ticket_medio: null,
    cortes: 0,
    despesas_caixa: 0,
    compras_estoque: 0,
    consumo_estoque: 0,
    perdas: 0,
    ajustes: 0,
    resultado_operacional: 0,
    fluxo_caixa: 0,
    contas_pagas: 0,
    contas_liquido: 0,
    contas_taxas: 0,
    lancamentos_contas: pagamentosContas.length,
  };

  for (const row of fechamentos) {
    const data = String(row.data).slice(0, 10);
    const dia = diasMap[data];
    if (!dia) continue;
    const pagamentos = normalizarLinhasFinanceiras(row.pagamentos || [], { comQtd: true });
    const formas = resumoFormasPagamento(pagamentos);
    somarResumoFormas(formasMes, formas);
    const totalPagamentos = somaLinhasFinanceiras(pagamentos);
    const vendas = Number(row.vendas || totalPagamentos || 0);
    const cortes = somaLinhasFinanceiras(row.cortes || []);
    const despesas = somaLinhasFinanceiras(row.despesas || []);
    const pratos = parseNonNegativeInteger(row.pratos_vendidos || 0);
    Object.assign(dia, {
      vendas,
      total_pagamentos: totalPagamentos,
      pratos_vendidos: pratos,
      cortes,
      despesas,
      venda_lancada: true,
    });
    totais.dias_com_caixa++;
    totais.vendas += vendas;
    totais.total_pagamentos += totalPagamentos;
    totais.pratos_vendidos += pratos;
    totais.cortes += cortes;
    totais.despesas_caixa += despesas;
  }

  for (const mov of (movRes.data || [])) {
    const data = dataISOFromTimestampSP(mov.created_at);
    const dia = diasMap[data];
    if (!dia) continue;
    const valor = Number(mov.valor || 0);
    dia.movimentos_total++;
    if (mov.tipo === 'Entrada') dia.compras_estoque += valor;
    else if (mov.tipo === 'Saída') dia.consumo_estoque += valor;
    else if (mov.tipo === 'Perda') dia.perdas += valor;
    else if (mov.tipo === 'Ajuste') dia.ajustes += valor;
  }

  for (const p of pagamentosContas) {
    const dia = diasMap[p.data];
    const bruto = Number(p.valor_bruto || 0);
    const liquido = Number(p.valor_liquido || 0);
    const taxa = Number(p.taxa || 0);
    if (dia) dia.contas_pagas += bruto;
    totais.contas_pagas += bruto;
    totais.contas_liquido += liquido;
    totais.contas_taxas += taxa;
  }

  for (const dia of Object.values(diasMap)) {
    for (const key of ['compras_estoque','consumo_estoque','perdas','ajustes','contas_pagas']) {
      dia[key] = Number(dia[key].toFixed(2));
    }
    dia.resultado_operacional = Number((dia.vendas - dia.consumo_estoque - dia.perdas - dia.despesas).toFixed(2));
    dia.fluxo_caixa = Number((dia.vendas - dia.despesas).toFixed(2));
    totais.compras_estoque += dia.compras_estoque;
    totais.consumo_estoque += dia.consumo_estoque;
    totais.perdas += dia.perdas;
    totais.ajustes += dia.ajustes;
    totais.resultado_operacional += dia.resultado_operacional;
    totais.fluxo_caixa += dia.fluxo_caixa;
  }

  for (const key of ['vendas','total_pagamentos','cortes','despesas_caixa','compras_estoque','consumo_estoque','perdas','ajustes','resultado_operacional','fluxo_caixa','contas_pagas','contas_liquido','contas_taxas']) {
    totais[key] = Number(totais[key].toFixed(2));
  }
  totais.ticket_medio = totais.pratos_vendidos > 0 ? Number((totais.vendas / totais.pratos_vendidos).toFixed(2)) : null;

  const formasPagamento = Object.values(formasMes)
    .map(row => ({ ...row, valor: Number(Number(row.valor || 0).toFixed(2)) }))
    .filter(row => row.valor > 0 || row.qtd > 0)
    .sort((a, b) => b.valor - a.valor);

  return {
    inicio,
    fim,
    inicio_br: dataBR(inicio),
    fim_br: dataBR(fim),
    configuracao_pendente: configuracaoPendente,
    totais,
    formas_pagamento: formasPagamento,
    contas: {
      por_grupo: agruparPagamentos(pagamentosContas, 'grupo'),
      por_categoria: agruparPagamentosPorConta(pagamentosContas),
      por_forma: agruparPagamentos(pagamentosContas, 'forma'),
      pagamentos: pagamentosContas.slice(0, 80),
    },
    dias: Object.values(diasMap),
  };
}

function montarMensagemFechamentoDia(d) {
  const vendasLancadas = !!d.venda_lancada;
  const semMovimento = d.movimentos.total === 0;
  if (!vendasLancadas && semMovimento) {
    return `📋 *FECHAMENTO DO DIA — ${d.data_br}*\n\n⚠️ Nada registrado hoje.\n\nLance o movimento do caixa na aba Dia e registre consumo/perdas no estoque para calcular a realidade.`;
  }

  let msg = `📋 *FECHAMENTO DO DIA — ${d.data_br}*\n\n`;
  if (d.pratos_vendidos) msg += `🍽️ Pratos vendidos: ${d.pratos_vendidos}\n`;
  msg += `💰 Vendas recebidas: ${vendasLancadas ? fmtBRL(d.vendas) : 'não lançada'}\n`;
  if (vendasLancadas && d.ticket_medio) msg += `🎟️ Ticket médio: ${fmtBRL(d.ticket_medio)}\n`;
  msg += `📦 Compras do estoque: ${fmtBRL(d.compras_estoque)}\n`;
  msg += `🍳 Consumo do estoque: ${fmtBRL(d.consumo_estoque)}\n`;
  msg += `🗑️ Perdas do estoque: ${fmtBRL(d.perdas)}\n`;
  if (d.despesas > 0) msg += `💸 Despesas do caixa: ${fmtBRL(d.despesas)}\n`;
  if (d.lixo_buffet_g != null && d.lixo_buffet_g > 0) msg += `🥡 Lixo final do buffet: ${d.lixo_buffet_g}g (anotação — não entra nas contas)\n`;

  if (d.pagamentos?.length) {
    msg += `\n💳 *Recebimentos:*\n`;
    msg += d.pagamentos.map(r => linhaFinanceiraTexto(r, true)).join('\n');
  }
  if (d.cortes?.length) {
    msg += `\n\n⚠️ *Cortes/sem cobrança:*\n`;
    msg += d.cortes.map(r => linhaFinanceiraTexto(r, true)).join('\n');
  }
  if (d.despesas_lista?.length) {
    msg += `\n\n💸 *Despesas:*\n`;
    msg += d.despesas_lista.slice(0, 12).map(r => linhaFinanceiraTexto(r, false)).join('\n');
    if (d.despesas_lista.length > 12) msg += `\n• +${d.despesas_lista.length - 12} despesa(s)`;
  }

  msg += `\n\n📊 *Leitura:*\n`;
  if (vendasLancadas) {
    msg += `Lucro estoque antes das despesas: ${fmtBRL(d.lucro_bruto_estimado)}\n`;
    msg += `Resultado estimado do dia: ${fmtBRL(d.resultado_dia_estimado)}\n`;
    msg += `Caixa do dia sem compras: ${fmtBRL(d.fluxo_caixa)}\n`;
    msg += `Consumo: ${d.consumo_sobre_vendas_pct?.toFixed(2)}% das vendas\n`;
    msg += `Perdas: ${d.perdas_sobre_vendas_pct?.toFixed(2)}% das vendas`;
    if (d.despesas > 0) msg += `\nDespesas: ${d.despesas_sobre_vendas_pct?.toFixed(2)}% das vendas`;
    if (d.compras_estoque > 0) msg += `\nCompras ficam separadas: são investimento/estoque, não despesa do resultado do dia.`;
  } else {
    msg += `Movimento do caixa ainda não lançado. Sem ele não dá para calcular lucro.\n`;
    msg += `O estoque já mostra ${fmtBRL(d.consumo_estoque)} de consumo e ${fmtBRL(d.perdas)} de perdas.`;
  }

  const ontem = d.comparativo?.ontem;
  if (vendasLancadas && ontem && ontem.vendas > 0) {
    msg += `\n\n📈 *Comparativo com ontem:*\n`;
    msg += `Vendas: ${ontem.dif_vendas >= 0 ? '+' : ''}${fmtBRL(ontem.dif_vendas)}\n`;
    msg += `Resultado: ${ontem.dif_resultado >= 0 ? '+' : ''}${fmtBRL(ontem.dif_resultado)}\n`;
    msg += `Perdas: ${ontem.dif_perdas >= 0 ? '+' : ''}${fmtBRL(ontem.dif_perdas)}`;
  }

  if (d.movimentos.total > 0) {
    msg += `\n\n📋 Estoque: ${d.movimentos.total} movimentações`;
    msg += ` (${d.movimentos.n_compras} ent, ${d.movimentos.n_consumo} saí`;
    if (d.movimentos.n_perdas) msg += `, ${d.movimentos.n_perdas} perdas`;
    if (d.movimentos.n_ajustes) msg += `, ${d.movimentos.n_ajustes} ajustes`;
    msg += `)`;
    const linhasResp = resumirResponsaveis(d.movimentos.por_responsavel);
    if (linhasResp) msg += `\n\n👤 *Quem lançou estoque:*\n${linhasResp}`;
  }

  if (d.configuracao_pendente) msg += `\n\n⚠️ Configure a tabela fechamentos_diarios para salvar o movimento do dia.`;
  if (d.movimentos.anomalias > 0) msg += `\n\n⚠️ ${d.movimentos.anomalias} lançamento(s) com quantidade anômala — revise no app.`;
  if (d.perdas > 0) msg += `\n🗑️ Perdas são descarte/lixo: isso é perda real, diferente de compra.`;
  return msg;
}

app.get('/api/realidade-dia', auth, requirePerm('dia'), async (req, res) => {
  try {
    const resumo = await montarRealidadeDia(req.query?.data);
    res.json(resumo);
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao carregar realidade do dia.' });
  }
});

app.post('/api/realidade-dia', auth, requirePerm('dia'), async (req, res) => {
  try {
    const dataDia = validarDataISO(req.body?.data);
    const pagamentos = normalizarLinhasFinanceiras(req.body?.pagamentos || [], { comQtd: true });
    const cortes = normalizarLinhasFinanceiras(req.body?.cortes || [], { comQtd: true });
    const despesas = normalizarLinhasFinanceiras(req.body?.despesas || [], { comQtd: false });
    const totalPagamentos = somaLinhasFinanceiras(pagamentos);
    const vendasInformadas = parseNonNegativeMoney(req.body?.vendas);
    const vendas = pagamentos.length ? totalPagamentos : vendasInformadas;
    const observacao = sanitizeText(req.body?.observacao || '', 300);
    const pratosVendidos = parseNonNegativeInteger(req.body?.pratos_vendidos || 0);
    const relatorioTexto = sanitizeLongText(req.body?.relatorio_texto || '', 6000);
    // Lixo do buffet: anotação em gramas (não soma em nada financeiro). Aceita 0..99999g.
    const lixoRaw = req.body?.lixo_buffet_g;
    const lixoBuffetG = (lixoRaw === null || lixoRaw === undefined || lixoRaw === '')
      ? null
      : Math.min(Math.max(parseNonNegativeInteger(lixoRaw) || 0, 0), 99999);
    if (vendas === null) return res.status(400).json({ erro: 'Informe o movimento do caixa com valor válido.' });

    const { error } = await supabase.from('fechamentos_diarios').upsert({
      data: dataDia,
      vendas,
      observacao,
      pratos_vendidos: pratosVendidos,
      pagamentos,
      cortes,
      despesas,
      relatorio_texto: relatorioTexto,
      lixo_buffet_g: lixoBuffetG,
      responsavel: req.user.nome || req.user.username,
      updated_at: nowSP(),
    }, { onConflict: chaveConflito('data') });
    if (error) {
      if (isTabelaFechamentoMissing(error)) {
        return res.status(500).json({ erro: 'Tabela fechamentos_diarios precisa ser atualizada. Rode o arquivo SUPABASE_REALIDADE_DIA.sql no Supabase.' });
      }
      throw error;
    }

    // Taxa da maquininha entra junto com o fechamento — sem isso a conta "Taxas de Cartão"
    // fica eternamente vazia e o custo total do mês sai menor do que é.
    const quem = req.user.nome || req.user.username;
    const taxasLancadas = await lancarTaxasDoDia(dataDia, resumoFormasPagamento(pagamentos), quem);
    const despesasLancadas = await lancarDespesasDoCaixaNasContas(dataDia, despesas, quem);

    await audit('realidade_dia_salvar', {
      data: dataDia,
      vendas,
      pratos_vendidos: pratosVendidos,
      pagamentos: pagamentos.length,
      cortes: cortes.length,
      despesas: despesas.length,
      taxas_lancadas: taxasLancadas,
      despesas_lancadas: despesasLancadas,
    }, req.user, getClientIp(req));
    const resumo = await montarRealidadeDia(dataDia);
    res.json(resumo);
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao salvar movimento do dia.' });
  }
});

app.delete('/api/realidade-dia', auth, requirePerm('dia'), async (req, res) => {
  try {
    const dataRaw = req.query?.data || req.body?.data;
    if (!isDataISO(dataRaw)) return res.status(400).json({ erro: 'Informe uma data válida.' });
    const dataDia = String(dataRaw);
    const { error } = await supabase.from('fechamentos_diarios').delete().eq('data', dataDia);
    if (error) {
      if (isTabelaFechamentoMissing(error)) {
        return res.status(500).json({ erro: 'Tabela fechamentos_diarios precisa ser atualizada.' });
      }
      throw error;
    }
    // Apagou o fechamento → a taxa calculada em cima dele não faz mais sentido.
    try {
      await supabase.from('pagamentos_comprovantes').delete().eq('data', dataDia)
        .in('origem', ['taxa-auto', 'taxa-backfill', 'caixa-auto', 'caixa-backfill']);
    } catch (e) { console.error('taxa/caixa-auto delete:', e.message); }
    await audit('realidade_dia_limpar', { data: dataDia }, req.user, getClientIp(req));
    const resumo = await montarRealidadeDia(dataDia);
    res.json(resumo);
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao limpar movimento do dia.' });
  }
});

app.post('/api/realidade-dia/mover', auth, requirePerm('dia'), async (req, res) => {
  try {
    if (!isDataISO(req.body?.data_origem) || !isDataISO(req.body?.data_destino)) {
      return res.status(400).json({ erro: 'Informe data de origem e destino válidas.' });
    }
    const origem = String(req.body.data_origem);
    const destino = String(req.body.data_destino);
    if (origem === destino) return res.status(400).json({ erro: 'A data de destino precisa ser diferente.' });

    const { data: rowOrigem, error: errOrigem } = await supabase.from('fechamentos_diarios')
      .select('data')
      .eq('data', origem)
      .maybeSingle();
    if (errOrigem) {
      if (isTabelaFechamentoMissing(errOrigem)) return res.status(500).json({ erro: 'Tabela fechamentos_diarios precisa ser atualizada.' });
      throw errOrigem;
    }
    if (!rowOrigem) return res.status(404).json({ erro: 'Não existe movimento salvo nesta data de origem.' });

    const { data: rowDestino, error: errDestino } = await supabase.from('fechamentos_diarios')
      .select('data')
      .eq('data', destino)
      .maybeSingle();
    if (errDestino) throw errDestino;
    if (rowDestino) return res.status(409).json({ erro: 'Já existe movimento salvo na data de destino. Abra essa data para editar ou limpar primeiro.' });

    const { error } = await supabase.from('fechamentos_diarios')
      .update({
        data: destino,
        responsavel: req.user.nome || req.user.username,
        updated_at: nowSP(),
      })
      .eq('data', origem);
    if (error) throw error;

    await audit('realidade_dia_mover', { origem, destino }, req.user, getClientIp(req));
    const resumo = await montarRealidadeDia(destino);
    res.json(resumo);
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao mover movimento do dia.' });
  }
});

app.get('/api/planilha-mensal', auth, requirePerm('planilha'), async (req, res) => {
  try {
    const planilha = await montarPlanilhaMensal(req.query?.mes);
    res.json(planilha);
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao carregar planilha mensal.' });
  }
});

// ── ABRIR UM RESTAURANTE NOVO NA PLATAFORMA ─────────────────────────────────
// O restaurante nasce PRONTO PRA USAR, não vazio (Rubens, 01/08: "deveria já vir
// completo, a pessoa se encaixa no perfil do aplicativo"). Deixar o estoque vazio
// joga a maior fricção no cliente logo no primeiro dia — cadastrar centenas de
// produtos é onde ele desiste. O catálogo-modelo (produtos_modelo) vem dos produtos
// reais do Toca, sem preço e sem quantidade: o dono revisa e ajusta em vez de digitar.
function requireSuperadmin(req, res, next) {
  if (req.user?.role !== 'superadmin') return res.status(403).json({ erro: 'Só a administração da plataforma pode fazer isso.' });
  next();
}

// ── VALIDAÇÃO DO CADASTRO ────────────────────────────────────────────────────
// Cadastro é a maior alavanca de retenção de um SaaS (pesquisa 01/08: onboarding
// responde por 30–50% da variação de churn). Mas aqui ele tem um segundo papel:
// impedir que um cadastro torto entre e quebre o fluxo depois — do cliente ou nosso.
// Tudo é validado no SERVIDOR; o formulário só antecipa a mensagem.

// Mod-11 da Receita. Confirma que o número é ESTRUTURALMENTE plausível — não confirma
// que a empresa existe nem que está ativa. Por isso o CNPJ é opcional: barrar cadastro
// por causa dele criaria atrito sem entregar a garantia que o cliente imagina.
function cnpjValido(valor) {
  const n = String(valor || '').replace(/\D/g, '');
  if (n.length !== 14) return false;
  if (/^(\d)\1{13}$/.test(n)) return false;               // 00000000000000 e afins passam no mod-11
  const dv = (base, pesos) => {
    const soma = base.split('').reduce((s, d, i) => s + Number(d) * pesos[i], 0);
    const r = soma % 11;
    return r < 2 ? 0 : 11 - r;
  };
  const d1 = dv(n.slice(0, 12), [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  const d2 = dv(n.slice(0, 13), [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  return d1 === Number(n[12]) && d2 === Number(n[13]);
}

const RESERVADOS = new Set(['admin', 'api', 'app', 'root', 'sistema', 'plataforma', 'suporte', 'null', 'undefined', 'teste', 'test', 'www']);

function validarCadastroRestaurante(b) {
  const erros = [];
  const nome = sanitizeText(b.nome || '', 120);
  if (nome.length < 3) erros.push({ campo: 'nome', erro: 'O nome do restaurante precisa de ao menos 3 letras.' });

  const slug = sanitizeText(b.slug || '', 60).toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{2,39}$/.test(slug)) {
    erros.push({ campo: 'slug', erro: 'O identificador deve ter de 3 a 40 caracteres, só letras minúsculas, números e hífen.' });
  } else if (RESERVADOS.has(slug)) {
    erros.push({ campo: 'slug', erro: `"${slug}" é reservado pelo sistema. Escolha outro.` });
  }

  const usuario = sanitizeText(b.admin_usuario || '', 40).toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,39}$/.test(usuario)) {
    erros.push({ campo: 'admin_usuario', erro: 'O usuário deve ter de 3 a 40 caracteres, só letras minúsculas, números, ponto, hífen ou sublinhado.' });
  } else if (RESERVADOS.has(usuario)) {
    erros.push({ campo: 'admin_usuario', erro: `"${usuario}" é reservado pelo sistema. Escolha outro.` });
  }

  const senha = String(b.admin_senha || '');
  if (senha.length < 8) erros.push({ campo: 'admin_senha', erro: 'A senha precisa de ao menos 8 caracteres.' });
  else if (!/[a-zA-Z]/.test(senha) || !/\d/.test(senha)) erros.push({ campo: 'admin_senha', erro: 'A senha precisa misturar letras e números.' });
  else if (senha.toLowerCase().includes(usuario) || /^(12345678|senha123|password)/i.test(senha)) {
    erros.push({ campo: 'admin_senha', erro: 'Essa senha é fácil de adivinhar. Escolha outra.' });
  }

  const cnpj = String(b.cnpj || '').replace(/\D/g, '');
  if (cnpj && !cnpjValido(cnpj)) erros.push({ campo: 'cnpj', erro: 'CNPJ inválido — confira os números.' });

  if (b.plano && !['financeiro', 'estoque', 'completo'].includes(b.plano)) {
    erros.push({ campo: 'plano', erro: 'Plano inválido.' });
  }
  return { erros, limpos: { nome, slug, usuario, senha, cnpj, plano: b.plano || 'financeiro' } };
}

async function abrirRestaurante({ nome, slug, cnpj, telefone, plano, admin_usuario, admin_senha, admin_nome, importar_catalogo = true }) {
  const raw = supabaseRaw;   // criação acontece FORA do contexto de tenant (o tenant ainda não existe)
  const { data: tenant, error: errT } = await raw.from('tenants').insert({
    nome: sanitizeText(nome, 120), slug: sanitizeText(slug, 60).toLowerCase(),
    cnpj: sanitizeText(cnpj || '', 20) || null, telefone: sanitizeText(telefone || '', 20) || null,
    plano: ['financeiro', 'estoque', 'completo'].includes(plano) ? plano : 'financeiro',
  }).select('*').single();
  if (errT) throw new Error(errT.message.includes('duplicate') ? 'Já existe restaurante com esse identificador.' : errT.message);

  const resumo = { tenant, categorias: 0, produtos: 0, usuario: null };

  // Criar restaurante são vários passos e o Postgrest não dá transação entre eles.
  // Se qualquer um falhar, DESFAZ tudo: restaurante criado pela metade é pior que
  // restaurante nenhum — o cliente entra, encontra o app quebrado e a confiança acaba
  // no primeiro dia. O cascade das FKs limpa categorias, produtos e usuários juntos.
  try {
    return await montarRestaurante(raw, tenant, resumo, { importar_catalogo, admin_usuario, admin_senha, admin_nome, nome, slug });
  } catch (e) {
    try { await raw.from('tenants').delete().eq('id', tenant.id); } catch (_) {}
    throw e;
  }
}

async function montarRestaurante(raw, tenant, resumo, { importar_catalogo, admin_usuario, admin_senha, admin_nome, nome, slug }) {
  // 1) Categorias: são a ponte produto → conta contábil. Sem elas o CMV não classifica.
  const { data: cats } = await raw.from('categorias').select('nome').eq('tenant_id', TENANT_MODELO);
  const nomesCat = [...new Set((cats || []).map(c => c.nome))].filter(n => !/^qa robo/i.test(n));
  if (nomesCat.length) {
    await raw.from('categorias').insert(nomesCat.map(nome => ({ nome, tenant_id: tenant.id })));
    resumo.categorias = nomesCat.length;
  }

  // 2) Catálogo: zerado e sem preço — é sugestão de cadastro, não estoque de mentira.
  if (importar_catalogo) {
    const { data: modelo } = await raw.from('produtos_modelo').select('nome, categoria, unidade');
    const linhas = (modelo || []).map(p => ({
      nome: p.nome, nome_search: normalizeSearch(p.nome), categoria: p.categoria, unidade: p.unidade,
      qtd: 0, custo: 0, minimo: 1, ativo: 1, tenant_id: tenant.id, updated_at: nowSP(),
    }));
    for (let i = 0; i < linhas.length; i += 500) {
      const { error } = await raw.from('produtos').insert(linhas.slice(i, i + 500));
      if (error) throw new Error('Erro ao importar o catálogo: ' + error.message);
    }
    resumo.produtos = linhas.length;
  }

  // 3) O dono, que administra os usuários dele daqui pra frente.
  // O nome de usuário é único na PLATAFORMA, não no restaurante: o login recebe só
  // usuário e senha, então dois "admin" em restaurantes diferentes deixariam o sistema
  // sem saber quem é quem — e o login falharia com "senha inválida", que manda o dono
  // procurar o problema no lugar errado. Melhor barrar aqui, com a mensagem certa.
  const usuario = sanitizeText(admin_usuario, 40).toLowerCase();
  const { data: jaExiste } = await raw.from('users').select('id').ilike('username', usuario).maybeSingle();
  if (jaExiste) {
    // o rollback fica por conta do catch em abrirRestaurante — um lugar só, sem duplicar
    throw new Error(`O usuário "${usuario}" já existe na plataforma. Escolha outro (ex: ${slug}.admin).`);
  }
  const { data: u, error: errU } = await raw.from('users').insert({
    tenant_id: tenant.id, username: usuario, password_hash: hashPassword(String(admin_senha)),
    nome: sanitizeText(admin_nome || nome, 80), role: 'admin', active: 1,
  }).select('id, username, nome, role').single();
  if (errU) throw new Error('Restaurante criado, mas falhou ao criar o usuário: ' + errU.message);
  resumo.usuario = u;
  return resumo;
}

// Confere disponibilidade ANTES de o cadastro ser enviado — evita o cliente preencher
// tudo e só então descobrir que o identificador já existe.
app.get('/api/plataforma/disponivel', auth, requireSuperadmin, async (req, res) => {
  const slug = sanitizeText(req.query?.slug || '', 60).toLowerCase();
  const usuario = sanitizeText(req.query?.usuario || '', 40).toLowerCase();
  const out = {};
  if (slug) {
    const { data } = await supabaseRaw.from('tenants').select('id').eq('slug', slug).maybeSingle();
    out.slug = { livre: !data && !RESERVADOS.has(slug) };
  }
  if (usuario) {
    const { data } = await supabaseRaw.from('users').select('id').ilike('username', usuario).maybeSingle();
    out.usuario = { livre: !data && !RESERVADOS.has(usuario) };
  }
  res.json(out);
});

app.post('/api/plataforma/restaurantes', auth, requireSuperadmin, async (req, res) => {
  try {
    const b = req.body || {};
    const { erros, limpos } = validarCadastroRestaurante(b);
    if (erros.length) return res.status(400).json({ erro: erros[0].erro, erros });
    // Passa os valores JÁ NORMALIZADOS adiante. Sem isso, valido um valor ("Cantina"
    // vira "cantina" na checagem) e gravo outro caminho de normalização — divergência
    // silenciosa que só apareceria quando dois cadastros colidissem.
    const r = await abrirRestaurante({
      ...b, nome: limpos.nome, slug: limpos.slug, cnpj: limpos.cnpj || null,
      plano: limpos.plano, admin_usuario: limpos.usuario, admin_senha: limpos.senha,
    });
    res.json({
      ok: true, restaurante: { id: r.tenant.id, nome: r.tenant.nome, slug: r.tenant.slug, plano: r.tenant.plano },
      preparado: { categorias: r.categorias, produtos: r.produtos }, admin: r.usuario,
    });
  } catch (e) {
    console.error('abrir restaurante:', e.message);
    res.status(400).json({ erro: e.message });
  }
});

// ── O QUE O DONO DO RESTAURANTE PODE CONFIGURAR ─────────────────────────────
// Parâmetro é diferente de estrutura. Taxa de maquininha e dados da empresa são
// DELE — cada restaurante negocia a taxa que consegue, e usar a taxa de outro faria
// o custo sair errado. O que ele não mexe é o que muda a forma de medir: plano de
// contas, categorias e as regras dos índices continuam iguais pra todo mundo, que é
// justamente o que permite comparar um restaurante com outro.
app.get('/api/restaurante', auth, async (req, res) => {
  if (!MULTI_TENANT) return res.json({ multi_tenant: false });
  const { data } = await supabaseRaw.from('tenants').select('id, nome, slug, cnpj, telefone, endereco, plano, config').eq('id', req.tenantId).maybeSingle();
  if (!data) return res.status(404).json({ erro: 'Restaurante não encontrado.' });
  res.json({ multi_tenant: true, restaurante: data, pode_editar: ['admin', 'superadmin'].includes(req.user.role) });
});

app.put('/api/restaurante', auth, requireRole('admin', 'superadmin'), async (req, res) => {
  if (!MULTI_TENANT) return res.status(400).json({ erro: 'Indisponível.' });
  try {
    const b = req.body || {};
    const { data: atual } = await supabaseRaw.from('tenants').select('config').eq('id', req.tenantId).maybeSingle();
    const cfg = { ...(atual?.config || {}) };

    if (b.taxas && typeof b.taxas === 'object') {
      const taxas = { ...(cfg.taxas || {}) };
      for (const k of ['credito', 'debito', 'voucher', 'pix', 'cartao']) {
        if (b.taxas[k] === undefined || b.taxas[k] === '') continue;
        const v = Number(String(b.taxas[k]).replace(',', '.'));
        // Taxa fora de 0–20% é digitação errada, não negociação — barra antes de virar
        // custo errado em todo fechamento do mês.
        if (!Number.isFinite(v) || v < 0 || v > 20) {
          return res.status(400).json({ erro: `Taxa de ${k} inválida: use um número entre 0 e 20.` });
        }
        taxas[k] = Number(v.toFixed(2));
      }
      cfg.taxas = taxas;
    }
    if (b.alerta_caixa && typeof b.alerta_caixa === 'object') {
      cfg.alerta_caixa = { ...(cfg.alerta_caixa || {}), ...b.alerta_caixa };
    }

    const patch = { config: cfg };
    for (const campo of ['nome', 'cnpj', 'telefone', 'endereco']) {
      if (typeof b[campo] === 'string') patch[campo] = sanitizeText(b[campo], 120);
    }
    const { error } = await supabaseRaw.from('tenants').update(patch).eq('id', req.tenantId);
    if (error) throw error;
    await audit('restaurante_config', { campos: Object.keys(patch) }, req.user, getClientIp(req));
    res.json({ ok: true, config: cfg });
  } catch (e) {
    console.error('config restaurante:', e.message);
    res.status(500).json({ erro: 'Erro ao salvar as configurações.' });
  }
});

// Painel da plataforma — só o superadmin enxerga. Mostra a SAÚDE de cada cliente,
// não o financeiro dele: o que importa pra operar a plataforma é saber quem está
// lançando e quem parou. Cliente que deixa de lançar cancela em dois meses, e isso
// dá pra ver antes de acontecer.
app.get('/api/plataforma/restaurantes', auth, requireSuperadmin, async (req, res) => {
  try {
    const { data: tenants } = await supabaseRaw.from('tenants').select('*').order('id');
    const mes = dateSP().slice(0, 7);
    const inicioMes = `${mes}-01`;
    const hoje = dateSP();
    const diaDoMes = Number(hoje.slice(8, 10));

    const lista = [];
    for (const t of (tenants || [])) {
      const [fech, usuarios, prods] = await Promise.all([
        supabaseRaw.from('fechamentos_diarios').select('data').eq('tenant_id', t.id).gte('data', inicioMes).lte('data', hoje),
        supabaseRaw.from('users').select('id', { count: 'exact', head: true }).eq('tenant_id', t.id).eq('active', 1),
        supabaseRaw.from('produtos').select('id', { count: 'exact', head: true }).eq('tenant_id', t.id).eq('ativo', 1),
      ]);
      const diasLancados = (fech.data || []).length;
      // A métrica que antecipa cancelamento: abaixo de 80% dos dias, o cliente está
      // perdendo o hábito — e sem lançamento o sistema mostra número errado e ele culpa a ferramenta.
      const aderencia = diaDoMes > 0 ? Math.round((diasLancados / diaDoMes) * 100) : 0;
      lista.push({
        id: t.id, nome: t.nome, slug: t.slug, plano: t.plano, ativo: t.ativo,
        criado_em: t.criado_em,
        usuarios: usuarios.count || 0,
        produtos: prods.count || 0,
        dias_lancados: diasLancados,
        dias_do_mes: diaDoMes,
        aderencia,
        saude: aderencia >= 80 ? 'ok' : (aderencia >= 50 ? 'atencao' : 'risco'),
      });
    }
    res.json({ restaurantes: lista, mes });
  } catch (e) {
    console.error('painel plataforma:', e.message);
    res.status(500).json({ erro: 'Erro ao carregar os restaurantes.' });
  }
});

app.post('/api/plataforma/restaurantes/:id/status', auth, requireSuperadmin, async (req, res) => {
  const ativo = req.body?.ativo !== false;
  const { error } = await supabaseRaw.from('tenants')
    .update({ ativo, suspenso_em: ativo ? null : nowSP() }).eq('id', req.params.id);
  if (error) return res.status(500).json({ erro: 'Erro ao mudar o status.' });
  res.json({ ok: true, ativo });
});

// COMPARADOR DE PERÍODOS — a aba Relatórios deixa de repetir o que a Planilha já mostra
// (Rubens, 01/08: "não é uma duplicidade de informação?"). Era: os mesmos números com
// período flexível. Agora responde a pergunta que nenhuma outra tela responde:
// "este período foi melhor ou pior que o anterior, e em quê?".
function variacao(atual, anterior) {
  const a = Number(atual || 0), b = Number(anterior || 0);
  if (!b) return { abs: Number(a.toFixed(2)), pct: null };  // sem base, % não significa nada
  return { abs: Number((a - b).toFixed(2)), pct: Number((((a - b) / Math.abs(b)) * 100).toFixed(1)) };
}

// Período anterior do mesmo tamanho, imediatamente antes — é a comparação que faz sentido
// por padrão (7 dias contra os 7 anteriores, um mês contra o mês anterior).
function periodoAnterior(inicio, fim) {
  const d1 = new Date(inicio + 'T12:00:00Z'), d2 = new Date(fim + 'T12:00:00Z');
  const dias = Math.round((d2 - d1) / 86400000) + 1;
  const fimAnt = new Date(d1.getTime() - 86400000);
  const iniAnt = new Date(fimAnt.getTime() - (dias - 1) * 86400000);
  const iso = d => d.toISOString().slice(0, 10);
  return { inicio: iso(iniAnt), fim: iso(fimAnt) };
}

app.get('/api/comparar', auth, requirePerm('planilha'), async (req, res) => {
  try {
    const aIni = validarDataISO(req.query?.inicio || dateAgoDias(6));
    const aFim = validarDataISO(req.query?.fim || dateSP());
    const ant = periodoAnterior(aIni, aFim);
    const bIni = validarDataISO(req.query?.base_inicio || ant.inicio);
    const bFim = validarDataISO(req.query?.base_fim || ant.fim);

    const [a, b] = await Promise.all([
      montarRelatorioPeriodo(aIni, aFim),
      montarRelatorioPeriodo(bIni, bFim),
    ]);

    // Em cada linha: se "subir" é bom ou ruim. Sem isso a tela pinta de verde um
    // consumo que disparou — que é justamente o que o dono precisa enxergar.
    const LINHAS = [
      { chave: 'vendas', rotulo: 'Vendas', tipo: 'dinheiro', subir: 'bom' },
      { chave: 'pratos_vendidos', rotulo: 'Pratos vendidos', tipo: 'numero', subir: 'bom' },
      { chave: 'ticket_medio', rotulo: 'Ticket médio', tipo: 'dinheiro', subir: 'bom' },
      { chave: 'consumo_estoque', rotulo: 'Consumo de estoque', tipo: 'dinheiro', subir: 'ruim' },
      { chave: 'perdas', rotulo: 'Perdas', tipo: 'dinheiro', subir: 'ruim' },
      { chave: 'despesas_caixa', rotulo: 'Despesas do caixa', tipo: 'dinheiro', subir: 'ruim' },
      { chave: 'compras_estoque', rotulo: 'Compras de estoque', tipo: 'dinheiro', subir: 'neutro' },
      { chave: 'contas_pagas', rotulo: 'Contas pagas', tipo: 'dinheiro', subir: 'neutro' },
      { chave: 'cortes', rotulo: 'Cortes', tipo: 'dinheiro', subir: 'ruim' },
      { chave: 'resultado_operacional', rotulo: 'Resultado operacional', tipo: 'dinheiro', subir: 'bom' },
      { chave: 'dias_com_caixa', rotulo: 'Dias com caixa lançado', tipo: 'numero', subir: 'bom' },
    ];

    const linhas = LINHAS.map(l => {
      const atual = a.totais[l.chave], anterior = b.totais[l.chave];
      const v = variacao(atual, anterior);
      const melhorou = l.subir === 'neutro' || v.abs === 0 ? null
        : (l.subir === 'bom' ? v.abs > 0 : v.abs < 0);
      return { ...l, atual: atual ?? null, anterior: anterior ?? null, ...v, melhorou };
    });

    // Consumo sobre vendas é o índice que mais denuncia problema: se a venda caiu e o
    // consumo não, alguma coisa está saindo sem ser vendida.
    const pctA = pct(a.totais.consumo_estoque, a.totais.vendas);
    const pctB = pct(b.totais.consumo_estoque, b.totais.vendas);
    linhas.push({
      chave: 'consumo_sobre_vendas', rotulo: 'Consumo sobre vendas', tipo: 'pct', subir: 'ruim',
      atual: pctA, anterior: pctB,
      abs: (pctA !== null && pctB !== null) ? Number((pctA - pctB).toFixed(1)) : null,
      pct: null, melhorou: (pctA !== null && pctB !== null) ? pctA < pctB : null,
    });

    res.json({
      atual: { inicio: aIni, fim: aFim, dias: a.totais.dias_periodo, label: `${dataBR(aIni)} a ${dataBR(aFim)}` },
      base: { inicio: bIni, fim: bFim, dias: b.totais.dias_periodo, label: `${dataBR(bIni)} a ${dataBR(bFim)}` },
      linhas,
      alerta: (() => {
        const vend = linhas.find(l => l.chave === 'vendas');
        const cons = linhas.find(l => l.chave === 'consumo_estoque');
        if (vend?.pct !== null && cons?.pct !== null && vend?.pct < -5 && cons?.pct > 5)
          return 'A venda caiu e o consumo de estoque subiu no mesmo período. Vale conferir perda, desperdício ou saída sem venda.';
        const cs = linhas.find(l => l.chave === 'consumo_sobre_vendas');
        if (cs?.abs !== null && cs?.abs > 5)
          return `O consumo passou de ${cs.anterior}% para ${cs.atual}% das vendas. Cada ponto aí sai direto do seu resultado.`;
        return null;
      })(),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao comparar os períodos.' });
  }
});

app.get('/api/indices', auth, requirePerm('planilha'), async (req, res) => {
  try {
    res.json(await montarIndices(req.query?.mes));
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao calcular os índices.' });
  }
});

app.get('/api/relatorios/periodo', auth, requirePerm('planilha'), async (req, res) => {
  try {
    const relatorio = await montarRelatorioPeriodo(req.query?.data_inicio, req.query?.data_fim);
    res.json(relatorio);
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao carregar relatório do período.' });
  }
});

app.get('/api/pagamentos', auth, requirePerm('contas'), async (req, res) => {
  try {
    const d = await montarPagamentosMensal(req.query?.mes);
    res.json(d);
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao carregar pagamentos.' });
  }
});

app.get('/api/pagamentos/categorias', auth, requirePerm('contas'), async (req, res) => {
  res.json({ grupos: CONTAS_PLANILHA_PAGAMENTOS });
});

app.post('/api/pagamentos', auth, requirePerm('contas'), async (req, res) => {
  try {
    const p = normalizarPagamentoInput(req.body || {});
    if (p.valor_bruto <= 0 && p.valor_liquido <= 0) return res.status(400).json({ erro: 'Informe o valor do pagamento.' });
    const { error } = await supabase.from('pagamentos_comprovantes').insert({
      ...p,
      responsavel: req.user.nome || req.user.username,
      updated_at: nowSP(),
    });
    if (error) {
      if (isTabelaPagamentosMissing(error)) return res.status(500).json({ erro: 'Tabela pagamentos_comprovantes precisa ser criada. Rode o arquivo SUPABASE_PAGAMENTOS_COMPROVANTES.sql no Supabase.' });
      throw error;
    }
    await audit('pagamento_salvar', { data: p.data, grupo: p.grupo, categoria: p.categoria, forma: p.forma, valor_bruto: p.valor_bruto }, req.user, getClientIp(req));
    res.json(await montarPagamentosMensal(p.data.slice(0, 7)));
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao salvar pagamento.' });
  }
});

app.put('/api/pagamentos/:id', auth, requirePerm('contas'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ erro: 'Pagamento inválido.' });
    const p = normalizarPagamentoInput(req.body || {});
    if (p.valor_bruto <= 0 && p.valor_liquido <= 0) return res.status(400).json({ erro: 'Informe o valor do pagamento.' });
    const { error } = await supabase.from('pagamentos_comprovantes').update({
      ...p,
      responsavel: req.user.nome || req.user.username,
      updated_at: nowSP(),
    }).eq('id', id);
    if (error) throw error;
    await audit('pagamento_editar', { id, data: p.data, grupo: p.grupo, categoria: p.categoria, forma: p.forma, valor_bruto: p.valor_bruto }, req.user, getClientIp(req));
    res.json(await montarPagamentosMensal(p.data.slice(0, 7)));
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao editar pagamento.' });
  }
});

app.delete('/api/pagamentos/:id', auth, requirePerm('contas'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ erro: 'Pagamento inválido.' });
    const { data: old } = await supabase.from('pagamentos_comprovantes').select('data').eq('id', id).maybeSingle();
    const { error } = await supabase.from('pagamentos_comprovantes').delete().eq('id', id);
    if (error) throw error;
    await audit('pagamento_excluir', { id }, req.user, getClientIp(req));
    res.json(await montarPagamentosMensal(String(old?.data || dateSP()).slice(0, 7)));
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao excluir pagamento.' });
  }
});

app.post('/api/pagamentos/ler-comprovante', auth, requirePerm('contas'), async (req, res) => {
  try {
    const texto = sanitizeLongText(req.body?.texto || '', 5000);
    const imagens = (Array.isArray(req.body?.imagens) ? req.body.imagens : (req.body?.imagem ? [req.body.imagem] : []))
      .filter(Boolean)
      .slice(0, 4);
    if (!texto && !imagens.length) return res.status(400).json({ erro: 'Envie o texto ou a imagem do comprovante.' });
    const pagamento = imagens.length
      ? await lerComprovantePagamentoComIA({ imagens, mediaType: req.body?.mediaType || 'image/jpeg', texto, dataPadrao: req.body?.data }, req.user)
      : extrairPagamentoTextoLocal(texto, req.body?.data);
    if (pagamento.valor_bruto <= 0 && pagamento.valor_liquido <= 0) {
      return res.status(422).json({ erro: 'Não encontrei valor no comprovante. Confira o texto/imagem.' });
    }
    res.json({ pagamento });
  } catch(e) {
    console.error(e);
    res.status(e.status || 500).json({ erro: e.message || 'Erro ao ler comprovante.' });
  }
});

// ==================== CATÁLOGO DE PRATOS (com foto) ====================
function isTabelaPratosCardapioMissing(error) {
  const msg = String(error?.message || error?.details || '');
  return error && (
    error.code === '42P01' ||
    error.code === 'PGRST205' ||
    /pratos_cardapio|schema cache|does not exist|relation|column/i.test(msg)
  );
}

app.get('/api/pratos-cardapio', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const q = sanitizeText(req.query?.q || '', 100);
    let query = supabase.from('pratos_cardapio').select('*').eq('ativo', 1).order('nome');
    if (q) query = query.ilike('nome', `%${q}%`);
    const { data, error } = await query.limit(300);
    if (error) {
      if (isTabelaPratosCardapioMissing(error)) return res.json({ pratos: [], configuracao_pendente: true });
      throw error;
    }
    res.json({ pratos: data || [] });
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao carregar catálogo de pratos.' });
  }
});

app.post('/api/pratos-cardapio/foto', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const imagemB64 = req.body?.imagem;
    if (!imagemB64) return res.status(400).json({ erro: 'Envie a imagem.' });
    const mediaType = sanitizeText(req.body?.mediaType || 'image/jpeg', 40);
    const ext = mediaType.includes('png') ? 'png' : (mediaType.includes('webp') ? 'webp' : 'jpg');
    const nomeArquivo = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
    const buffer = Buffer.from(imagemB64, 'base64');
    if (buffer.length > 6 * 1024 * 1024) return res.status(413).json({ erro: 'Imagem muito grande (máx. 6MB).' });
    const { error } = await supabase.storage.from('pratos-fotos').upload(nomeArquivo, buffer, { contentType: mediaType, upsert: false });
    if (error) throw error;
    const { data: pub } = supabase.storage.from('pratos-fotos').getPublicUrl(nomeArquivo);
    res.json({ foto_url: pub.publicUrl });
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao enviar foto.' });
  }
});

app.post('/api/pratos-cardapio', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const nome = sanitizeText(req.body?.nome || '', 120);
    if (!nome) return res.status(400).json({ erro: 'Informe o nome do prato.' });
    const fotoUrl = sanitizeText(req.body?.foto_url || '', 300);
    const categoria = sanitizeText(req.body?.categoria || '', 60);
    const produtoId = Number.isInteger(Number(req.body?.produto_id)) && Number(req.body.produto_id) > 0 ? Number(req.body.produto_id) : null;
    const { data, error } = await supabase.from('pratos_cardapio').insert({
      nome, foto_url: fotoUrl, categoria, produto_id: produtoId, ativo: 1,
    }).select('*').single();
    if (error) {
      if (isTabelaPratosCardapioMissing(error)) return res.status(500).json({ erro: 'Tabela pratos_cardapio precisa ser criada. Rode o arquivo SUPABASE_PRATOS_CARDAPIO.sql no Supabase.' });
      throw error;
    }
    await audit('prato_cardapio_criar', { id: data.id, nome }, req.user, getClientIp(req));
    res.json(data);
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao salvar prato.' });
  }
});

app.put('/api/pratos-cardapio/:id', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ erro: 'Prato inválido.' });
    const nome = sanitizeText(req.body?.nome || '', 120);
    if (!nome) return res.status(400).json({ erro: 'Informe o nome do prato.' });
    const fotoUrl = sanitizeText(req.body?.foto_url || '', 300);
    const categoria = sanitizeText(req.body?.categoria || '', 60);
    const produtoId = Number.isInteger(Number(req.body?.produto_id)) && Number(req.body.produto_id) > 0 ? Number(req.body.produto_id) : null;
    const { error } = await supabase.from('pratos_cardapio').update({ nome, foto_url: fotoUrl, categoria, produto_id: produtoId }).eq('id', id);
    if (error) throw error;
    await audit('prato_cardapio_editar', { id, nome }, req.user, getClientIp(req));
    res.json({ ok: true });
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao editar prato.' });
  }
});

app.delete('/api/pratos-cardapio/:id', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ erro: 'Prato inválido.' });
    const { error } = await supabase.from('pratos_cardapio').update({ ativo: 0 }).eq('id', id);
    if (error) throw error;
    await audit('prato_cardapio_excluir', { id }, req.user, getClientIp(req));
    res.json({ ok: true });
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao excluir prato.' });
  }
});

// ==================== BANCO DE CARDÁPIOS SALVOS ====================
// Cada "Salvar" pede um nome e cria um registro novo (ex: "Terça Mineira", "Quarta do
// Rock") — nada se sobrescreve/apaga sozinho, formando uma biblioteca reutilizável.
function isTabelaCardapiosSalvosMissing(error) {
  const msg = String(error?.message || error?.details || '');
  return error && (
    error.code === '42P01' ||
    error.code === 'PGRST205' ||
    /cardapios_salvos|schema cache|does not exist|relation|column/i.test(msg)
  );
}

function normalizarSecaoCardapio(value, max = 20) {
  const rows = arrayFromMaybeJson(value);
  return rows.slice(0, max).map(row => {
    const pratoId = Number.isInteger(Number(row?.prato_id)) && Number(row?.prato_id) > 0 ? Number(row.prato_id) : null;
    const cubas = parseNonNegativeInteger(row?.cubas ?? 1) || 1;
    const obs = sanitizeText(row?.obs || '', 160);
    return { prato_id: pratoId, cubas, obs };
  }).filter(row => row.prato_id);
}

async function comDetalhesPratos(base) {
  const secoes = ['buffet_principal', 'rechaud_redondo', 'rechaud_retangular'];
  const idsPratos = [...new Set(
    secoes.flatMap(s => arrayFromMaybeJson(base[s]).map(item => item?.prato_id).filter(Boolean))
  )];
  let pratosPorId = {};
  if (idsPratos.length) {
    const { data: pratos } = await supabase.from('pratos_cardapio').select('id,nome,foto_url,produto_id').in('id', idsPratos);
    for (const p of (pratos || [])) pratosPorId[p.id] = p;
  }
  const idsProdutos = [...new Set(Object.values(pratosPorId).map(p => p.produto_id).filter(Boolean))];
  let estoquePorId = {};
  if (idsProdutos.length) {
    const { data: produtosLigados } = await supabase.from('produtos').select('id,qtd,unidade,ativo,minimo').in('id', idsProdutos);
    for (const p of (produtosLigados || [])) estoquePorId[p.id] = p;
  }
  const comDetalhes = (secaoRows) => arrayFromMaybeJson(secaoRows).map(item => {
    const prato = item?.prato_id ? pratosPorId[item.prato_id] : null;
    const prod = prato?.produto_id ? estoquePorId[prato.produto_id] : null;
    return {
      ...item,
      nome: prato ? prato.nome : '(prato removido do catálogo)',
      foto_url: prato ? prato.foto_url : '',
      prato_removido: !!(item?.prato_id && !prato),
      estoque_atual: prod ? Number(prod.qtd) : null,
      estoque_unidade: prod ? prod.unidade : null,
      estoque_baixo: prod ? (Number(prod.qtd) <= Number(prod.minimo || 0) && Number(prod.minimo || 0) > 0) : false,
      produto_arquivado: prod ? !(prod.ativo === 1 || prod.ativo === null) : false,
    };
  });
  return {
    id: base.id,
    nome: base.nome,
    buffet_principal: comDetalhes(base.buffet_principal),
    rechaud_redondo: comDetalhes(base.rechaud_redondo),
    rechaud_retangular: comDetalhes(base.rechaud_retangular),
    responsavel: base.responsavel || '',
    updated_at: base.updated_at,
    created_at: base.created_at,
  };
}

app.get('/api/cardapios-salvos', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const q = sanitizeText(req.query?.q || '', 100);
    let query = supabase.from('cardapios_salvos').select('id,nome,responsavel,updated_at,created_at').eq('ativo', 1).order('updated_at', { ascending: false });
    if (q) query = query.ilike('nome', `%${q}%`);
    const { data, error } = await query.limit(200);
    if (error) {
      if (isTabelaCardapiosSalvosMissing(error)) return res.json({ cardapios: [], configuracao_pendente: true });
      throw error;
    }
    res.json({ cardapios: data || [] });
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao carregar cardápios salvos.' });
  }
});

app.get('/api/cardapios-salvos/:id', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ erro: 'Cardápio inválido.' });
    const { data, error } = await supabase.from('cardapios_salvos').select('*').eq('id', id).maybeSingle();
    if (error) {
      if (isTabelaCardapiosSalvosMissing(error)) return res.status(500).json({ erro: 'Tabela cardapios_salvos precisa ser criada. Rode o arquivo SUPABASE_CARDAPIOS_SALVOS.sql no Supabase.' });
      throw error;
    }
    if (!data) return res.status(404).json({ erro: 'Cardápio não encontrado.' });
    res.json(await comDetalhesPratos(data));
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao carregar cardápio.' });
  }
});

app.post('/api/cardapios-salvos', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const nome = sanitizeText(req.body?.nome || '', 120);
    if (!nome) return res.status(400).json({ erro: 'Dê um nome pro cardápio (ex: "Terça Mineira").' });
    const buffet_principal = normalizarSecaoCardapio(req.body?.buffet_principal, 20);
    const rechaud_redondo = normalizarSecaoCardapio(req.body?.rechaud_redondo, 10);
    const rechaud_retangular = normalizarSecaoCardapio(req.body?.rechaud_retangular, 10);

    const { data, error } = await supabase.from('cardapios_salvos').insert({
      nome,
      buffet_principal,
      rechaud_redondo,
      rechaud_retangular,
      responsavel: req.user.nome || req.user.username,
      ativo: 1,
      updated_at: nowSP(),
    }).select('*').single();
    if (error) {
      if (isTabelaCardapiosSalvosMissing(error)) {
        return res.status(500).json({ erro: 'Tabela cardapios_salvos precisa ser criada. Rode o arquivo SUPABASE_CARDAPIOS_SALVOS.sql no Supabase.' });
      }
      throw error;
    }
    await audit('cardapio_criar', { id: data.id, nome, itens: buffet_principal.length + rechaud_redondo.length + rechaud_retangular.length }, req.user, getClientIp(req));
    res.json(await comDetalhesPratos(data));
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao salvar cardápio.' });
  }
});

app.put('/api/cardapios-salvos/:id', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ erro: 'Cardápio inválido.' });
    const nome = sanitizeText(req.body?.nome || '', 120);
    if (!nome) return res.status(400).json({ erro: 'Dê um nome pro cardápio.' });
    const buffet_principal = normalizarSecaoCardapio(req.body?.buffet_principal, 20);
    const rechaud_redondo = normalizarSecaoCardapio(req.body?.rechaud_redondo, 10);
    const rechaud_retangular = normalizarSecaoCardapio(req.body?.rechaud_retangular, 10);

    const { data, error } = await supabase.from('cardapios_salvos').update({
      nome, buffet_principal, rechaud_redondo, rechaud_retangular,
      responsavel: req.user.nome || req.user.username,
      updated_at: nowSP(),
    }).eq('id', id).select('*').single();
    if (error) throw error;
    await audit('cardapio_atualizar', { id, nome }, req.user, getClientIp(req));
    res.json(await comDetalhesPratos(data));
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao atualizar cardápio.' });
  }
});

app.delete('/api/cardapios-salvos/:id', auth, requirePerm('cardapio'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ erro: 'Cardápio inválido.' });
    const { error } = await supabase.from('cardapios_salvos').update({ ativo: 0 }).eq('id', id);
    if (error) throw error;
    await audit('cardapio_excluir', { id }, req.user, getClientIp(req));
    res.json({ ok: true });
  } catch(e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao excluir cardápio.' });
  }
});

// ==================== EXPORTAR ====================
app.get('/api/exportar/:tipo', auth, async (req, res) => {
  const { tipo } = req.params;
  const permNecessaria = tipo === 'fechamentos' ? 'planilha' : (tipo === 'pagamentos' ? 'contas' : 'exportar');
  if (!(await usuarioTemPerm(req, permNecessaria))) {
    return res.status(403).json({ erro: 'Acesso não liberado para este recurso. Fale com o administrador.' });
  }
  let rows, headers, filename;
  let delimiter = ',';
  if (tipo === 'estoque') {
    // Mesmo filtro do relatório HTML/Estoque/Dashboard — sem isso, produto arquivado
    // (descontinuado) entrava no CSV misturado com o estoque de verdade.
    const { data } = await supabase.from('produtos').select('nome, categoria, unidade, qtd, minimo, custo').or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    headers = ['Produto','Categoria','Unidade','Qtd Atual','Mínimo','Custo Unit.','Valor Total','Status'];
    rows = (data || []).map(r => {
      let st = Number(r.qtd) === 0 ? 'ZERADO' : Number(r.qtd) <= Number(r.minimo) * 0.5 ? 'CRITICO' : Number(r.qtd) < Number(r.minimo) ? 'ATENCAO' : 'OK';
      return [r.nome, r.categoria, r.unidade, r.qtd, r.minimo, r.custo, (Number(r.qtd) * Number(r.custo)).toFixed(2), st];
    });
    filename = 'estoque_toca_coelho.csv';
  } else if (tipo === 'movimentacoes') {
    const data = await fetchTodas(() => supabase.from('movimentacoes').select('*').order('id', { ascending: false }));
    headers = ['Data/Hora','Produto','Categoria','Tipo','Qtd','Unidade','Custo','Valor','Motivo','Responsável','Obs'];
    rows = (data || []).map(r => [r.created_at, r.produto_nome, r.categoria, r.tipo, r.qtd, r.unidade, r.custo, r.valor, r.motivo, r.responsavel, r.obs]);
    filename = 'movimentacoes_toca_coelho.csv';
  } else if (tipo === 'compras') {
    // Idem: produto arquivado não pode entrar na lista de compras (senão manda comprar
    // algo que o restaurante nem usa mais).
    const { data } = await supabase.from('produtos').select('nome, categoria, unidade, qtd, minimo').or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    headers = ['Produto','Categoria','Unidade','Qtd Atual','Mínimo','Sugerido Comprar'];
    // minimo > 0 exigido — sem isso, produto sem mínimo definido (comum: 80 itens sem
    // movimento) entrava aqui sugerindo "comprar 0" (mesma inconsistência do relatório HTML;
    // o comando de WhatsApp já exigia minimo>0 corretamente, aqui não exigia).
    rows = (data || []).filter(r => Number(r.minimo) > 0 && Number(r.qtd) <= Number(r.minimo) * 0.5)
      .map(r => [r.nome, r.categoria, r.unidade, r.qtd, r.minimo, Math.max(0, Number(r.minimo) * 2 - Number(r.qtd)).toFixed(3)]);
    filename = 'lista_compras_toca_coelho.csv';
  } else if (tipo === 'fechamentos') {
    const planilha = await montarPlanilhaMensal(req.query?.mes);
    // v58: colunas por TIPO de pagamento (v55) — antes exportava Stone/PagBank, chaves
    // que não existem mais (saíam 0,00). + Lixo do buffet (anotação em gramas).
    headers = ['Data','Dia','Status','Pratos','Vendas','Dinheiro','Crédito','Débito','Voucher','Pix','Cartão (maq.)','Ifood/Entrega','Outros','Cortes','Despesas','Compras Estoque','Consumo Estoque','Perdas','Resultado','Caixa','Lixo Buffet (g)','Mov. Estoque','Responsável','Observação'];
    rows = planilha.dias.map(d => [
      d.data_br,
      d.dia_semana,
      d.status,
      d.pratos_vendidos,
      d.vendas.toFixed(2),
      (d.formas?.dinheiro?.valor || 0).toFixed(2),
      (d.formas?.credito?.valor || 0).toFixed(2),
      (d.formas?.debito?.valor || 0).toFixed(2),
      (d.formas?.voucher?.valor || 0).toFixed(2),
      (d.formas?.pix?.valor || 0).toFixed(2),
      (d.formas?.cartao?.valor || 0).toFixed(2),
      (d.formas?.ifood?.valor || 0).toFixed(2),
      (d.formas?.outros?.valor || 0).toFixed(2),
      d.total_cortes.toFixed(2),
      d.despesas.toFixed(2),
      d.compras_estoque.toFixed(2),
      d.consumo_estoque.toFixed(2),
      d.perdas.toFixed(2),
      d.resultado_dia_estimado.toFixed(2),
      d.fluxo_caixa.toFixed(2),
      d.lixo_buffet_g != null ? d.lixo_buffet_g : '',
      d.movimentos_total,
      d.responsavel,
      d.observacao,
    ]);
    filename = `fechamento_mensal_${planilha.mes}.csv`;
  } else if (tipo === 'pagamentos') {
    const d = await montarPagamentosMensal(req.query?.mes);
    headers = null;
    rows = montarRowsExportPagamentos(d);
    filename = `contas_pagas_${d.mes}.csv`;
    delimiter = ';';
  } else return res.status(400).json({ erro: 'Tipo inválido' });
  await audit('exportar', { tipo }, req.user, getClientIp(req));
  const allRows = headers ? [headers, ...rows] : rows;
  const csv = allRows.map(r => r.map(c => `"${String(c ?? '').replace(/"/g, '""')}"`).join(delimiter)).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send('﻿' + csv);
});

// ==================== RELATÓRIOS HTML (imprimíveis / PDF) ====================
function escHtml(s) { return String(s ?? '').replace(/[&<>"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c])); }
const STATUS_INFO = {
  ZERADO:  { cor: '#ef4444', bg: '#fee2e2', label: 'Zerado' },
  CRITICO: { cor: '#f97316', bg: '#ffedd5', label: 'Crítico' },
  ATENCAO: { cor: '#ca8a04', bg: '#fef9c3', label: 'Atenção' },
  OK:      { cor: '#16a34a', bg: '#dcfce7', label: 'OK' },
};
function statusDe(qtd, minimo) {
  const q = Number(qtd), m = Number(minimo);
  return q === 0 ? 'ZERADO' : q <= m * 0.5 ? 'CRITICO' : q < m ? 'ATENCAO' : 'OK';
}
const CAT_CORES = ['#7c3aed','#db2777','#ea580c','#0891b2','#16a34a','#2563eb','#b45309','#be123c','#4f46e5','#0d9488'];
function corCategoria(nome) { let h = 0; for (const c of String(nome||'')) h = (h * 31 + c.charCodeAt(0)) % 997; return CAT_CORES[h % CAT_CORES.length]; }
function fmtBRL(n) { return 'R$ ' + Number(n || 0).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
function fmtQtd(n) { const x = Number(n || 0); return (x % 1 === 0 ? x.toString() : x.toFixed(3).replace(/\.?0+$/, '')); }

function paginaRelatorio(titulo, subtitulo, corpo) {
  const dataBR = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', dateStyle: 'short', timeStyle: 'short' });
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escHtml(titulo)} — Toca do Coelho</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif; margin: 0; background: #f1f5f9; color: #0f172a; }
  .wrap { max-width: 920px; margin: 0 auto; padding: 18px; }
  .head { background: linear-gradient(135deg,#7c3aed,#db2777); color: #fff; border-radius: 16px; padding: 20px 22px; margin-bottom: 16px; }
  .head h1 { margin: 0; font-size: 22px; }
  .head .sub { opacity: .92; font-size: 13px; margin-top: 4px; }
  .head .meta { opacity: .85; font-size: 12px; margin-top: 8px; }
  .barra { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px; }
  .chip { background:#fff; border-radius:10px; padding:8px 12px; font-size:12px; font-weight:600; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .chip b { font-size:15px; display:block; }
  .cat { background:#fff; border-radius:14px; overflow:hidden; margin-bottom:14px; box-shadow:0 1px 4px rgba(0,0,0,.07); }
  .cat-h { color:#fff; padding:10px 16px; font-weight:700; font-size:14px; display:flex; justify-content:space-between; align-items:center; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:9px 16px; font-size:13px; border-bottom:1px solid #f1f5f9; }
  th { font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#64748b; background:#f8fafc; }
  td.num, th.num { text-align:right; font-variant-numeric: tabular-nums; }
  tr:last-child td { border-bottom:none; }
  .badge { display:inline-block; padding:2px 9px; border-radius:20px; font-size:11px; font-weight:700; }
  .sub-row td { background:#fafafa; font-weight:700; font-size:12px; }
  .check { width:16px; height:16px; border:2px solid #94a3b8; border-radius:4px; display:inline-block; }
  .foot { text-align:center; color:#94a3b8; font-size:11px; margin:20px 0; }
  .print-btn { position:sticky; top:10px; float:right; background:#0f172a; color:#fff; border:none; padding:10px 16px; border-radius:10px; font-weight:700; cursor:pointer; font-size:13px; box-shadow:0 2px 8px rgba(0,0,0,.2); }
  @media print { body { background:#fff; } .print-btn { display:none; } .wrap { max-width:none; padding:0; } .cat, .head { box-shadow:none; } .cat { break-inside: avoid; } }
</style></head>
<body><div class="wrap">
  <button class="print-btn" onclick="window.print()">🖨️ Imprimir / Salvar PDF</button>
  <div class="head"><h1>🐰 ${escHtml(titulo)}</h1><div class="sub">${escHtml(subtitulo)}</div><div class="meta">Toca do Coelho · São Gonçalo/RJ · gerado em ${dataBR}</div></div>
  ${corpo}
  <div class="foot">Toca do Coelho — relatório gerado pelo app de estoque</div>
</div></body></html>`;
}

app.get('/api/relatorio/:tipo', auth, async (req, res) => {
  try {
    const tipo = req.params.tipo;
    const permNecessaria = tipo === 'fechamento' ? 'planilha' : 'exportar';
    if (!(await usuarioTemPerm(req, permNecessaria))) {
      return res.status(403).json({ erro: 'Acesso não liberado para este recurso. Fale com o administrador.' });
    }
    let html;

    if (tipo === 'estoque' || tipo === 'compras') {
      const ehCompras = tipo === 'compras';
      const { data } = await supabase.from('produtos').select('nome, categoria, unidade, qtd, minimo, custo')
        .or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
      let prods = data || [];
      // minimo > 0 exigido — mesma correção do CSV: sem mínimo definido não dá pra sugerir
      // quanto comprar (o comando de WhatsApp já filtrava certo; aqui não filtrava).
      if (ehCompras) prods = prods.filter(p => Number(p.minimo) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5);  // zerados + críticos
      const porCat = {};
      for (const p of prods) (porCat[p.categoria || 'Sem categoria'] = porCat[p.categoria || 'Sem categoria'] || []).push(p);
      const cont = { ZERADO: 0, CRITICO: 0, ATENCAO: 0, OK: 0 };
      let totalGeral = 0;
      let corpo = '';
      for (const cat of Object.keys(porCat).sort((a, b) => a.localeCompare(b))) {
        const itens = porCat[cat]; const cor = corCategoria(cat);
        let subtotal = 0; let linhas = '';
        for (const p of itens) {
          const st = statusDe(p.qtd, p.minimo); cont[st]++;
          const si = STATUS_INFO[st];
          if (ehCompras) {
            const sugerido = Math.max(0, Number(p.minimo) * 2 - Number(p.qtd));
            const custoEst = sugerido * Number(p.custo || 0); subtotal += custoEst;
            linhas += `<tr><td><span class="check"></span></td><td>${escHtml(p.nome)}</td>` +
              `<td class="num">${fmtQtd(p.qtd)} ${escHtml(p.unidade)}</td><td class="num">${fmtQtd(p.minimo)}</td>` +
              `<td class="num"><b>${fmtQtd(sugerido)} ${escHtml(p.unidade)}</b></td><td class="num">${fmtBRL(custoEst)}</td>` +
              `<td><span class="badge" style="background:${si.bg};color:${si.cor}">${si.label}</span></td></tr>`;
          } else {
            const valor = Number(p.qtd) * Number(p.custo || 0); subtotal += valor; totalGeral += valor;
            linhas += `<tr><td>${escHtml(p.nome)}</td><td class="num">${fmtQtd(p.qtd)} ${escHtml(p.unidade)}</td>` +
              `<td class="num">${fmtQtd(p.minimo)}</td><td class="num">${fmtBRL(p.custo)}</td><td class="num">${fmtBRL(valor)}</td>` +
              `<td><span class="badge" style="background:${si.bg};color:${si.cor}">${si.label}</span></td></tr>`;
          }
        }
        if (ehCompras) totalGeral += subtotal;
        const cabec = ehCompras
          ? `<tr><th></th><th>Produto</th><th class="num">Atual</th><th class="num">Mín</th><th class="num">Comprar</th><th class="num">Custo est.</th><th>Status</th></tr>`
          : `<tr><th>Produto</th><th class="num">Qtd</th><th class="num">Mín</th><th class="num">Custo un.</th><th class="num">Valor</th><th>Status</th></tr>`;
        const colspanLabel = ehCompras ? 5 : 4;
        corpo += `<div class="cat"><div class="cat-h" style="background:${cor}"><span>${escHtml(cat)}</span><span>${itens.length} ${itens.length === 1 ? 'item' : 'itens'}</span></div>` +
          `<table>${cabec}${linhas}` +
          `<tr class="sub-row"><td colspan="${colspanLabel}">Subtotal ${escHtml(cat)}</td><td class="num">${fmtBRL(subtotal)}</td><td></td></tr>` +
          `</table></div>`;
      }
      const chips = ehCompras
        ? `<div class="chip" style="color:#ef4444">Zerados<b>${cont.ZERADO}</b></div><div class="chip" style="color:#f97316">Críticos<b>${cont.CRITICO}</b></div><div class="chip">Itens a comprar<b>${prods.length}</b></div><div class="chip" style="color:#16a34a">Custo estimado<b>${fmtBRL(totalGeral)}</b></div>`
        : `<div class="chip" style="color:#ef4444">Zerados<b>${cont.ZERADO}</b></div><div class="chip" style="color:#f97316">Críticos<b>${cont.CRITICO}</b></div><div class="chip" style="color:#ca8a04">Atenção<b>${cont.ATENCAO}</b></div><div class="chip" style="color:#16a34a">OK<b>${cont.OK}</b></div><div class="chip">Valor total<b>${fmtBRL(totalGeral)}</b></div>`;
      const titulo = ehCompras ? 'Lista de Compras' : 'Posição do Estoque';
      const sub = ehCompras ? 'Itens zerados e críticos, organizados por categoria, com sugestão de reposição.' : 'Estoque atual por categoria, com valor e status.';
      html = paginaRelatorio(titulo, sub, `<div class="barra">${chips}</div>${corpo || '<div class="cat"><div style="padding:24px;text-align:center;color:#16a34a;font-weight:600">✅ Nada para comprar — tudo acima do mínimo!</div></div>'}`);

    } else if (tipo === 'movimentacoes') {
      const { data } = await supabase.from('movimentacoes').select('*').order('created_at', { ascending: false }).limit(400);
      const movs = data || [];
      const TIPO_COR = { 'Entrada': '#16a34a', 'Saída': '#ea580c', 'Perda': '#ef4444', 'Ajuste': '#2563eb' };
      const porDia = {};
      for (const m of movs) { const dia = String(m.created_at || '').slice(0, 10); (porDia[dia] = porDia[dia] || []).push(m); }
      let corpo = '';
      for (const dia of Object.keys(porDia).sort((a, b) => b.localeCompare(a))) {
        const itens = porDia[dia]; const diaBR = dia.split('-').reverse().join('/');
        let linhas = '';
        for (const m of itens) {
          const cor = TIPO_COR[m.tipo] || '#64748b';
          const hora = String(m.created_at || '').slice(11, 16);
          linhas += `<tr><td>${hora}</td><td>${escHtml(m.produto_nome)}</td>` +
            `<td><span class="badge" style="background:${cor}22;color:${cor}">${escHtml(m.tipo)}</span></td>` +
            `<td class="num">${fmtQtd(m.qtd)} ${escHtml(m.unidade)}</td><td class="num">${fmtBRL(m.valor)}</td>` +
            `<td>${escHtml(m.responsavel || '')}</td><td>${escHtml(m.motivo || '')}</td></tr>`;
        }
        corpo += `<div class="cat"><div class="cat-h" style="background:#334155"><span>📅 ${diaBR}</span><span>${itens.length} lançamentos</span></div>` +
          `<table><tr><th>Hora</th><th>Produto</th><th>Tipo</th><th class="num">Qtd</th><th class="num">Valor</th><th>Por</th><th>Motivo</th></tr>${linhas}</table></div>`;
      }
      html = paginaRelatorio('Movimentações', 'Últimos lançamentos agrupados por dia (até 400).', corpo || '<div class="cat"><div style="padding:24px;text-align:center;color:#64748b">Sem movimentações.</div></div>');

    } else if (tipo === 'fechamento') {
      // FECHAMENTO MENSAL OFICIAL (v59) — documento com cara de planilha de fluxo de
      // caixa: grade estilo Excel, cabeçalho escuro, zebra, linha de TOTAL, valores
      // pt-BR, A4 paisagem, botão "Salvar em PDF" (imprime direto). Pedido do Rubens
      // 19/07: "pdf oficial do mês, estilo planilha fluxo de caixa" (o CSV cru era
      // horrível de ver). Também remove as colunas mortas Stone/PagBank (resto do v55).
      const planilha = await montarPlanilhaMensal(req.query?.mes);
      const t = planilha.totais;
      const brl = (v) => 'R$ ' + Number(v || 0).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const neg = (v) => Number(v || 0) < 0 ? ' neg' : '';
      const F_KEYS = [['dinheiro','Dinheiro'],['credito','Crédito'],['debito','Débito'],['voucher','Voucher'],['pix','Pix'],['cartao','Cartão (maq.)']];
      // totais por tipo (a partir dos dias — mesmos baldes da Planilha)
      const somaFormas = {};
      for (const [k] of F_KEYS) somaFormas[k] = 0;
      let somaIfoodOutros = 0;
      for (const d of planilha.dias) {
        for (const [k] of F_KEYS) somaFormas[k] += Number(d.formas?.[k]?.valor || 0);
        somaIfoodOutros += Number(d.formas?.ifood?.valor || 0) + Number(d.formas?.outros?.valor || 0);
      }

      const diasComMov = planilha.dias.filter(d => d.tem_movimento);
      const linhasDia = diasComMov.map((d, i) => {
        const fimSemana = /s[áa]b|dom/i.test(d.dia_semana || '');
        return `<tr class="${i % 2 ? 'zebra' : ''}${fimSemana ? ' fds' : ''}">` +
          `<td class="c">${escHtml(d.data_br)}</td><td class="c">${escHtml(d.dia_semana || '')}</td>` +
          `<td class="num">${d.pratos_vendidos || '—'}</td><td class="num b">${brl(d.vendas)}</td>` +
          F_KEYS.map(([k]) => `<td class="num">${Number(d.formas?.[k]?.valor || 0) > 0 ? brl(d.formas[k].valor) : '—'}</td>`).join('') +
          `<td class="num">${Number(d.total_cortes) > 0 ? brl(d.total_cortes) : '—'}</td>` +
          `<td class="num">${Number(d.despesas) > 0 ? brl(d.despesas) : '—'}</td>` +
          `<td class="num">${Number(d.compras_estoque) > 0 ? brl(d.compras_estoque) : '—'}</td>` +
          `<td class="num">${Number(d.consumo_estoque) > 0 ? brl(d.consumo_estoque) : '—'}</td>` +
          `<td class="num">${Number(d.perdas) > 0 ? brl(d.perdas) : '—'}</td>` +
          `<td class="num b${neg(d.resultado_dia_estimado)}">${brl(d.resultado_dia_estimado)}</td>` +
          `<td class="num">${d.lixo_buffet_g != null && d.lixo_buffet_g > 0 ? d.lixo_buffet_g + 'g' : '—'}</td></tr>`;
      }).join('');

      const linhaTotal = `<tr class="total"><td class="c" colspan="2">TOTAL DO MÊS</td>` +
        `<td class="num">${t.pratos_vendidos}</td><td class="num">${brl(t.vendas)}</td>` +
        F_KEYS.map(([k]) => `<td class="num">${brl(somaFormas[k])}</td>`).join('') +
        `<td class="num">${brl(t.cortes)}</td><td class="num">${brl(t.despesas)}</td>` +
        `<td class="num">${brl(t.compras_estoque)}</td><td class="num">${brl(t.consumo_estoque)}</td>` +
        `<td class="num">${brl(t.perdas)}</td><td class="num${neg(t.resultado_dia_estimado)}">${brl(t.resultado_dia_estimado)}</td>` +
        `<td class="num">${t.lixo_buffet_g > 0 ? (t.lixo_buffet_g / 1000).toFixed(2).replace('.', ',') + 'kg' : '—'}</td></tr>`;

      const linhasFormas = planilha.formas_pagamento.map((f, i) =>
        `<tr class="${i % 2 ? 'zebra' : ''}"><td>${escHtml(f.forma)}</td><td class="num">${brl(f.valor)}</td>` +
        `<td class="num">${pct(f.valor, t.vendas) != null ? pct(f.valor, t.vendas).toFixed(1).replace('.', ',') + '%' : '—'}</td></tr>`).join('');

      const pendHtml = planilha.pendencias.sem_caixa.length
        ? `<div class="aviso">⚠️ ${planilha.pendencias.sem_caixa.length} dia(s) com estoque movimentado mas SEM caixa lançado: ${planilha.pendencias.sem_caixa.map(dataBR).join(', ')} — os totais acima não incluem as vendas desses dias.</div>`
        : '';

      const geradoEm = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
      html = `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<title>Fechamento Mensal ${escHtml(planilha.mes_label)} — Toca do Coelho</title>
<style>
  @page { size: A4 landscape; margin: 10mm; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: 'Segoe UI', Arial, sans-serif; color: #1a202c; background: #eef1f5; }
  .doc { max-width: 1180px; margin: 0 auto; background: #fff; padding: 26px 30px; }
  .no-print { text-align: center; padding: 14px; }
  .btn-pdf { background: #14532d; color: #fff; border: 0; border-radius: 8px; padding: 12px 26px; font-size: 15px; font-weight: 700; cursor: pointer; }
  header.doc-h { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 4px solid #14532d; padding-bottom: 10px; margin-bottom: 14px; }
  .doc-h h1 { margin: 0; font-size: 21px; color: #14532d; letter-spacing: .5px; }
  .doc-h .sub { color: #64748b; font-size: 12px; margin-top: 3px; }
  .doc-h .mes { text-align: right; }
  .doc-h .mes b { display: block; font-size: 24px; color: #14532d; }
  .doc-h .mes span { font-size: 11px; color: #64748b; }
  .resumo { display: grid; grid-template-columns: repeat(7, 1fr); gap: 6px; margin: 12px 0 16px; }
  .kpi { border: 1px solid #d7dde5; border-radius: 6px; padding: 8px 10px; background: #f8fafc; }
  .kpi .l { font-size: 10px; text-transform: uppercase; letter-spacing: .4px; color: #64748b; }
  .kpi .v { font-size: 14px; font-weight: 800; margin-top: 2px; white-space: nowrap; }
  .kpi .v.green { color: #15803d; } .kpi .v.red { color: #b91c1c; } .kpi .v.orange { color: #c2410c; }
  h2.sec { font-size: 13px; text-transform: uppercase; letter-spacing: .6px; color: #14532d; border-left: 4px solid #14532d; padding-left: 8px; margin: 20px 0 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 11px; }
  th { background: #14532d; color: #fff; padding: 6px 6px; text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: .3px; border: 1px solid #0e3a20; }
  th.num, td.num { text-align: right; }
  td { border: 1px solid #d7dde5; padding: 5px 6px; white-space: nowrap; }
  td.c { text-align: center; }
  td.b { font-weight: 700; }
  td.neg, .neg { color: #b91c1c; }
  tr.zebra td { background: #f4f7fa; }
  tr.fds td { background: #fdf6e3; }
  tr.total td { background: #14532d; color: #fff; font-weight: 800; border-color: #0e3a20; font-size: 11.5px; }
  .duascol { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .aviso { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; border-radius: 6px; padding: 10px 12px; font-size: 12px; margin: 10px 0; font-weight: 600; }
  .nota { font-size: 10px; color: #64748b; margin-top: 6px; }
  footer.doc-f { margin-top: 26px; border-top: 1px solid #d7dde5; padding-top: 8px; display: flex; justify-content: space-between; font-size: 10px; color: #64748b; }
  @media print { body { background: #fff; } .no-print { display: none; } .doc { padding: 0; max-width: none; } }
</style></head><body>
<div class="no-print"><button class="btn-pdf" onclick="window.print()">📄 Salvar em PDF / Imprimir</button>
  <div style="font-size:12px;color:#64748b;margin-top:6px">Na janela de impressão escolha “Salvar como PDF” — o documento já sai em A4 deitado.</div></div>
<div class="doc">
  <header class="doc-h">
    <div><h1>🐰 RESTAURANTE TOCA DO COELHO</h1><div class="sub">Fechamento Mensal — Fluxo de Caixa Operacional · São Gonçalo/RJ</div></div>
    <div class="mes"><span>Mês de referência</span><b>${escHtml(planilha.mes_label)}</b><span>Gerado em ${escHtml(geradoEm)}</span></div>
  </header>

  <div class="resumo">
    <div class="kpi"><div class="l">Vendas</div><div class="v green">${brl(t.vendas)}</div></div>
    <div class="kpi"><div class="l">Pratos</div><div class="v">${t.pratos_vendidos}${t.ticket_medio ? ' · ' + brl(t.ticket_medio) : ''}</div></div>
    <div class="kpi"><div class="l">Despesas caixa</div><div class="v red">${brl(t.despesas)}</div></div>
    <div class="kpi"><div class="l">Compras estoque</div><div class="v orange">${brl(t.compras_estoque)}</div></div>
    <div class="kpi"><div class="l">Consumo estoque</div><div class="v orange">${brl(t.consumo_estoque)}</div></div>
    <div class="kpi"><div class="l">Perdas</div><div class="v red">${brl(t.perdas)}</div></div>
    <div class="kpi"><div class="l">Resultado</div><div class="v ${t.resultado_dia_estimado < 0 ? 'red' : 'green'}">${brl(t.resultado_dia_estimado)}</div></div>
  </div>
  ${pendHtml}

  <h2 class="sec">Movimento diário — ${escHtml(planilha.mes_label)}</h2>
  <table>
    <thead><tr>
      <th class="c">Data</th><th class="c">Dia</th><th class="num">Pratos</th><th class="num">Vendas</th>
      ${F_KEYS.map(([, lbl]) => `<th class="num">${lbl}</th>`).join('')}
      <th class="num">Cortes</th><th class="num">Despesas</th><th class="num">Compras</th><th class="num">Consumo</th><th class="num">Perdas</th><th class="num">Resultado</th><th class="num">Lixo</th>
    </tr></thead>
    <tbody>${linhasDia}${linhaTotal}</tbody>
  </table>
  <div class="nota">Resultado = vendas − consumo − perdas − despesas do caixa. Compras são investimento em estoque (não entram no resultado do dia). Lixo do buffet é anotação (não entra nas contas).${somaIfoodOutros > 0 ? ' Recebimentos em Ifood/Outros no mês: ' + brl(somaIfoodOutros) + '.' : ''}</div>

  <div class="duascol">
    <div>
      <h2 class="sec">Recebimentos por tipo de pagamento</h2>
      <table>
        <thead><tr><th>Tipo</th><th class="num">Valor</th><th class="num">% das vendas</th></tr></thead>
        <tbody>${linhasFormas}<tr class="total"><td>TOTAL</td><td class="num">${brl(t.total_pagamentos)}</td><td class="num">100%</td></tr></tbody>
      </table>
    </div>
    <div>
      <h2 class="sec">Indicadores do mês</h2>
      <table>
        <thead><tr><th>Indicador</th><th class="num">Valor</th></tr></thead>
        <tbody>
          <tr><td>Dias com caixa fechado</td><td class="num">${t.dias_com_caixa} de ${t.dias_mes}</td></tr>
          <tr class="zebra"><td>Consumo sobre vendas</td><td class="num">${t.consumo_sobre_vendas_pct != null ? String(t.consumo_sobre_vendas_pct).replace('.', ',') + '%' : '—'}</td></tr>
          <tr><td>Perdas sobre vendas</td><td class="num">${t.perdas_sobre_vendas_pct != null ? String(t.perdas_sobre_vendas_pct).replace('.', ',') + '%' : '—'}</td></tr>
          <tr class="zebra"><td>Despesas sobre vendas</td><td class="num">${t.despesas_sobre_vendas_pct != null ? String(t.despesas_sobre_vendas_pct).replace('.', ',') + '%' : '—'}</td></tr>
          <tr><td>Cortes (erro/tara/patrões/funcionário)</td><td class="num">${brl(t.cortes)}</td></tr>
          <tr class="zebra"><td>🥡 Lixo do buffet no mês</td><td class="num">${t.lixo_buffet_g > 0 ? (t.lixo_buffet_g / 1000).toFixed(2).replace('.', ',') + ' kg em ' + t.dias_com_lixo + ' dia(s)' : 'sem anotações'}</td></tr>
          <tr><td>Caixa do mês (vendas − despesas)</td><td class="num">${brl(t.fluxo_caixa)}</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <footer class="doc-f">
    <span>Toca Estoque — documento gerado automaticamente a partir dos fechamentos diários e do estoque.</span>
    <span>Página gerada em ${escHtml(geradoEm)}</span>
  </footer>
</div>
</body></html>`;

    } else return res.status(400).send('Tipo inválido');

    await audit('relatorio_html', { tipo }, req.user, getClientIp(req));
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch(e) { res.status(500).send('Erro ao gerar relatório: ' + escHtml(e.message)); }
});

// ==================== RESETAR ====================
// Sincroniza a qtd de um produto SEMPRE registrando uma movimentação de Ajuste.
// Antes, reset/restauração sobrescreviam produtos.qtd direto, sem deixar rastro —
// a qtd ficava diferente do histórico e a conferência acusava "fantasmas" falsos
// (entrada registrada, qtd 0, nenhuma saída). Agora qtd e histórico nunca divergem.
async function sincronizarQtd(prod, novaQtd, motivo, responsavel) {
  const qtdAntes = Number(prod.qtd);
  const alvo = Number(Number(novaQtd).toFixed(3));
  if (!Number.isFinite(alvo) || alvo === qtdAntes) return false;
  const custoUnit = Number(prod.custo || 0);
  await supabase.from('produtos').update({ qtd: alvo }).eq('id', prod.id);
  await supabase.from('movimentacoes').insert({
    produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
    tipo: 'Ajuste', qtd: alvo, unidade: prod.unidade,
    custo: custoUnit, valor: Number((custoUnit * Math.abs(alvo - qtdAntes)).toFixed(2)),
    motivo, responsavel: responsavel || 'Sistema', obs: 'sincronização automática',
    qtd_antes: qtdAntes, qtd_depois: alvo, created_at: nowSP(),
  });
  return true;
}

app.post('/api/resetar', auth, requireRole('admin'), async (req, res) => {
  const confirmacao = sanitizeText(req.body?.confirmacao, 20).toUpperCase();
  if (confirmacao !== 'RESTAURAR') return res.status(400).json({ erro: 'Confirmação inválida. Digite RESTAURAR para continuar.' });
  const senhaAdmin = String(req.body?.senha_admin || '');
  const { data: userDb } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!verifyPassword(senhaAdmin, userDb.password_hash)) return res.status(401).json({ erro: 'Senha de administrador incorreta.' });
  const seedPath = path.join(__dirname, 'produtos_seed.json');
  if (!fs.existsSync(seedPath)) return res.status(404).json({ erro: 'Seed não encontrado.' });
  const produtos = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
  const { data: prodsDb } = await supabase.from('produtos').select('id, nome, categoria, unidade, qtd, custo');
  const mapDb = {}; for (const pd of (prodsDb || [])) mapDb[pd.nome] = pd;
  for (const p of produtos) {
    // custo/mínimo atualizam direto; a QTD vira Ajuste para não desincronizar o histórico
    await supabase.from('produtos').update({ custo: p.custo, minimo: p.minimo }).eq('nome', p.nome);
    const pd = mapDb[p.nome];
    if (pd) await sincronizarQtd({ ...pd, custo: p.custo }, p.qtd, 'Reset de estoque (restaurar seed)', req.user.nome);
  }
  await audit('resetar_estoque', { total_produtos: produtos.length }, req.user, getClientIp(req));
  res.json({ ok: true });
});

// ==================== LER CUPOM (IA) ====================
// Ler nota fiscal é parte do LANÇAMENTO de estoque (não da IA). Todo quem lança (operador
// inclusive) pode usar o leitor. NÃO acoplar à permissão 'ia' — senão desligar a varredura
// automática (ia) bloqueia o leitor junto.
// Motor compartilhado do leitor de nota: lê a(s) imagem(ns) com a IA e cruza com o estoque.
// Usado pelo app (/api/ler-cupom, confirmação na tela) e pelo grupo do WhatsApp (lançamento automático).
// Retorna { itens } | { itens:[], aviso } | { status, erro }.
async function lerNotaComIA(listaImg, mediaType, userLog) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { status: 500, erro: 'ANTHROPIC_API_KEY não configurada no servidor.' };
  const avisoFatias = listaImg.length > 1
    ? `\n\nATENÇÃO: você recebeu ${listaImg.length} FATIAS da MESMA nota fiscal, em ordem de cima para baixo, com pequena SOBREPOSIÇÃO entre uma fatia e a seguinte. Linhas que aparecem repetidas na emenda de duas fatias são o MESMO item — conte UMA vez só. Monte a lista única de itens da nota inteira.`
    : '';
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6', max_tokens: 16384,
        messages: [{ role: 'user', content: [
          ...listaImg.map(b64 => ({ type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: b64 } })),
          { type: 'text', text: avisoFatias + `Você está lendo um CUPOM FISCAL / NOTA FISCAL (NFC-e) de compras de um restaurante brasileiro.\nExtraia TODOS os itens com nome, quantidade, unidade e VALOR TOTAL da linha.\n\nESTRUTURA DA NOTA: cada item tem colunas — Descrição, QUANTIDADE (Qtd/Qtde/Quant), Unidade (UN/KG/CX/PCT), Valor Unitário (Vl Unit) e Valor Total (Vl Total). A QUANTIDADE é a coluna que importa — NUNCA o volume/peso que aparece no nome.\n\nCOMO ACERTAR A QUANTIDADE (regra de ouro):\n1. Pegue o número da COLUNA de quantidade (Qtd) da linha do item.\n2. CONFIRA dividindo: Valor Total ÷ Valor Unitário = quantidade. Use isso para corrigir leituras erradas. Ex: total 42,00 e unit 3,50 -> qtd 12.\n3. Para BEBIDA/LÍQUIDO em garrafa/lata/pote fechado, o volume no nome (350ML, 500ML, 2L) NÃO é a quantidade — conte as UNIDADES. MAS para SACO/CAIXA/FARDO de hortifruti, legume, tubérculo ou grão vendido por peso, o PESO no nome (25KG, 20KG) É a quantidade em kg.\n4. Multiplicador 'N x' ou 'x N' ou 'NX' ou 'A x B': a quantidade é o NÚMERO DE UNIDADES. Ex: 'COCA 350ML 12X' -> 12 | 'AGUA 500ML X 24' -> 24 | '350x12' -> 12 | 'REFRI 2L X 6' -> 6.\n5. IMPORTANTE: itens de compra de restaurante quase NUNCA têm quantidade 1. Se você leu 1, RELEIA a coluna de quantidade e o valor total — quase sempre a quantidade é maior.\n\nREGRA DE UNIDADE (o restaurante compra quase tudo por QUILO):\n- PROTEÍNAS são SEMPRE KG: file de frango, peito, coxa, sobrecoxa, asa, coracao, carne, boi, alcatra, patinho, acem, coxao, musculo, suino, porco, lombo, pernil, costela, linguica, bacon, salsicha, peixe, pescado, tilapia, salmao, camarao, bacalhau, file, mignon, fraldinha, picanha. Para proteína a qtd é o PESO em kg.\n- SACO/SC/CAIXA/CX/FARDO COM PESO de proteína, hortifruti, legume, tubérculo ou grão (ex 'FILE FRANGO CX 20KG', 'SACO BATATA 25KG', 'CX CENOURA 20KG', 'SACO CEBOLA 20KG', 'CARNE 18 KG') -> qtd = o PESO em KG (25, 20...), unidade KG. NÃO é 1 saco nem 1 caixa. Se houver N sacos/caixas, multiplique: '2 SACO BATATA 25KG' -> 50 KG.\n- Hortifruti, grãos, farinhas a granel: KG quando vier em peso.\n- UN só para itens realmente unitários e fechados: latas, garrafas, vidros, potes, pacotes, descartáveis.\n- L para litro. CX só quando for contagem de caixas SEM peso.\n\nVALOR TOTAL da linha (campo valor_total): o número da coluna Vl Total do item, em reais, número com PONTO decimal (ex: 42.00). É o valor que você já usa na conferência Total ÷ Unit. Se houver desconto na linha, use o valor final pago. Se não conseguir ler o valor daquela linha, use null — NUNCA invente.\n\nRESPONDA SOMENTE com JSON válido, sem markdown, no formato:\n{\"itens\":[{\"nome\":\"Nome do produto\",\"qtd\":12,\"unidade\":\"UN\",\"valor_total\":42.00}]}\n\nExemplos:\n'COCA-COLA 350ML 12X 3,50 42,00' -> {nome:'Coca-Cola 350ml', qtd:12, unidade:'UN', valor_total:42.00}\n'AGUA 500ML X 24 UN 1,20 28,80' -> qtd:24, UN, valor_total:28.80\n'FILE FRANGO CX 20KG 22,90 458,00' -> qtd:20, KG, valor_total:458.00\n'PEITO FGO 18,5 KG' -> qtd:18.5, KG\n'SACO BATATA 25KG' -> qtd:25, KG\n'CX CENOURA 20KG' -> qtd:20, KG\n'2 SACO CEBOLA 20KG' -> qtd:40, KG (2 sacos x 20kg)\n\nLeia com MUITA atenção cada linha. Em dúvida entre unidade e quilo numa proteína, escolha KG. Se não conseguir ler: {\"itens\":[],\"erro\":\"descrição do problema\"}` }
        ]}]
      })
    });
    if (!response.ok) {
      const errBody = (await response.text()).slice(0, 500);
      console.error('Anthropic API error [ler-cupom]:', response.status, errBody);
      return { status: 502, erro: 'Erro na API (' + response.status + '): ' + errBody };
    }
    const data = await response.json();
    const text = (data.content || []).map(b => b.text || '').join('');
    // Parse tolerante: tenta direto e, se falhar, extrai o JSON (1º '{' até o último '}').
    const tentaParse = (s) => { try { return JSON.parse(s); } catch(e) { return null; } };
    let parsed = tentaParse(text.replace(/```json|```/g, '').trim());
    if (!parsed) { const ini = text.indexOf('{'), fim = text.lastIndexOf('}'); if (ini >= 0 && fim > ini) parsed = tentaParse(text.slice(ini, fim + 1)); }
    if (!parsed) {
      console.error('ler-cupom: resposta não-JSON da IA:', text.slice(0, 300));
      await logErroAgenda('ler-cupom parse', 'IA respondeu fora do formato: ' + text.slice(0, 150), userLog);
      return { status: 422, erro: 'Foto ilegível. Tente uma imagem mais nítida e bem iluminada.' };
    }
    if (parsed.erro) return { itens: [], aviso: parsed.erro };

    // Batch synonym lookup — 1 query para todos os itens
    const termos = (parsed.itens || []).map(i => normalizeSearch(i.nome));
    const { data: sinonimosData } = await supabase.from('sinonimos').select('termo, produto_nome').in('termo', termos);
    const sinoMap = Object.fromEntries((sinonimosData || []).map(s => [s.termo, s.produto_nome]));

    // 1 query: todos os produtos ativos — matching feito em JS, sem queries no loop
    const { data: prodPool } = await supabase.from('produtos')
      .select('id, nome, categoria, unidade, qtd, minimo, custo, nome_search')
      .or('ativo.eq.1,ativo.is.null');
    const todosProds = prodPool || [];
    const prodByNomeLower = Object.fromEntries(todosProds.map(p => [p.nome.toLowerCase(), p]));

    const itens = [];
    for (const item of (parsed.itens || [])) {
      const qNorm = normalizeSearch(item.nome);
      let candidatos = [], via = null;

      // 1) Apelido salvo (sinônimo) — match CONFIÁVEL
      const prodNomeSinonimo = sinoMap[qNorm];
      if (prodNomeSinonimo) {
        const sp = prodByNomeLower[prodNomeSinonimo.toLowerCase()];
        if (sp) { candidatos = [sp]; via = 'apelido'; }
      }
      // 2) Nome exato normalizado — match CONFIÁVEL (se único)
      if (!candidatos.length) {
        const exato = todosProds.filter(p => (p.nome_search || normalizeSearch(p.nome)) === qNorm);
        if (exato.length === 1) { candidatos = exato; via = 'nome_exato'; }
        else if (exato.length > 1) { candidatos = exato.slice(0, 3); via = 'ambiguo'; }
      }
      // 3) Pontuação por palavra — PALPITE: só auto-seleciona se for líder isolado e cobrir o nome todo
      if (!candidatos.length) {
        const palavras = qNorm.split(/\s+/).filter(w => w.length > 2);
        const ranked = [];
        for (const p of todosProds) {
          const ns = (p.nome_search || normalizeSearch(p.nome));
          let score = 0;
          for (const w of palavras) if (ns.includes(w)) score++;
          if (qNorm && ns.includes(qNorm)) score += 0.5; // frase inteira contida = bônus
          if (score > 0) ranked.push({ produto: p, score });
        }
        ranked.sort((a, b) => b.score - a.score);
        candidatos = ranked.slice(0, 3).map(r => r.produto);
        const topScore = ranked.length ? ranked[0].score : 0;
        const segScore = ranked.length > 1 ? ranked[1].score : 0;
        const cobreTudo = palavras.length > 0 && topScore >= palavras.length;
        via = (cobreTudo && topScore > segScore) ? 'forte' : 'palpite';
      }

      // Auto-seleciona o produto SÓ quando o match é confiável; senão a tela exige confirmação.
      const confiavel = via === 'apelido' || via === 'nome_exato' || via === 'forte';
      // Preço da nota: valor_total da linha ÷ qtd (já normalizada p/ unidade do produto,
      // ex. saco 25kg → qtd 25) = custo unitário REAL da compra. Mantém preço vivo.
      const qtdItem = Number(item.qtd) || 1;
      const vt = Number(item.valor_total);
      const valorTotal = Number.isFinite(vt) && vt > 0 ? Number(vt.toFixed(2)) : null;
      itens.push({
        nome_cupom: item.nome,
        qtd: qtdItem,
        unidade_cupom: item.unidade || 'UN',
        valor_total: valorTotal,
        custo_unit: valorTotal ? Number((valorTotal / qtdItem).toFixed(4)) : null,
        candidatos,
        produto: confiavel ? (candidatos[0] || null) : null,
        via, via_sinonimo: via === 'apelido',
        incerto: !confiavel && candidatos.length > 0,
      });
    }
    return { itens };
}

app.post('/api/ler-cupom', auth, requirePerm('lancar'), async (req, res) => {
  const { imagem, imagens, mediaType } = req.body;
  // Aceita 'imagens' (fatias de nota comprida, em ordem) ou 'imagem' única (compat).
  const listaImg = (Array.isArray(imagens) && imagens.length ? imagens : (imagem ? [imagem] : [])).slice(0, 8);
  if (!listaImg.length) return res.status(400).json({ erro: 'Imagem não enviada.' });
  try {
    const r = await lerNotaComIA(listaImg, mediaType, req.user);
    if (r.erro) return res.status(r.status || 500).json({ erro: r.erro });
    if (r.aviso) return res.json({ itens: [], aviso: r.aviso });
    await audit('ler_cupom', { total_itens: r.itens.length }, req.user, getClientIp(req));
    res.json({ itens: r.itens });
  } catch(e) {
    console.error('Erro ler-cupom:', e.message);
    await logErroAgenda('ler-cupom', e, req.user);
    res.status(500).json({ erro: 'Erro ao ler o cupom. Tente novamente.' });
  }
});

// ==================== LER NOTA VIA WHATSAPP (grupo de notas) ====================
// O bot manda a foto da nota; itens com match CONFIÁVEL (apelido/nome exato) e unidade
// compatível são lançados como Entrada automaticamente. O resto volta na resposta
// para confirmação no app. Nunca lança no chute.
function unidadeCompativel(uniCupom, uniProd) {
  const n = (u) => normalizeSearch(u).replace(/s$/, '');
  const a = n(uniCupom || 'un'), b = n(uniProd || 'un');
  if (a === b) return true;
  const grupos = [['un', 'unidade', 'pc', 'pct', 'cx', 'fardo', 'pacote'], ['kg', 'quilo', 'kilo', 'g'], ['l', 'lt', 'litro', 'ml']];
  return grupos.some(g => g.includes(a) && g.includes(b));
}

// ── GRUPO "TOCA FINANCEIRO" — conta/boleto vira lançamento ───────────────────
// Mesma ideia do grupo de notas do estoque, mas pro financeiro (pedido do Rubens,
// 01/08). Só CONTA e BOLETO — contracheque e folha NÃO passam por aqui, porque o
// grupo teria dado pessoal de funcionário circulando no WhatsApp.
// O problema que isso resolve: hoje a conta só existe se alguém lembrar de lançar,
// e foi por isso que julho passou o mês inteiro sem água e luz.
async function lerContaComIA(listaImg, mediaType, userLog) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { erro: 'ANTHROPIC_API_KEY não configurada no servidor.' };
  const contasDisponiveis = CONTAS_PLANILHA_PAGAMENTOS
    .map(g => `${g.grupo}: ${g.contas.join(' | ')}`).join('\n');
  const prompt = `Você está lendo uma CONTA ou BOLETO de um restaurante brasileiro (conta de luz, água, internet, telefone, boleto de fornecedor, guia de imposto, tarifa).

Extraia:
- fornecedor: quem está cobrando (ex: "Light", "CEDAE", "Vivo", "Prefeitura"). Nome curto e limpo.
- valor: o valor A PAGAR em reais, número com PONTO decimal. É o total do documento, não parcela avulsa nem juros isolados.
- vencimento: data de vencimento no formato AAAA-MM-DD. Se não houver, null.
- documento: número do documento/código de barras curto, se visível. Senão null.
- descricao: uma linha curta descrevendo (ex: "Conta de luz referente a julho").
- grupo e categoria: classifique NAS CONTAS ABAIXO, exatamente como escritas. Se não tiver certeza, use null nos dois.

CONTAS DISPONÍVEIS:
${contasDisponiveis}

RESPONDA SOMENTE com JSON válido, sem markdown:
{"tipo":"conta","fornecedor":"Light","valor":5312.00,"vencimento":"2026-07-20","documento":null,"descricao":"Conta de luz de julho","grupo":"Contas Públicas","categoria":"Eletricidade"}

═══ CASO ESPECIAL: DOCUMENTOS DE FOLHA ═══
Se for documento de folha, use tipo "folha". É PROIBIDO incluir nome de funcionário,
CPF, matrícula, cargo ou salário individual no JSON — o sistema não usa esses dados.

Identifique QUAL dos documentos é e extraia SÓ o total indicado:

1) EXTRATO MENSAL / FOLHA DE PAGAMENTO (várias páginas, últimas com quadro de totais)
   → rubrica "Salários" = valor de "Total Geral Proventos"
   Esse é o custo bruto do pessoal. NÃO extraia INSS nem IRRF daqui: eles são DESCONTOS
   que já estão dentro dos proventos, e lançá-los de novo contaria duas vezes.
   Se o quadro trouxer "Valor do FGTS" e/ou "Valor FGTS Rescisório", some os dois numa
   rubrica "FGTS".

2) GUIA DO FGTS (GFD / FGTS Digital / GRF)
   → rubrica "FGTS" = valor de "Valor a recolher" (ou "Total a recolher")

3) DARF / GPS de INSS
   → rubrica "INSS" = "Valor Total do Documento"
   IMPORTANTE: olhe os códigos de receita. Se TODOS forem contribuição descontada do
   segurado (ex: 1082, 1099, 1007) sem parte patronal, marque "so_segurado": true — esse
   valor já saiu do bolso do funcionário e não é custo novo do empregador.

4) CONTRACHEQUE INDIVIDUAL, folha de ponto, informativo ou previsão de férias
   → responda {"tipo":"folha","ignorar":"<que documento é>"} sem rubricas.

5) COMPROVANTE DE PAGAMENTO de salário (Pix/TED para funcionário, recibo de salário)
   → tipo "quitacao". É a QUITAÇÃO da folha, não um custo novo: o custo já foi
   reconhecido quando a folha do mês entrou. Extraia só o valor e a competência
   (se não disser a competência, use o mês da data do pagamento).
   NÃO inclua o nome de quem recebeu.
   {"tipo":"quitacao","competencia":"2026-07","valor":1850.00,"descricao":"Pagamento de salário"}

Formato:
{"tipo":"folha","competencia":"2026-07","descricao":"Folha de julho","so_segurado":false,"rubricas":[{"rubrica":"Salários","valor":30072.09}]}

Se não conseguir ler: {"erro":"descrição do problema"}`;
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6', max_tokens: 2048,
        messages: [{ role: 'user', content: [
          // Boleto quase sempre chega em PDF, não em foto — a API aceita os dois, mas o
          // bloco é 'document' pra PDF e 'image' pro resto.
          ...listaImg.map(b64 => (/pdf/i.test(mediaType || '')
            ? { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: b64 } }
            : { type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: b64 } })),
          { type: 'text', text: prompt },
        ] }],
      }),
    });
    if (!response.ok) {
      const errBody = (await response.text()).slice(0, 300);
      console.error('Anthropic API error [ler-conta]:', response.status, errBody);
      return { erro: `Erro na API (${response.status})` };
    }
    const data = await response.json();
    const text = (data.content || []).map(b => b.text || '').join('');
    const tenta = s => { try { return JSON.parse(s); } catch (e) { return null; } };
    let parsed = tenta(text.replace(/```json|```/g, '').trim());
    if (!parsed) { const i = text.indexOf('{'), f = text.lastIndexOf('}'); if (i >= 0 && f > i) parsed = tenta(text.slice(i, f + 1)); }
    if (!parsed) {
      await logErroAgenda('ler-conta parse', 'IA fora do formato: ' + text.slice(0, 150), userLog);
      return { erro: 'Foto ilegível. Tente uma imagem mais nítida e inteira.' };
    }
    return parsed;
  } catch (e) {
    console.error('ler-conta:', e.message);
    return { erro: e.message };
  }
}

// Decide a conta com 3 níveis de confiança. A memória (fornecedor já visto e
// confirmado) é a única que auto-lança — o resto vai pra confirmação, igual as
// pendências de nota. Sem isso o financeiro entra errado e ninguém percebe.
async function classificarConta({ fornecedor, grupo, categoria, descricao }) {
  const termo = normalizeSearch(fornecedor || '');
  if (termo) {
    const { data: mem } = await supabase.from('conta_memoria').select('*').eq('termo', termo).maybeSingle();
    if (mem) return { grupo: mem.grupo, categoria: mem.categoria, confianca: 'memoria' };
  }
  const daIA = grupo && categoria ? acharContaPagamento(categoria) : null;
  if (daIA && daIA.grupo === grupo) return { ...daIA, confianca: 'texto' };
  const porTexto = inferirContaPagamentoPorTexto([fornecedor, descricao].filter(Boolean).join(' '));
  if (porTexto && porTexto.categoria !== 'Outros') return { ...porTexto, confianca: 'texto' };
  return { grupo: null, categoria: null, confianca: 'nenhuma' };
}

app.post('/api/webhook/ler-conta', webhookLimiter, async (req, res) => {
  if (!WEBHOOK_SECRET) return res.status(503).json({ erro: 'Webhook não configurado no servidor.' });
  const secret = req.headers['x-webhook-secret'] || req.body?.secret;
  if (secret !== WEBHOOK_SECRET) return res.status(403).json({ erro: 'Acesso negado.' });
  const { imagem, imagens, mediaType } = req.body;
  const remetente = sanitizeText(req.body?.remetente, 60) || 'WhatsApp';
  const lista = (Array.isArray(imagens) && imagens.length ? imagens : (imagem ? [imagem] : [])).slice(0, 4);
  if (!lista.length) return res.status(400).json({ erro: 'Imagem não enviada.' });
  try {
    const r = await lerContaComIA(lista, mediaType, { nome: remetente });
    if (r.erro) return res.json({ resposta: `❌ Não consegui ler: ${r.erro}` });

    // FOLHA: entra pelos TOTAIS por rubrica. Nome, CPF e salário individual não são
    // extraídos nem gravados — o financeiro só precisa do custo por conta, e guardar
    // dado pessoal de funcionário seria risco sem nenhum ganho.
    // Comprovante de pagamento de salário: registra a saída, mas NÃO soma no custo —
    // a folha da competência já respondeu "quanto custou". Aqui é "quanto já saiu".
    if (r.tipo === 'quitacao') {
      const valor = parseNonNegativeMoney(r.valor);
      if (!valor) return res.json({ resposta: '⚠️ Não achei o valor do comprovante.' });
      const comp = /^\d{4}-\d{2}$/.test(r.competencia || '') ? r.competencia : dateSP().slice(0, 7);
      await supabase.from('pagamentos_comprovantes').insert({
        data: dateSP(), grupo: 'Despesas Fixas / CMO', categoria: 'Salários', forma: 'quitacao',
        valor_bruto: valor, taxa: 0, valor_liquido: valor, parcelas: 0,
        descricao: sanitizeText(r.descricao || 'Pagamento de salário', 180),
        origem: 'quitacao-whatsapp', responsavel: remetente, quitacao: true, competencia: comp,
        created_at: nowSP(), updated_at: nowSP(),
      });
      const { data: pagos } = await supabase.from('pagamentos_comprovantes')
        .select('valor_bruto').eq('quitacao', true).eq('competencia', comp);
      const totalPago = (pagos || []).reduce((s, p) => s + Number(p.valor_bruto || 0), 0);
      const { data: folha } = await supabase.from('pagamentos_comprovantes')
        .select('valor_bruto').eq('origem', 'folha-whatsapp').eq('data', fimMesISO(comp));
      const custoFolha = (folha || []).reduce((s, p) => s + Number(p.valor_bruto || 0), 0);
      await audit('quitacao_folha', { remetente, competencia: comp, valor }, null, '');
      return res.json({ resposta:
        `✅ Pagamento de ${fmtBRL(valor)} registrado (competência ${comp.split('-').reverse().join('/')}).\n\n` +
        (custoFolha > 0
          ? `Folha do mês: ${fmtBRL(custoFolha)}\nJá pago: ${fmtBRL(totalPago)}\nEm aberto: ${fmtBRL(custoFolha - totalPago)}`
          : `Já pago nessa competência: ${fmtBRL(totalPago)}\n_A folha desse mês ainda não foi lançada — manda que eu fecho a conta._`) +
        `\n\n_Não somei no custo: quem diz o custo é a folha._` });
    }
    if (r.tipo === 'folha' && r.ignorar) {
      return res.json({ resposta: `ℹ️ Isso é *${sanitizeText(r.ignorar, 80)}* — não tem total pra lançar.\n\nDo pacote do contador, manda só três: a *folha de pagamento*, a *guia do FGTS* e o *DARF do INSS*.` });
    }
    // INSS que é só contribuição descontada do segurado já está dentro dos proventos —
    // lançar de novo contaria o mesmo dinheiro duas vezes no CMO.
    if (r.tipo === 'folha' && r.so_segurado) {
      const v = parseNonNegativeMoney((r.rubricas || [])[0]?.valor) || 0;
      return res.json({ resposta:
        `ℹ️ DARF de INSS${v ? ' de ' + fmtBRL(v) : ''} — *não lancei de propósito*.\n\n` +
        `Esse valor é a contribuição descontada dos funcionários, que já está dentro do total de proventos da folha. ` +
        `Lançar de novo contaria o mesmo dinheiro duas vezes.\n\n_Se tiver parte patronal, me avisa que eu lanço._` });
    }
    if (r.tipo === 'folha' && Array.isArray(r.rubricas) && r.rubricas.length) {
      const competencia = /^\d{4}-\d{2}$/.test(r.competencia || '') ? r.competencia : dateSP().slice(0, 7);
      const dataLanc = fimMesISO(competencia);
      const linhas = [], ignoradas = [];
      for (const rb of r.rubricas) {
        const valor = parseNonNegativeMoney(rb.valor);
        const conta = acharContaPagamento(sanitizeText(rb.rubrica || '', 120));
        if (!valor || !conta) { ignoradas.push(rb.rubrica); continue; }
        linhas.push({
          data: dataLanc, grupo: conta.grupo, categoria: conta.categoria, forma: 'folha',
          valor_bruto: valor, taxa: 0, valor_liquido: valor, parcelas: 0,
          descricao: `Folha ${competencia.split('-').reverse().join('/')} — ${conta.categoria}`,
          origem: 'folha-whatsapp', responsavel: remetente, created_at: nowSP(), updated_at: nowSP(),
        });
      }
      if (!linhas.length) return res.json({ resposta: '⚠️ Li a folha mas não reconheci nenhuma rubrica. Manda o resumo com os totais (salários, INSS, FGTS, VT).' });
      // Idempotência POR RUBRICA, não pela competência inteira: a folha do mês chega em
      // documentos separados (extrato, guia do FGTS, DARF). Apagar tudo da competência
      // faria a guia do FGTS derrubar o lançamento de Salários que veio antes.
      await supabase.from('pagamentos_comprovantes').delete()
        .eq('origem', 'folha-whatsapp').eq('data', dataLanc)
        .in('categoria', linhas.map(l => l.categoria));
      const { error } = await supabase.from('pagamentos_comprovantes').insert(linhas);
      if (error) return res.json({ resposta: '❌ Erro ao lançar a folha.' });
      await audit('ler_folha_whatsapp', { remetente, competencia, rubricas: linhas.length, total: linhas.reduce((s, l) => s + l.valor_bruto, 0) }, null, '');
      const total = linhas.reduce((s, l) => s + l.valor_bruto, 0);
      return res.json({ resposta:
        `✅ *Folha ${competencia.split('-').reverse().join('/')}* lançada — ${fmtBRL(total)}\n\n` +
        linhas.map(l => `• ${l.categoria}: ${fmtBRL(l.valor_bruto)}`).join('\n') +
        (ignoradas.length ? `\n\n⚠️ Não reconheci: ${ignoradas.filter(Boolean).join(', ')}` : '') +
        `\n\n_Só os totais foram guardados — nenhum nome ou salário individual._`,
      });
    }
    const valor = parseNonNegativeMoney(r.valor);
    if (!valor) return res.json({ resposta: '⚠️ Não achei o valor a pagar. Manda uma foto mais nítida e inteira.' });

    const fornecedor = sanitizeText(r.fornecedor || '', 90);
    const descricao = sanitizeText(r.descricao || fornecedor || 'Conta', 180);
    const vencimento = isDataISO(r.vencimento) ? r.vencimento : null;
    const conta = await classificarConta({ fornecedor, grupo: r.grupo, categoria: r.categoria, descricao });

    // Só auto-lança o que a memória já confirmou antes. Primeira vez de um fornecedor
    // sempre passa pela sua conferência — é assim que ele aprende sem errar sozinho.
    if (conta.confianca === 'memoria') {
      const { data: pag } = await supabase.from('pagamentos_comprovantes').insert({
        data: vencimento || dateSP(), grupo: conta.grupo, categoria: conta.categoria,
        forma: 'boleto', valor_bruto: valor, taxa: 0, valor_liquido: valor, parcelas: 0,
        descricao: `${descricao}${fornecedor ? ' — ' + fornecedor : ''}`,
        origem: 'whatsapp-conta', responsavel: remetente, created_at: nowSP(), updated_at: nowSP(),
      }).select('id').single();
      const termoMem = normalizeSearch(fornecedor);
      const { data: memAtual } = await supabase.from('conta_memoria').select('vezes').eq('termo', termoMem).maybeSingle();
      await supabase.from('conta_memoria')
        .update({ vezes: (memAtual?.vezes || 0) + 1, ultimo_valor: valor, atualizado_em: nowSP() })
        .eq('termo', termoMem);
      await audit('ler_conta_whatsapp', { remetente, fornecedor, valor, conta: conta.categoria, auto: true }, null, '');
      return res.json({ resposta: `✅ Lançado: *${conta.categoria}* — ${fmtBRL(valor)}\n${fornecedor}${vencimento ? ' · vence ' + dataBR(vencimento) : ''}\n\n_Já conhecia esse fornecedor._` });
    }

    const { data: pend } = await supabase.from('conta_pendencias').insert({
      fornecedor, documento: sanitizeText(r.documento || '', 60) || null, valor,
      vencimento, descricao, grupo_sugerido: conta.grupo, categoria_sugerida: conta.categoria,
      confianca: conta.confianca, remetente, status: 'pendente', created_at: nowSP(),
    }).select('id').single();
    await audit('ler_conta_whatsapp', { remetente, fornecedor, valor, sugestao: conta.categoria, auto: false }, null, '');
    return res.json({
      resposta: conta.categoria
        ? `📄 Li: *${fornecedor || 'conta'}* — ${fmtBRL(valor)}${vencimento ? ' · vence ' + dataBR(vencimento) : ''}\n\nAcho que é *${conta.categoria}*. Confirma no app em Contas → Pendentes que eu já aprendo pra próxima.`
        : `📄 Li: *${fornecedor || 'conta'}* — ${fmtBRL(valor)}${vencimento ? ' · vence ' + dataBR(vencimento) : ''}\n\nNão sei em qual conta lançar. Escolhe no app em Contas → Pendentes que eu guardo pra próxima.`,
      pendencia_id: pend?.id,
    });
  } catch (e) {
    console.error('Erro ler-conta webhook:', e.message);
    await logErroAgenda('ler-conta-whatsapp', e, { nome: remetente });
    return res.status(500).json({ resposta: '❌ Erro ao processar a conta.' });
  }
});

// Pendências de conta: listar, confirmar (com aprendizado) e ignorar.
app.get('/api/conta-pendencias', auth, requirePerm('contas'), async (req, res) => {
  const { data } = await supabase.from('conta_pendencias')
    .select('*').eq('status', 'pendente').order('id', { ascending: false }).limit(200);
  res.json({ pendencias: data || [], contas_modelo: CONTAS_PLANILHA_PAGAMENTOS });
});

app.post('/api/conta-pendencias/:id/confirmar', auth, requirePerm('contas'), async (req, res) => {
  const { data: p } = await supabase.from('conta_pendencias').select('*').eq('id', req.params.id).single();
  if (!p || p.status !== 'pendente') return res.status(404).json({ erro: 'Pendência não encontrada.' });
  const conta = acharContaPagamento(sanitizeText(req.body?.categoria || p.categoria_sugerida || '', 120));
  if (!conta) return res.status(400).json({ erro: 'Escolha uma conta válida do plano.' });
  const valor = parseNonNegativeMoney(req.body?.valor ?? p.valor);
  if (!valor) return res.status(400).json({ erro: 'Valor inválido.' });

  const { data: pag, error } = await supabase.from('pagamentos_comprovantes').insert({
    data: p.vencimento || dateSP(), grupo: conta.grupo, categoria: conta.categoria,
    forma: 'boleto', valor_bruto: valor, taxa: 0, valor_liquido: valor, parcelas: 0,
    descricao: `${p.descricao || 'Conta'}${p.fornecedor ? ' — ' + p.fornecedor : ''}`,
    origem: 'whatsapp-conta', responsavel: req.user.nome, created_at: nowSP(), updated_at: nowSP(),
  }).select('id').single();
  if (error) return res.status(500).json({ erro: 'Erro ao lançar a conta.' });

  // APRENDIZADO: da próxima vez que esse fornecedor aparecer, entra sozinho.
  const termo = normalizeSearch(p.fornecedor || '');
  if (termo) {
    const { data: mem } = await supabase.from('conta_memoria').select('vezes').eq('termo', termo).maybeSingle();
    await supabase.from('conta_memoria').upsert({
      termo, grupo: conta.grupo, categoria: conta.categoria,
      vezes: (mem?.vezes || 0) + 1, ultimo_valor: valor,
      atualizado_em: nowSP(), criado_por: req.user.nome,
    }, { onConflict: chaveConflito('termo') });
  }
  await supabase.from('conta_pendencias').update({
    status: 'resolvido', pagamento_id: pag.id, resolvido_em: nowSP(), resolvido_por: req.user.nome,
  }).eq('id', p.id);
  await audit('conta_pendencia_confirmar', { id: p.id, fornecedor: p.fornecedor, conta: conta.categoria, valor }, req.user, getClientIp(req));
  res.json({ ok: true, aprendido: !!termo, conta: conta.categoria });
});

app.post('/api/conta-pendencias/:id/ignorar', auth, requirePerm('contas'), async (req, res) => {
  const { data: p } = await supabase.from('conta_pendencias').select('id,status').eq('id', req.params.id).single();
  if (!p) return res.status(404).json({ erro: 'Pendência não encontrada.' });
  await supabase.from('conta_pendencias').update({ status: 'ignorado', resolvido_em: nowSP(), resolvido_por: req.user.nome }).eq('id', p.id);
  await audit('conta_pendencia_ignorar', { id: p.id }, req.user, getClientIp(req));
  res.json({ ok: true });
});

app.post('/api/webhook/ler-nota', webhookLimiter, async (req, res) => {
  if (!WEBHOOK_SECRET) return res.status(503).json({ erro: 'Webhook não configurado no servidor.' });
  const secret = req.headers['x-webhook-secret'] || req.body?.secret;
  if (secret !== WEBHOOK_SECRET) return res.status(403).json({ erro: 'Acesso negado.' });
  const { imagem, imagens, mediaType } = req.body;
  const remetente = sanitizeText(req.body?.remetente, 60) || 'WhatsApp';
  const listaImg = (Array.isArray(imagens) && imagens.length ? imagens : (imagem ? [imagem] : [])).slice(0, 8);
  if (!listaImg.length) return res.status(400).json({ erro: 'Imagem não enviada.' });
  try {
    const r = await lerNotaComIA(listaImg, mediaType, { nome: remetente });
    if (r.erro) return res.json({ resposta: `❌ Não consegui ler a nota: ${r.erro}` });
    if (r.aviso || !r.itens.length) return res.json({ resposta: `⚠️ Não achei itens na nota. ${r.aviso || 'Tente uma foto mais nítida e inteira.'}` });

    const lancados = [], confirmar = [], naoachados = [], pendencias = [];
    for (const item of r.itens) {
      // Auto-lança SÓ apelido/nome exato (certeza real) com unidade compatível; 'forte' é palpite — vai pra confirmação.
      const auto = item.produto && (item.via === 'apelido' || item.via === 'nome_exato') && unidadeCompativel(item.unidade_cupom, item.produto.unidade);
      if (!auto) {
        // Guarda a pendência pra resolver no app (aba Histórico → Pendentes), sem refazer foto.
        pendencias.push({
          produto_cupom: item.nome_cupom, qtd: item.qtd, unidade_cupom: item.unidade_cupom || null,
          valor_total: item.valor_total || null,
          candidatos: (item.candidatos || []).map(c => ({ id: c.id, nome: c.nome, unidade: c.unidade, codigo: c.codigo || null })),
          remetente, status: 'pendente', created_at: nowSP(),
        });
        if (item.candidatos && item.candidatos.length) confirmar.push({ nome_cupom: item.nome_cupom, qtd: item.qtd, sugestao: item.candidatos[0].nome });
        else naoachados.push(`${item.nome_cupom} (${item.qtd})`);
        continue;
      }
      // Entrada com trava otimista (mesma blindagem do webhook entrada)
      // Preço da nota atualiza o custo do produto — senão o custo congela pra sempre.
      const custoNovo = item.custo_unit && item.custo_unit > 0 ? item.custo_unit : null;
      let prodAtual = item.produto, novaQtd = 0, sucesso = false;
      for (let tent = 0; tent < 4 && !sucesso; tent++) {
        novaQtd = Number((Number(prodAtual.qtd) + Number(item.qtd)).toFixed(3));
        const updData = custoNovo !== null ? { qtd: novaQtd, custo: custoNovo } : { qtd: novaQtd };
        const { data: upd } = await supabase.from('produtos').update(updData).eq('id', prodAtual.id).eq('qtd', prodAtual.qtd).select('id');
        if (upd && upd.length) { sucesso = true; break; }
        const { data: re } = await supabase.from('produtos').select('*').eq('id', item.produto.id).single();
        if (!re) break;
        prodAtual = re;
      }
      if (!sucesso) { confirmar.push({ nome_cupom: item.nome_cupom, qtd: item.qtd, sugestao: item.produto.nome }); continue; }
      const custoUnit = custoNovo !== null ? custoNovo : Number(item.produto.custo || 0);
      const { data: movNota } = await supabase.from('movimentacoes').insert({
        produto_id: item.produto.id, produto_nome: item.produto.nome, categoria: item.produto.categoria,
        tipo: 'Entrada', qtd: item.qtd, unidade: item.produto.unidade,
        custo: custoUnit, valor: Number((custoUnit * item.qtd).toFixed(2)),
        motivo: 'Compra', responsavel: remetente, obs: 'nota via WhatsApp', created_at: nowSP(),
        qtd_antes: Number(prodAtual.qtd), qtd_depois: novaQtd, // foto antes→depois (auditoria cruzada)
      }).select('id').single();
      const custoAntes = Number(item.produto.custo || 0);
      await lancarCompraNasContas({ produto: item.produto, qtd: item.qtd, custoUnit, responsavel: remetente, obs: 'nota via WhatsApp', movId: movNota?.id });
      lancados.push({ nome: item.produto.nome, qtd: item.qtd, unidade: item.produto.unidade, estoque: novaQtd,
        custo_antes: custoAntes, custo_novo: custoNovo !== null && Math.abs(custoNovo - custoAntes) >= 0.01 ? custoNovo : null });
    }
    // Salva os itens em dúvida como pendências (resolver no app, aba Histórico → Pendentes).
    if (pendencias.length) { try { await supabase.from('nota_pendencias').insert(pendencias); } catch (e) { console.error('pendencias insert:', e.message); } }
    await audit('ler_nota_whatsapp', { remetente, lancados: lancados.length, confirmar: confirmar.length, nao_achados: naoachados.length, pendencias: pendencias.length }, null, '');

    let msg = `🧾 *NOTA PROCESSADA* (por ${remetente})\n\n`;
    if (lancados.length) {
      msg += `✅ *Lançados (${lancados.length}):*\n` + lancados.map(l => `• ${l.nome}: +${l.qtd} ${l.unidade} (estoque: ${l.estoque})` + (l.custo_novo !== null && l.custo_novo !== undefined ? `\n   💲 custo R$${l.custo_antes.toFixed(2)} → R$${l.custo_novo.toFixed(2)}` : '')).join('\n') + '\n';
    }
    if (confirmar.length) msg += `\n⚠️ *Confira no app (${confirmar.length}) — não lancei no chute:*\n` + confirmar.map(c => `• "${c.nome_cupom}" (${c.qtd}) → seria ${c.sugestao}?`).join('\n') + '\n';
    if (naoachados.length) msg += `\n❓ *Não achei no estoque:*\n` + naoachados.map(n => `• ${n}`).join('\n') + '\n';
    if (!lancados.length && !confirmar.length && !naoachados.length) msg += 'Nada para lançar.';
    if (pendencias.length) msg += `\n💡 Resolva no app: aba *Histórico → Pendentes* (${pendencias.length}) — escolha o produto e confirme. Marque "memorizar" que da próxima eu lanço sozinho.`;
    res.json({ resposta: msg, lancados: lancados.length, confirmar: confirmar.length, nao_achados: naoachados.length, pendencias: pendencias.length });
  } catch(e) {
    console.error('Erro ler-nota webhook:', e.message);
    await logErroAgenda('ler-nota-whatsapp', e, { nome: remetente });
    res.json({ resposta: '❌ Erro ao processar a nota: ' + e.message });
  }
});

// ==================== PENDÊNCIAS DE NOTA (resolver no app) ====================
// Itens que a IA teve dúvida ao ler a nota no WhatsApp. Admin resolve escolhendo o
// produto certo (ou libera a permissão 'pendencias' pra um funcionário).
app.get('/api/pendencias', auth, requirePerm('pendencias'), async (req, res) => {
  const { data } = await supabase.from('nota_pendencias').select('*').eq('status', 'pendente').order('id', { ascending: false }).limit(200);
  res.json(data || []);
});

app.post('/api/pendencias/:id/resolver', auth, requirePerm('pendencias'), async (req, res) => {
  const produtoId = req.body?.produto_id;
  const memorizar = !!req.body?.memorizar;
  if (!produtoId) return res.status(400).json({ erro: 'Escolha o produto.' });
  const { data: pend } = await supabase.from('nota_pendencias').select('*').eq('id', req.params.id).single();
  if (!pend || pend.status !== 'pendente') return res.status(404).json({ erro: 'Pendência não encontrada ou já resolvida.' });
  const { data: prod } = await supabase.from('produtos').select('*').eq('id', produtoId).single();
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });
  // Quantidade: usa a corrigida pelo usuário (ex.: peso do saco/caixa) se veio; senão a lida da nota.
  const qtdCorrigida = parsePositiveNumber(req.body?.qtd);
  const qtd = qtdCorrigida !== null ? qtdCorrigida : (Number(pend.qtd) || 0);
  if (qtd <= 0) return res.status(400).json({ erro: 'Quantidade inválida.' });
  // Custo: usa o informado pelo usuário; senão o preço da nota (valor_total ÷ qtd final).
  const custoInformado = parsePositiveNumber(req.body?.custo);
  const vtPend = Number(pend.valor_total);
  const custoNovo = custoInformado !== null ? custoInformado
    : (Number.isFinite(vtPend) && vtPend > 0 ? Number((vtPend / qtd).toFixed(4)) : null);

  // Entrada com trava otimista (mesma blindagem dos outros lançamentos).
  let prodAtual = prod, novaQtd = 0, sucesso = false;
  for (let tent = 0; tent < 4 && !sucesso; tent++) {
    novaQtd = Number((Number(prodAtual.qtd) + qtd).toFixed(3));
    const updData = custoNovo !== null ? { qtd: novaQtd, custo: custoNovo } : { qtd: novaQtd };
    const { data: upd } = await supabase.from('produtos').update(updData).eq('id', prodAtual.id).eq('qtd', prodAtual.qtd).select('id');
    if (upd && upd.length) { sucesso = true; break; }
    const { data: re } = await supabase.from('produtos').select('*').eq('id', prod.id).single();
    if (!re) return res.status(500).json({ erro: 'Erro ao atualizar estoque.' });
    prodAtual = re;
  }
  if (!sucesso) return res.status(409).json({ erro: 'Outro lançamento simultâneo alterou o estoque. Tente de novo.' });

  const custoUnit = custoNovo !== null ? custoNovo : Number(prod.custo || 0);
  const { data: movPend, error: movErr } = await supabase.from('movimentacoes').insert({
    produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
    tipo: 'Entrada', qtd, unidade: prod.unidade,
    custo: custoUnit, valor: Number((custoUnit * qtd).toFixed(2)),
    motivo: 'Compra', responsavel: req.user.nome, obs: 'nota WhatsApp (resolvido no app)', created_at: nowSP(),
    qtd_antes: Number(prodAtual.qtd), qtd_depois: novaQtd, // foto antes→depois (auditoria cruzada)
  }).select('id').single();
  if (movErr) { await supabase.from('produtos').update({ qtd: prodAtual.qtd }).eq('id', prod.id).eq('qtd', novaQtd); return res.status(500).json({ erro: 'Erro ao registrar movimentação.' }); }

  // "Memorizar": salva o apelido (nome da nota → produto), pra próxima lançar sozinho.
  if (memorizar && pend.produto_cupom) {
    try { await supabase.from('sinonimos').upsert({ termo: normalizeSearch(pend.produto_cupom), produto_nome: prod.nome }, { onConflict: chaveConflito('termo') }); } catch (e) {}
  }
  await lancarCompraNasContas({ produto: prod, qtd, custoUnit, responsavel: req.user.nome, obs: 'nota WhatsApp (pendência)', movId: movPend?.id });
  await supabase.from('nota_pendencias').update({ status: 'resolvido', resolvido_em: nowSP(), resolvido_por: req.user.nome }).eq('id', pend.id);
  await audit('pendencia_resolver', { pendencia_id: pend.id, produto: prod.nome, qtd, custo: custoUnit, memorizar }, req.user, getClientIp(req));
  res.json({ ok: true, produto: prod.nome, qtd, nova_qtd: novaQtd, custo_aplicado: custoUnit });
});

// Cadastra um produto NOVO direto da pendência (quando não existe no estoque) e lança a entrada.
app.post('/api/pendencias/:id/criar-produto', auth, requirePerm('pendencias'), async (req, res) => {
  const nome = sanitizeText(req.body?.nome, 120);
  const categoria = sanitizeText(req.body?.categoria, 80);
  const unidade = sanitizeText(req.body?.unidade, 20);
  const memorizar = !!req.body?.memorizar;
  if (!nome || !categoria || !unidade) return res.status(400).json({ erro: 'Nome, categoria e unidade são obrigatórios.' });
  const { data: pend } = await supabase.from('nota_pendencias').select('*').eq('id', req.params.id).single();
  if (!pend || pend.status !== 'pendente') return res.status(404).json({ erro: 'Pendência não encontrada ou já resolvida.' });
  const qtdCorrigida = parsePositiveNumber(req.body?.qtd);
  const qtd = qtdCorrigida !== null ? qtdCorrigida : (Number(pend.qtd) || 0);
  if (qtd <= 0) return res.status(400).json({ erro: 'Quantidade inválida.' });
  let custo = parseNonNegativeNumber(req.body?.custo ?? 0) ?? 0;
  // Sem custo informado: usa o preço da própria nota (valor_total ÷ qtd).
  if (!custo) { const vtP = Number(pend.valor_total); if (Number.isFinite(vtP) && vtP > 0) custo = Number((vtP / qtd).toFixed(4)); }

  // Cria o produto já com a quantidade da nota (é a primeira entrada).
  const { data: novo, error } = await supabase.from('produtos').insert({
    nome, nome_search: normalizeSearch(nome), categoria, unidade,
    qtd, minimo: 1, custo, ativo: 1,
  }).select().single();
  if (error) {
    if (error.code === '23505') return res.status(400).json({ erro: 'Já existe um produto com esse nome. Use "Buscar outro produto".' });
    return res.status(500).json({ erro: 'Erro ao cadastrar produto.' });
  }
  // Registra a movimentação de Entrada correspondente (rastreabilidade).
  const { data: movNovo } = await supabase.from('movimentacoes').insert({
    produto_id: novo.id, produto_nome: novo.nome, categoria: novo.categoria,
    tipo: 'Entrada', qtd, unidade: novo.unidade, custo,
    valor: Number((custo * qtd).toFixed(2)), motivo: 'Compra',
    responsavel: req.user.nome, obs: 'produto novo via nota WhatsApp', created_at: nowSP(),
    qtd_antes: 0, qtd_depois: qtd, // produto criado agora: 0 → primeira entrada
  }).select('id').single();
  await lancarCompraNasContas({ produto: novo, qtd, custoUnit: custo, responsavel: req.user.nome, obs: 'produto novo via nota', movId: movNovo?.id });
  if (memorizar && pend.produto_cupom) {
    try { await supabase.from('sinonimos').upsert({ termo: normalizeSearch(pend.produto_cupom), produto_nome: novo.nome }, { onConflict: chaveConflito('termo') }); } catch (e) {}
  }
  await supabase.from('nota_pendencias').update({ status: 'resolvido', resolvido_em: nowSP(), resolvido_por: req.user.nome }).eq('id', pend.id);
  await audit('pendencia_criar_produto', { pendencia_id: pend.id, produto: novo.nome, qtd, categoria, unidade }, req.user, getClientIp(req));
  res.json({ ok: true, produto: novo.nome, qtd });
});

app.post('/api/pendencias/:id/ignorar', auth, requirePerm('pendencias'), async (req, res) => {
  const { data: pend } = await supabase.from('nota_pendencias').select('id,status').eq('id', req.params.id).single();
  if (!pend || pend.status !== 'pendente') return res.status(404).json({ erro: 'Pendência não encontrada ou já resolvida.' });
  await supabase.from('nota_pendencias').update({ status: 'ignorado', resolvido_em: nowSP(), resolvido_por: req.user.nome }).eq('id', pend.id);
  await audit('pendencia_ignorar', { pendencia_id: pend.id }, req.user, getClientIp(req));
  res.json({ ok: true });
});

// ==================== ASSISTENTE IA AGÊNTICO ====================

const IA_TOOLS = [
  {
    name: 'buscar_produto',
    description: 'Busca produtos pelo nome. Retorna nome, categoria, qtd atual, mínimo, custo, unidade e status.',
    input_schema: {
      type: 'object',
      properties: { nome: { type: 'string', description: 'Nome ou parte do nome do produto' } },
      required: ['nome']
    }
  },
  {
    name: 'listar_produtos',
    description: 'Lista produtos com filtros opcionais. Status: zerado, critico, atencao, ok.',
    input_schema: {
      type: 'object',
      properties: {
        status: { type: 'string', enum: ['zerado', 'critico', 'atencao', 'ok'] },
        categoria: { type: 'string', description: 'Filtrar por categoria' },
        limite: { type: 'number', description: 'Máximo de resultados (padrão 50)' }
      }
    }
  },
  {
    name: 'ver_historico',
    description: 'Histórico de movimentações de um produto específico.',
    input_schema: {
      type: 'object',
      properties: {
        produto_nome: { type: 'string', description: 'Nome do produto' },
        dias: { type: 'number', description: 'Quantos dias atrás buscar (padrão 30)' },
        limite: { type: 'number', description: 'Máximo de registros (padrão 20)' }
      },
      required: ['produto_nome']
    }
  },
  {
    name: 'ver_movimentacoes',
    description: 'Ver movimentações recentes, filtradas por data, tipo ou produto.',
    input_schema: {
      type: 'object',
      properties: {
        hoje: { type: 'boolean', description: 'Se true, retorna apenas movimentações de hoje' },
        tipo: { type: 'string', enum: ['Entrada', 'Saída', 'Perda', 'Ajuste'] },
        dias: { type: 'number', description: 'Quantos dias atrás buscar' },
        produto_nome: { type: 'string', description: 'Filtrar por nome do produto' },
        limite: { type: 'number', description: 'Máximo de registros (padrão 50)' }
      }
    }
  },
  {
    name: 'ver_dashboard',
    description: 'Resumo geral do estoque: totais, zerados, críticos, valor total, lançamentos de hoje.',
    input_schema: { type: 'object', properties: {} }
  },
  {
    name: 'ver_realidade_dia',
    description: 'Resumo do dia cruzando movimento do caixa, pratos vendidos, formas de pagamento, despesas, consumo/perdas do estoque e resultado estimado. Compras entram separadas como investimento/controle de estoque.',
    input_schema: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Data em YYYY-MM-DD. Se omitir, usa hoje.' }
      }
    }
  },
  {
    name: 'alertas_giro_parado',
    description: 'Produtos de alto giro (perecíveis, carnes) sem movimentação além do esperado.',
    input_schema: { type: 'object', properties: {} }
  },
  {
    name: 'listar_categorias',
    description: 'Lista categorias com resumo de quantidade de produtos e status.',
    input_schema: { type: 'object', properties: {} }
  },
  {
    name: 'registrar_movimentacao',
    description: 'Registra entrada, saída, perda ou ajuste de estoque para um produto.',
    input_schema: {
      type: 'object',
      properties: {
        produto_nome: { type: 'string', description: 'Nome do produto' },
        tipo: { type: 'string', enum: ['Entrada', 'Saída', 'Perda', 'Ajuste'] },
        qtd: { type: 'number', description: 'Quantidade' },
        motivo: { type: 'string', description: 'Motivo da movimentação' },
        custo: { type: 'number', description: 'Custo unitário (opcional, Entrada)' }
      },
      required: ['produto_nome', 'tipo', 'qtd']
    }
  },
  {
    name: 'atualizar_produto',
    description: 'Atualiza custo ou estoque mínimo de um produto. Requer role gerente ou admin.',
    input_schema: {
      type: 'object',
      properties: {
        produto_nome: { type: 'string' },
        custo: { type: 'number', description: 'Novo custo unitário' },
        minimo: { type: 'number', description: 'Novo estoque mínimo' }
      },
      required: ['produto_nome']
    }
  },
  {
    name: 'registrar_nota_agenda',
    description: 'Registra observação, erro, melhoria ou alerta na agenda da IA.',
    input_schema: {
      type: 'object',
      properties: {
        tipo: { type: 'string', enum: ['observacao', 'melhoria', 'erro', 'alerta', 'elogio'] },
        texto: { type: 'string', description: 'Conteúdo da nota' },
        produto_nome: { type: 'string', description: 'Produto relacionado (se houver)' }
      },
      required: ['tipo', 'texto']
    }
  },
  {
    name: 'ver_agenda',
    description: 'Lê notas recentes da agenda da IA: observações, melhorias sugeridas, erros detectados.',
    input_schema: {
      type: 'object',
      properties: {
        tipo: { type: 'string', enum: ['observacao', 'melhoria', 'erro', 'alerta', 'elogio'] },
        limite: { type: 'number', description: 'Quantidade de notas (padrão 20)' },
        dias: { type: 'number', description: 'Quantos dias atrás (padrão 30)' }
      }
    }
  }
];

// ===== Matcher determinístico de produto: código → apelido → nome → parcial =====
function pareceCodigo(s) { return /^[a-z]{2,4}\s*-?\s*\d{1,3}$/i.test(String(s || '').trim()); }
function normCodigo(s) {
  const m = String(s || '').toUpperCase().replace(/\s+/g, '').match(/^([A-Z]{2,4})-?(\d{1,3})$/);
  return m ? `${m[1]}-${m[2].padStart(2, '0')}` : null;
}
const SEL_PROD = 'id, nome, codigo, categoria, qtd, minimo, custo, unidade';
// Retorna { produtos:[...], via }. via: codigo | apelido | nome_exato | parcial | vazio.
// Quando vem só 1 → certeza; vários no 'parcial' → ambíguo, a IA deve perguntar.
async function buscarProdutos(termo) {
  const raw = String(termo || '').trim();
  if (!raw) return { produtos: [], via: 'vazio' };
  if (pareceCodigo(raw)) {
    const cod = normCodigo(raw);
    if (cod) {
      const { data } = await supabase.from('produtos').select(SEL_PROD).eq('codigo', cod).limit(1);
      if (data && data.length) return { produtos: data, via: 'codigo' };
    }
  }
  const qn = normalizeSearch(raw);
  const { data: sino } = await supabase.from('sinonimos').select('produto_nome').eq('termo', qn).limit(1);
  if (sino && sino.length) {
    const { data } = await supabase.from('produtos').select(SEL_PROD).eq('nome', sino[0].produto_nome).limit(1);
    if (data && data.length) return { produtos: data, via: 'apelido' };
  }
  const { data: exato } = await supabase.from('produtos').select(SEL_PROD).eq('nome_search', qn).or('ativo.eq.1,ativo.is.null').limit(5);
  if (exato && exato.length) return { produtos: exato, via: 'nome_exato' };
  const { data: parcial } = await supabase.from('produtos').select(SEL_PROD).ilike('nome_search', `%${qn}%`).or('ativo.eq.1,ativo.is.null').order('nome').limit(10);
  return { produtos: parcial || [], via: 'parcial' };
}
function statusProd(p) { return Number(p.qtd) === 0 ? 'ZERADO' : Number(p.qtd) <= Number(p.minimo) * 0.5 ? 'CRITICO' : Number(p.qtd) < Number(p.minimo) ? 'ATENCAO' : 'OK'; }

// Acha UM produto pelo texto digitado — acento/caixa-insensível, aceita código (BOV-01) e apelido.
// Retorna { prod } (registro completo) quando a identificação é certa; { opcoes } quando ambíguo; {} quando não achou.
async function acharProdutoUnico(termo) {
  const { produtos } = await buscarProdutos(termo);
  if (!produtos.length) return {};
  let alvo = produtos.length === 1 ? produtos[0] : null;
  if (!alvo) {
    const qn = normalizeSearch(termo);
    alvo = produtos.find(p => normalizeSearch(p.nome) === qn) || null;
  }
  if (!alvo) return { opcoes: produtos };
  const { data } = await supabase.from('produtos').select('*').eq('id', alvo.id).single();
  return data ? { prod: data } : {};
}

async function acharProdutoPorIdOuNome(produtoId, produtoNome) {
  const id = Number(produtoId || 0);
  if (Number.isFinite(id) && id > 0) {
    const { data } = await supabase.from('produtos').select('*').eq('id', id).single();
    if (data) return { prod: data };
  }
  return acharProdutoUnico(produtoNome);
}

async function executarFerramenta(nome, input, user) {
  try {
    switch (nome) {

      case 'buscar_produto': {
        const q = sanitizeText(input.nome, 100);
        const { produtos, via } = await buscarProdutos(q);
        const lista = produtos.map(p => ({ ...p, status: statusProd(p), valor_em_estoque: Number((Number(p.qtd) * Number(p.custo)).toFixed(2)) }));
        // via 'codigo'/'apelido'/'nome_exato' = identificação CERTA. 'parcial' com >1 = AMBÍGUO: pergunte, não chute.
        const ambiguo = via === 'parcial' && lista.length > 1;
        return { encontrados: lista.length, via, ambiguo,
          instrucao: ambiguo ? 'Vários produtos batem — NÃO escolha sozinho. Liste com o código e pergunte qual.' : (lista.length === 1 ? 'Identificação certa.' : undefined),
          produtos: lista };
      }

      case 'listar_produtos': {
        let q = supabase.from('produtos').select('id, nome, codigo, categoria, qtd, minimo, custo, unidade').or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
        if (input.categoria) q = q.eq('categoria', sanitizeText(input.categoria, 80));
        const { data } = await q.limit(500);
        let res = (data || []).map(p => {
          const st = Number(p.qtd) === 0 ? 'ZERADO' : Number(p.qtd) <= Number(p.minimo) * 0.5 ? 'CRITICO' : Number(p.qtd) < Number(p.minimo) ? 'ATENCAO' : 'OK';
          return { ...p, status: st };
        });
        if (input.status === 'zerado') res = res.filter(p => p.status === 'ZERADO');
        else if (input.status === 'critico') res = res.filter(p => p.status === 'CRITICO');
        else if (input.status === 'atencao') res = res.filter(p => p.status === 'ATENCAO');
        else if (input.status === 'ok') res = res.filter(p => p.status === 'OK');
        const limite = Math.min(Number(input.limite) || 50, 200);
        return { total: res.length, produtos: res.slice(0, limite) };
      }

      case 'ver_historico': {
        const nomeBusca = sanitizeText(input.produto_nome, 120);
        const { prod, opcoes } = await acharProdutoUnico(nomeBusca);
        if (opcoes) return { erro: `Vários produtos batem com "${nomeBusca}". Pergunte qual: ${opcoes.slice(0, 8).map(p => `${p.nome} (${p.codigo || 's/cód'})`).join(', ')}` };
        if (!prod) return { erro: `Produto "${nomeBusca}" não encontrado` };
        const dias = Math.min(Number(input.dias) || 30, 365);
        const desde = dateAgoDias(dias);
        const { data: movs } = await supabase.from('movimentacoes')
          .select('tipo, qtd, unidade, motivo, responsavel, obs, created_at, qtd_antes, qtd_depois')
          .eq('produto_id', prod.id).gte('created_at', desde + 'T00:00:00-03:00')
          .order('id', { ascending: false }).limit(Math.min(Number(input.limite) || 20, 100));
        return { produto: prod.nome, qtd_atual: prod.qtd, unidade: prod.unidade, minimo: prod.minimo, periodo_dias: dias, movimentacoes: movs || [] };
      }

      case 'ver_movimentacoes': {
        let q = supabase.from('movimentacoes').select('produto_nome, categoria, tipo, qtd, unidade, motivo, responsavel, obs, created_at');
        if (input.hoje) {
          const hSP = dateSP();
          q = q.gte('created_at', hSP + 'T00:00:00-03:00').lte('created_at', hSP + 'T23:59:59-03:00');
        } else if (input.dias) {
          q = q.gte('created_at', dateAgoDias(Number(input.dias)) + 'T00:00:00-03:00');
        }
        if (input.tipo) q = q.eq('tipo', input.tipo);
        if (input.produto_nome) {
          const termoMov = sanitizeText(input.produto_nome, 100);
          const { produtos: provaveis } = await buscarProdutos(termoMov);
          if (provaveis.length) q = q.in('produto_id', provaveis.map(p => p.id));
          else q = q.ilike('produto_nome', `%${termoMov}%`);
        }
        const { data } = await q.order('id', { ascending: false }).limit(Math.min(Number(input.limite) || 50, 200));
        return { total: (data || []).length, movimentacoes: data || [] };
      }

      case 'ver_dashboard': {
        const { data: all } = await supabase.from('produtos').select('qtd, minimo, custo').or('ativo.eq.1,ativo.is.null');
        const prods = all || [];
        const zerados = prods.filter(p => Number(p.qtd) === 0).length;
        const criticos = prods.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5).length;
        const atencao = prods.filter(p => Number(p.qtd) > Number(p.minimo) * 0.5 && Number(p.qtd) < Number(p.minimo)).length;
        const valor = Number(prods.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0).toFixed(2));
        const hSP = dateSP();
        const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true }).gte('created_at', hSP + 'T00:00:00-03:00').lte('created_at', hSP + 'T23:59:59-03:00');
        const { data: ultimos } = await supabase.from('movimentacoes').select('produto_nome, tipo, qtd, unidade, responsavel, created_at').order('id', { ascending: false }).limit(5);
        return { total_produtos: prods.length, zerados, criticos, atencao, ok: prods.length - zerados - criticos - atencao, valor_total: valor, lancamentos_hoje: lancHoje || 0, ultimos_lancamentos: ultimos || [] };
      }

      case 'ver_realidade_dia': {
        if (user?.role !== 'admin') {
          let permsCol = null;
          try { const { data: u } = await supabase.from('users').select('permissoes').eq('id', user.id).single(); permsCol = u && u.permissoes; } catch(e) {}
          const perms = permsEfetivas(user?.role, permsCol);
          if (!perms.dia) return { erro: 'Acesso ao Dia/fechamento não liberado para este usuário.' };
        }
        const dataDia = input.data ? validarDataISO(input.data) : dateSP();
        const d = await montarRealidadeDia(dataDia);
        return {
          data: d.data,
          data_br: d.data_br,
          venda_lancada: d.venda_lancada,
          vendas: d.vendas,
          pratos_vendidos: d.pratos_vendidos,
          ticket_medio: d.ticket_medio,
          pagamentos: d.pagamentos,
          cortes: d.cortes,
          despesas_caixa: d.despesas,
          despesas_lista: d.despesas_lista,
          compras_estoque: d.compras_estoque,
          consumo_estoque: d.consumo_estoque,
          perdas: d.perdas,
          lucro_bruto_estimado: d.lucro_bruto_estimado,
          resultado_dia_estimado: d.resultado_dia_estimado,
          fluxo_caixa: d.fluxo_caixa,
          consumo_sobre_vendas_pct: d.consumo_sobre_vendas_pct,
          perdas_sobre_vendas_pct: d.perdas_sobre_vendas_pct,
          despesas_sobre_vendas_pct: d.despesas_sobre_vendas_pct,
          movimentos: {
            total: d.movimentos.total,
            entradas: d.movimentos.n_compras,
            saidas: d.movimentos.n_consumo,
            perdas: d.movimentos.n_perdas,
            ajustes: d.movimentos.n_ajustes,
            anomalias: d.movimentos.anomalias,
            perdas_itens: d.movimentos.perdas_itens,
          },
          comparativo_ontem: d.comparativo.ontem,
          configuracao_pendente: d.configuracao_pendente,
        };
      }

      case 'alertas_giro_parado': {
        const CATS = ['Hortifruti', 'Aves', 'Massa Fresca', 'Carnes Bovinas', 'Carnes Suínas', 'Pescados', 'Laticínios', 'Outras Proteínas', 'Bebidas'];
        const THR = { 'Hortifruti': 7, 'Aves': 7, 'Massa Fresca': 7, 'Carnes Bovinas': 10, 'Carnes Suínas': 10, 'Pescados': 10, 'Laticínios': 10, 'Outras Proteínas': 10, 'Bebidas': 15 };
        const { data: prods } = await supabase.from('produtos').select('id, nome, categoria, qtd, unidade').in('categoria', CATS).or('ativo.eq.1,ativo.is.null');
        const ids = (prods || []).map(p => p.id);
        if (!ids.length) return { total_alertas: 0, alertas: [] };
        const { data: movs } = await supabase.from('movimentacoes').select('produto_id, created_at').in('produto_id', ids).order('created_at', { ascending: false });
        const lastMov = {};
        for (const m of (movs || [])) { if (!lastMov[m.produto_id]) lastMov[m.produto_id] = m.created_at; }
        const alertas = [];
        for (const p of (prods || [])) {
          const thr = THR[p.categoria] || 10;
          const last = lastMov[p.id];
          const dias = last ? Math.floor((Date.now() - new Date(last).getTime()) / 86400000) : null;
          if (dias === null || dias >= thr) {
            alertas.push({ nome: p.nome, categoria: p.categoria, dias_parado: dias !== null ? dias : 'sem histórico', qtd: p.qtd, unidade: p.unidade, urgencia: dias === null ? 'SEM_HISTORICO' : dias >= thr * 2 ? 'CRITICO' : 'ATENCAO' });
          }
        }
        alertas.sort((a, b) => { const o = { SEM_HISTORICO: 0, CRITICO: 1, ATENCAO: 2 }; return o[a.urgencia] - o[b.urgencia]; });
        return { total_alertas: alertas.length, alertas };
      }

      case 'listar_categorias': {
        const { data } = await supabase.from('produtos').select('categoria, qtd, minimo, custo').or('ativo.eq.1,ativo.is.null');
        const catMap = {};
        for (const p of (data || [])) {
          if (!catMap[p.categoria]) catMap[p.categoria] = { total: 0, zerados: 0, criticos: 0, atencao: 0, ok: 0, valor: 0 };
          const c = catMap[p.categoria];
          c.total++;
          c.valor += Number(p.qtd) * Number(p.custo);
          const st = Number(p.qtd) === 0 ? 'zerados' : Number(p.qtd) <= Number(p.minimo) * 0.5 ? 'criticos' : Number(p.qtd) < Number(p.minimo) ? 'atencao' : 'ok';
          c[st]++;
        }
        return { categorias: Object.entries(catMap).sort((a, b) => a[0].localeCompare(b[0])).map(([cat, d]) => ({ categoria: cat, ...d, valor: Number(d.valor.toFixed(2)) })) };
      }

      case 'registrar_movimentacao': {
        const nomeBusca = sanitizeText(input.produto_nome, 120);
        const tipo = ['Entrada','Saída','Perda','Ajuste'].includes(input.tipo) ? input.tipo : null;
        if (!tipo) return { sucesso: false, erro: 'Tipo inválido. Use: Entrada, Saída, Perda ou Ajuste' };
        const qtd = tipo === 'Ajuste' ? parseNonNegativeNumber(input.qtd) : parsePositiveNumber(input.qtd);
        if (qtd === null) return { sucesso: false, erro: 'Quantidade inválida' };
        const { produtos: cands, via } = await buscarProdutos(nomeBusca);
        if (!cands.length) return { sucesso: false, erro: `Produto "${nomeBusca}" não encontrado. Use buscar_produto para ver o código/nome exato.` };
        if (cands.length > 1 && via === 'parcial') return { sucesso: false, ambiguo: true,
          erro: `"${nomeBusca}" casa com vários produtos — NÃO lance no chute. Pergunte qual (pelo código):`,
          opcoes: cands.map(p => ({ codigo: p.codigo, nome: p.nome, qtd: p.qtd, unidade: p.unidade })) };
        const { data: prod } = await supabase.from('produtos').select('*').eq('id', cands[0].id).single();
        if (!prod) return { sucesso: false, erro: `Produto "${nomeBusca}" não encontrado.` };
        // Trava otimista com retry — mesmo padrão do endpoint REST: dois comandos
        // simultâneos ao assistente não corrompem o estoque.
        let novaQtd, qtdAntes, custoUnit, valor, prodAtual = prod, sucesso = false;
        for (let tent = 0; tent < 4 && !sucesso; tent++) {
          qtdAntes = Number(prodAtual.qtd);
          if (tipo === 'Entrada') novaQtd = Number((qtdAntes + qtd).toFixed(3));
          else if (tipo === 'Saída' || tipo === 'Perda') {
            if (qtd > qtdAntes) return { sucesso: false, erro: `Estoque insuficiente: disponível ${prodAtual.qtd} ${prodAtual.unidade}` };
            novaQtd = Number((qtdAntes - qtd).toFixed(3));
          } else novaQtd = Number(qtd.toFixed(3));
          custoUnit = input.custo !== undefined ? (parseNonNegativeNumber(input.custo) || Number(prodAtual.custo || 0)) : Number(prodAtual.custo || 0);
          const valorBase = tipo === 'Ajuste' ? Math.abs(novaQtd - qtdAntes) : qtd;
          valor = Number((custoUnit * valorBase).toFixed(2));
          const updateData = { qtd: novaQtd };
          if (tipo === 'Entrada' && input.custo !== undefined) updateData.custo = custoUnit;
          const { data: upd } = await supabase.from('produtos').update(updateData).eq('id', prodAtual.id).eq('qtd', prodAtual.qtd).select('id');
          if (upd && upd.length) { sucesso = true; break; }
          const { data: re } = await supabase.from('produtos').select('*').eq('id', prod.id).single();
          if (!re) return { sucesso: false, erro: 'Erro ao atualizar estoque' };
          prodAtual = re;
        }
        if (!sucesso) return { sucesso: false, erro: 'Outro lançamento simultâneo alterou o estoque. Tente novamente.' };
        const { error: movErr } = await supabase.from('movimentacoes').insert({
          produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
          tipo, qtd: tipo === 'Ajuste' ? novaQtd : qtd, unidade: prod.unidade,
          custo: custoUnit, valor, motivo: sanitizeText(input.motivo || 'Via assistente IA', 80),
          responsavel: user && user.nome ? user.nome : 'IA', obs: 'Registrado pelo assistente IA',
          qtd_antes: qtdAntes, qtd_depois: novaQtd, created_at: nowSP(),
        });
        if (movErr) { await supabase.from('produtos').update({ qtd: qtdAntes }).eq('id', prod.id).eq('qtd', novaQtd); return { sucesso: false, erro: 'Erro ao registrar movimentação' }; }
        await audit('movimentacao_ia', { produto: prod.nome, tipo, qtd, nova_qtd: novaQtd }, user, '');
        return { sucesso: true, produto: prod.nome, tipo, qtd, qtd_antes: qtdAntes, qtd_depois: novaQtd, unidade: prod.unidade };
      }

      case 'atualizar_produto': {
        if (!['admin','gerente'].includes(user && user.role)) return { sucesso: false, erro: 'Permissão insuficiente. Requer gerente ou admin.' };
        const nomeBusca = sanitizeText(input.produto_nome, 120);
        const { prod, opcoes } = await acharProdutoUnico(nomeBusca);
        if (opcoes) return { sucesso: false, erro: `Vários produtos batem com "${nomeBusca}". Pergunte qual: ${opcoes.slice(0, 8).map(p => `${p.nome} (${p.codigo || 's/cód'})`).join(', ')}` };
        if (!prod) return { sucesso: false, erro: `Produto "${nomeBusca}" não encontrado` };
        const updates = {};
        if (input.custo !== undefined) { const c = parseNonNegativeNumber(input.custo); if (c !== null) updates.custo = c; }
        if (input.minimo !== undefined) { const m = parseNonNegativeNumber(input.minimo); if (m !== null) updates.minimo = m; }
        if (!Object.keys(updates).length) return { sucesso: false, erro: 'Nenhum campo válido para atualizar' };
        await supabase.from('produtos').update(updates).eq('id', prod.id);
        await audit('produto_update_ia', { produto: prod.nome, updates }, user, '');
        return { sucesso: true, produto: prod.nome, atualizacoes: updates };
      }

      case 'registrar_nota_agenda': {
        const tipo = ['observacao','melhoria','erro','alerta','elogio'].includes(input.tipo) ? input.tipo : 'observacao';
        const texto = sanitizeText(input.texto, 500);
        if (!texto) return { sucesso: false, erro: 'Texto é obrigatório' };
        const { error } = await supabase.from('ia_agenda').insert({
          tipo, texto,
          produto_nome: input.produto_nome ? sanitizeText(input.produto_nome, 120) : null,
          usuario_nome: user && user.nome ? user.nome : null, criado_em: nowSP()
        });
        if (error) return { sucesso: false, erro: error.message };
        return { sucesso: true, tipo, resumo: texto.slice(0, 60) };
      }

      case 'ver_agenda': {
        let q = supabase.from('ia_agenda').select('*');
        if (input.tipo) q = q.eq('tipo', input.tipo);
        const dias = Math.min(Number(input.dias) || 30, 365);
        q = q.gte('criado_em', dateAgoDias(dias));
        const { data } = await q.order('id', { ascending: false }).limit(Math.min(Number(input.limite) || 20, 100));
        return { total: (data || []).length, notas: data || [] };
      }

      default:
        return { erro: `Ferramenta desconhecida: ${nome}` };
    }
  } catch(e) {
    console.error(`Erro na ferramenta ${nome}:`, e.message);
    await logErroAgenda('ferramenta:' + nome, e, user);
    return { erro: `Erro interno: ${e.message}` };
  }
}

// Varredura automática (init): roda no MÁXIMO 1x por dia e SOMENTE para o admin.
// Resultado do dia fica em cache p/ não reprocessar a cada abertura da aba IA.
let varreduraCache = { dia: null, resposta: null };
app.post('/api/chat', auth, requirePerm('ia'), chatLimiter, async (req, res) => {
  let isInit = !!(req.body && req.body.init);
  const tsVarredura = nowSP();
  const forcar = !!(req.body && req.body.forcar);
  // Só o admin dispara a varredura automática; outros usuários não rodam análise ao abrir.
  if (isInit && req.user.role !== 'admin') {
    return res.json({ resposta: '', movimentos_executados: [], pulado: 'nao_admin' });
  }
  // Admin: usa o cache do dia SÓ se nada mudou desde que ele foi gerado.
  // (Antes ficava preso o dia todo: um inventário no meio do dia deixava o relatório defasado.)
  if (isInit && !forcar && varreduraCache.dia === dateSP() && varreduraCache.resposta && varreduraCache.geradoEm) {
    const { count } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true }).gt('created_at', varreduraCache.geradoEm);
    if (!count) return res.json({ resposta: varreduraCache.resposta, movimentos_executados: [], cache: true });
  }
  const pergunta = isInit ? null : String((req.body && req.body.pergunta) || '').replace(/[^\S\n]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim().slice(0, 8000);
  const historico = Array.isArray(req.body && req.body.historico) ? req.body.historico.slice(-10) : [];
  if (!isInit && !pergunta) return res.status(400).json({ erro: 'Pergunta não informada.' });
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(500).json({ erro: 'API não configurada.' });

  const bootExtra = isInit
    ? '\n\nMODO VARREDURA AUTOMÁTICA: O usuário acabou de abrir o assistente. Faça AGORA uma varredura chamando em sequência: ver_dashboard, ver_movimentacoes (hoje=true), alertas_giro_parado, ver_agenda. Monte um relatório de status seguindo o FORMATO DAS RESPOSTAS acima: comece com o bloco 📊 Resumo do estoque; depois "⚠️ Precisa de atenção" (zerados/críticos/giro parado, máx ~10 itens); depois "📥 Movimentos de hoje" (resumo, não lista tudo); e "📝 Agenda" (1-3 notas mais recentes). Máximo 20 linhas, texto puro, sem markdown. Não peça permissão — execute agora.'
    : '';

  const systemPrompt = 'Você é o assistente de estoque do restaurante "Toca do Coelho" em São Gonçalo, Rio de Janeiro.\n' +
    'Você é o CÉREBRO do sistema — não só responde, você INTERPRETA o pedido, decide, registra e melhora.\n\n' +
    'Data/hora: ' + nowSP() + '. Usuário: ' + req.user.nome + ' (' + req.user.role + ').\n\n' +
    'ENTENDER A PERGUNTA (o usuário fala rápido, por voz ou digitando errado — interprete a INTENÇÃO):\n' +
    '- Corrija mentalmente erros de digitação, abreviações, gírias, falta de acento e texto ditado por voz.\n' +
    '  Ex.: "qto tem de file" = quanto tem de filé · "ta zerado oq" = o que está zerado · "lanca 5 cebola" = registrar saída de 5 de cebola · "compras" / "oq comprar" = o que precisa repor · "resumo" / "como ta o estoque" = dashboard geral.\n' +
    '- Nome de produto quase sempre vem incompleto ou sem acento. SEMPRE use buscar_produto/listar_produtos com o pedaço do nome ANTES de dizer que não achou.\n' +
    '- Cada produto tem um CÓDIGO único (ex.: BOV-01, PES-03). buscar_produto aceita código, apelido ou nome. Quando o usuário der um código, use-o — é identificação exata. Sempre que listar/confirmar um produto, mostre o código junto do nome (ex.: "BOV-06 Contra Filé").\n' +
    '- buscar_produto retorna "via" e "ambiguo". Se via=codigo/apelido/nome_exato → é o produto CERTO, pode seguir. Se ambiguo=true (vários no parcial) → NUNCA escolha sozinho: liste as opções COM o código e pergunte qual (cuidado com variações que mudam tudo: zero/normal, posta/lascas, com maminha/pura).\n' +
    '- Se a busca trouxer vários parecidos, NÃO chute: liste as opções numeradas (com código) e pergunte qual. Só peça esclarecimento quando for realmente ambíguo — se dá pra entender, responda direto.\n' +
    '- Perguntas curtas (ex.: "e o frango?") devem ser entendidas no contexto do histórico da conversa.\n\n' +
    'COMO AGIR:\n' +
    '1. Responda SEMPRE em português brasileiro, direto e curto. Nada de repetir a pergunta nem enrolar.\n' +
    '2. Todo número (qtd, custo, valor, lançamentos de hoje) vem SEMPRE de uma chamada de ferramenta FEITA AGORA. NUNCA invente e NUNCA reaproveite números citados antes nesta conversa nem de relatórios anteriores — o estoque muda o tempo todo e aquilo já pode estar velho. Se perguntarem "o que mexeu hoje", chame ver_movimentacoes(hoje=true) na hora; se perguntarem saldo, chame buscar_produto na hora; se perguntarem lucro, vendas, pratos, despesas, perdas do dia, movimento do caixa, fechamento ou realidade do dia, chame ver_realidade_dia.\n' +
    '2b. CONFERIR UMA LISTA (comparar o que o usuário mandou com o estoque/movimentos): vá item por item, SEMPRE consultando a ferramenta para cada um. NÃO confie na memória nem em respostas anteriores. Se a lista for grande, confira em blocos e diga quantos faltam. Quando um nome não casar exatamente, busque e pergunte em vez de chutar.\n' +
    '2c. QUANDO O USUÁRIO MANDAR VÁRIOS ITENS/LINHAS DE UMA VEZ: trate cada linha como um item separado, mantenha a MESMA ORDEM que ele enviou, responda um item por linha e não junte itens diferentes nem pule nenhum. Se vier um texto longo, não resuma misturando — preserve a estrutura do que foi enviado.\n' +
    '3. Seja proativo: ao buscar, se notar algo grave (zerado urgente, giro parado, anomalia), avise e registre na agenda.\n' +
    '4. Antes de registrar movimentação, confirme produto + quantidade + tipo (salvo se já estiver claro). Depois, mostre o NOVO saldo.\n' +
    '5. Ao terminar uma tarefa, diga em 1 linha o que foi feito.\n\n' +
    'FORMATO DAS RESPOSTAS (o app FORMATA automaticamente: títulos, listas e valores ganham cor e destaque — escreva organizado em blocos):\n' +
    '- Você PODE usar **negrito** para destacar nomes/títulos. Use "• " no começo de cada item de lista. Deixe UMA linha em branco entre blocos. NÃO use # nem tabelas.\n' +
    '- Status por emoji: 🔴 zerado · 🟠 crítico · 🟡 atenção · 🟢 ok. Dinheiro sempre R$ 0,00. Quantidade com a unidade (kg, un, L).\n' +
    '- Título curto com emoji na 1ª linha. Itens em linhas começando com "• ". Uma linha em branco entre blocos.\n' +
    '- Consulta de 1 produto:\n' +
    '  📦 Filé de Frango\n' +
    '  • Estoque: 12 kg  (mínimo 8 kg)  🟢 OK\n' +
    '  • Custo: R$ 18,00/kg  •  Em estoque: R$ 216,00\n' +
    '- Resumo geral / dashboard:\n' +
    '  📊 Resumo do estoque\n' +
    '  • 285 produtos  •  Valor total: R$ 12.340,00\n' +
    '  🔴 Zerados 4   🟠 Críticos 7   🟡 Atenção 12   🟢 OK 262\n' +
    '  • Lançamentos hoje: 9\n' +
    '- Listas (zerados / críticos / compras): máx ~15 itens no formato "• Nome — 0 kg (mín 5)"; se houver mais, termine com "…e mais N". Agrupe por categoria quando ajudar.\n' +
    '- Confirmação de lançamento:\n' +
    '  ✅ Saída registrada: 5 kg de Cebola\n' +
    '  • Novo saldo: 7 kg\n' +
    '- Feche com 1 recomendação SÓ quando fizer diferença (ex.: "👉 Repor hoje: Coca Zero e Filé").\n\n' +
    'AGENDA — registre com registrar_nota_agenda quando:\n' +
    '- Quantidade lançada muito alta (possível erro) → alerta\n' +
    '- Produto crítico/zerado há muitos dias → alerta\n' +
    '- Sugestão de melhoria no processo → melhoria\n' +
    '- Erro do sistema detectado → erro\n' +
    '- Observação importante do dia → observacao' +
    bootExtra;

  try {
    const messages = [
      ...historico.map(h => ({ role: h.role, content: h.content })),
      { role: 'user', content: isInit ? 'Faça a varredura automática do sistema agora.' : pergunta }
    ];

    let movimentosExecutados = [];
    let textoFinal = '';
    const MAX_ITER = 12;

    for (let iter = 0; iter < MAX_ITER; iter++) {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        // Sonnet 4.6: modelo forte — o assistente precisa de QUALIDADE de raciocínio, não só
        // velocidade. (O timeout do celular na conferência é tratado à parte, sem trocar o modelo.)
        body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 4096, system: systemPrompt, tools: IA_TOOLS, messages })
      });

      if (!response.ok) {
        const errBody = (await response.text()).slice(0, 500);
        console.error('Anthropic API error [chat]:', response.status, errBody);
        return res.status(502).json({ erro: 'Erro na API (' + response.status + '): ' + errBody });
      }

      const data = await response.json();
      messages.push({ role: 'assistant', content: data.content });

      if (data.stop_reason !== 'tool_use') {
        textoFinal = data.content.filter(b => b.type === 'text').map(b => b.text).join('').trim();
        break;
      }

      const toolResults = [];
      for (const block of data.content.filter(b => b.type === 'tool_use')) {
        const resultado = await executarFerramenta(block.name, block.input || {}, req.user);
        if (block.name === 'registrar_movimentacao' && resultado.sucesso) movimentosExecutados.push(resultado);
        toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: JSON.stringify(resultado) });
      }
      messages.push({ role: 'user', content: toolResults });
    }

    if (isInit) varreduraCache = { dia: dateSP(), resposta: textoFinal, geradoEm: tsVarredura };
    await audit('chat_ia', { pergunta: isInit ? '__boot__' : pergunta.slice(0, 100), lancamentos: movimentosExecutados.length }, req.user, getClientIp(req));
    res.json({ resposta: textoFinal, movimentos_executados: movimentosExecutados });
  } catch(e) {
    console.error('Erro chat:', e);
    await logErroAgenda('chat', e, req.user);
    res.status(500).json({ erro: 'Erro no assistente. Tente novamente em instantes.' });
  }
});

// ==================== AGENDA IA ====================
app.get('/api/agenda', auth, async (req, res) => {
  const tipo = sanitizeText(req.query && req.query.tipo || '', 20);
  const dias = Math.min(Math.max(parseInt((req.query && req.query.dias) || '30', 10), 1), 365);
  const limite = Math.min(Math.max(parseInt((req.query && req.query.limite) || '50', 10), 1), 200);
  const desde = dateAgoDias(dias);
  let query = supabase.from('ia_agenda').select('*').gte('criado_em', desde);
  if (tipo && ['observacao','melhoria','erro','alerta','elogio'].includes(tipo)) query = query.eq('tipo', tipo);
  query = query.order('id', { ascending: false }).limit(limite);
  const { data } = await query;
  res.json(data || []);
});

// ==================== ALERTAS ====================
app.get('/api/alertas/estoque-parado', auth, async (req, res) => {
  try {
    const { data: produtos } = await supabase.from('produtos').select('id, nome, categoria, qtd, unidade, minimo, grupo_troca').or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    const ids = (produtos || []).map(p => p.id);
    if (!ids.length) return res.json({ alertas: [], resumo: { total: 0, criticos: 0, atencao: 0, sem_historico: 0 } });
    const { data: todosMov } = await supabase.from('movimentacoes').select('produto_id, created_at, tipo, responsavel').in('produto_id', ids).order('created_at', { ascending: false });
    const lastMovMap = {};
    for (const m of (todosMov || [])) { if (!lastMovMap[m.produto_id]) lastMovMap[m.produto_id] = m; }
    // Último movimento por GRUPO de troca: irmão girando = grupo vivo, não alarma os outros.
    const lastGrupoMov = {};
    for (const p of (produtos || [])) {
      if (p.grupo_troca && lastMovMap[p.id]) {
        const t = new Date(lastMovMap[p.id].created_at).getTime();
        if (!lastGrupoMov[p.grupo_troca] || t > lastGrupoMov[p.grupo_troca]) lastGrupoMov[p.grupo_troca] = t;
      }
    }
    const agora = Date.now();
    const alertas = [];
    let silenciadosPorGrupo = 0;
    for (const p of (produtos || [])) {
      const thDias = THRESHOLDS_ALERTA[p.categoria] || THRESHOLD_PADRAO;
      const lastMov = lastMovMap[p.id];
      const diasParado = lastMov ? Math.floor((agora - new Date(lastMov.created_at).getTime()) / 86400000) : null;
      if (diasParado === null || diasParado >= thDias) {
        if (p.grupo_troca && lastGrupoMov[p.grupo_troca] && (agora - lastGrupoMov[p.grupo_troca]) < thDias * 86400000) {
          silenciadosPorGrupo++; continue; // substituto do grupo em uso — rotativo, não parado
        }
        const urgencia = diasParado === null ? 'SEM_HISTORICO' : diasParado >= thDias * 2 ? 'CRITICO' : 'ATENCAO';
        alertas.push({ produto_id: p.id, nome: p.nome, categoria: p.categoria, qtd: p.qtd, unidade: p.unidade,
          dias_parado: diasParado, ultimo_movimento: lastMov?.created_at || null,
          ultimo_responsavel: lastMov?.responsavel || null, threshold_dias: thDias, urgencia, grupo_troca: p.grupo_troca || null });
      }
    }
    alertas.sort((a, b) => { const o = { SEM_HISTORICO: 0, CRITICO: 1, ATENCAO: 2 };
      return o[a.urgencia] !== o[b.urgencia] ? o[a.urgencia] - o[b.urgencia] : (b.dias_parado||999) - (a.dias_parado||999); });
    const resumo = { total: alertas.length,
      criticos: alertas.filter(a => a.urgencia === 'CRITICO').length,
      atencao: alertas.filter(a => a.urgencia === 'ATENCAO').length,
      sem_historico: alertas.filter(a => a.urgencia === 'SEM_HISTORICO').length,
      silenciados_por_grupo: silenciadosPorGrupo };
    await audit('alertas_estoque_parado', resumo, req.user, getClientIp(req));
    res.json({ alertas, resumo });
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

app.get('/api/alertas/fantasmas', auth, async (req, res) => {
  try {
    const { data: produtos } = await supabase.from('produtos')
      .select('id, nome, categoria, qtd, unidade')
      .or('ativo.eq.1,ativo.is.null')
      .eq('qtd', 0)
      .order('categoria').order('nome');
    const ids = (produtos || []).map(p => p.id);
    if (!ids.length) return res.json({ fantasmas: [] });
    const movs = await fetchTodas(() => supabase.from('movimentacoes')
      .select('produto_id, tipo, qtd, obs, created_at, responsavel')
      .in('produto_id', ids)
      .order('created_at', { ascending: true }).order('id', { ascending: true }));
    // Reconstrói o saldo CRONOLOGICAMENTE: Entrada soma, Saída/Perda subtrai e
    // Ajuste DEFINE o saldo absoluto (coluna qtd = novo valor). Assim funciona
    // mesmo nos Ajustes antigos sem qtd_antes/qtd_depois (que eram null).
    const movByProd = {};
    for (const m of (movs || [])) {
      if (!movByProd[m.produto_id]) movByProd[m.produto_id] = { entradas: 0, saidas: 0, bal: 0, contagemDown: 0, nAjuste: 0, ultimo: null, ultimo_responsavel: null };
      const g = movByProd[m.produto_id];
      const q = Number(m.qtd) || 0;
      if (m.tipo === 'Entrada') { g.entradas += q; g.bal += q; }
      else if (m.tipo === 'Saída' || m.tipo === 'Perda') { g.saidas += q; g.bal -= q; }
      else if (m.tipo === 'Ajuste') {
        g.nAjuste++;
        const reducao = g.bal - q;                       // quanto a contagem tirou
        // Ajuste de sincronização (reset) ou de inventário já é contabilizado — não é sumiço.
        if (reducao > 0.001 && m.obs !== 'sincronização automática' && m.obs !== 'inventario') g.contagemDown += reducao;
        g.bal = q;                                        // Ajuste define o saldo
      }
      g.ultimo = m.created_at; g.ultimo_responsavel = m.responsavel;   // ascendente: último fica no fim
    }
    // Conferência cruzada: compara o saldo reconstruído com a qtd real e classifica.
    const fantasmas = [];
    for (const p of (produtos || [])) {
      const h = movByProd[p.id];
      if (!h || h.entradas === 0) continue;            // nunca teve entrada: não é fantasma
      const balHist = Number(h.bal.toFixed(3));
      const desyncGap = Number((Number(p.qtd) - balHist).toFixed(3));   // p.qtd é 0 aqui
      let classe, label, explica;
      if (Math.abs(desyncGap) > 0.001) {
        // O histórico fecha com saldo, mas o estoque está 0: a qtd foi mexida POR FORA
        // do log (reset/importação antiga) — é dado furado, não consumo.
        classe = 'desync'; label = '🟡 dado furado';
        explica = `o histórico fecha em ${balHist} ${p.unidade}, mas o estoque está 0 — foi zerado por fora do app (reset/importação antiga), não por uso`;
      } else if (h.contagemDown > 0.001 && h.saidas === 0) {
        // Zerado por contagem/Ajuste sem nenhuma saída lançada: pode ser uso, perda ou erro.
        classe = 'sumico'; label = '🔴 zerado sem baixa';
        explica = `a contagem zerou ${Number(h.contagemDown.toFixed(3))} ${p.unidade} sem saída lançada — confirme se foi uso, perda ou erro de lançamento`;
      } else {
        continue;                                       // explicado por saída normal
      }
      fantasmas.push({ produto_id: p.id, nome: p.nome, categoria: p.categoria, unidade: p.unidade,
        total_entradas: Number(h.entradas.toFixed(3)), total_saidas: Number(h.saidas.toFixed(3)),
        ajustes: h.nAjuste, saldo_historico: balHist, classe, label, explica,
        ultimo_movimento: h.ultimo, ultimo_responsavel: h.ultimo_responsavel });
    }
    const ordem = { sumico: 0, desync: 1 };
    fantasmas.sort((a, b) => (ordem[a.classe] - ordem[b.classe]) || (new Date(b.ultimo_movimento) - new Date(a.ultimo_movimento)));
    res.json({ fantasmas });
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

// Reconcilia "dado furado": grava um Ajuste corretivo que alinha o histórico ao
// estoque real (qtd não muda) — assim o item para de reaparecer na conferência.
// É a "memória" da conferência: o que foi reconciliado uma vez não volta inocente.
app.post('/api/alertas/fantasmas/reconciliar', auth, requireRole('admin', 'gerente'), async (req, res) => {
  try {
    const alvoId = req.body?.produto_id ? Number(req.body.produto_id) : null;
    let q = supabase.from('produtos').select('id, nome, categoria, qtd, unidade, custo')
      .or('ativo.eq.1,ativo.is.null').eq('qtd', 0);
    if (alvoId) q = q.eq('id', alvoId);
    const { data: produtos } = await q;
    const ids = (produtos || []).map(p => p.id);
    if (!ids.length) return res.json({ reconciliados: 0 });
    const movs = await fetchTodas(() => supabase.from('movimentacoes')
      .select('produto_id, tipo, qtd, obs, created_at').in('produto_id', ids)
      .order('created_at', { ascending: true }).order('id', { ascending: true }));
    const agg = {};
    for (const m of (movs || [])) {
      if (!agg[m.produto_id]) agg[m.produto_id] = { entradas: 0, bal: 0 };
      const g = agg[m.produto_id];
      const q = Number(m.qtd) || 0;
      if (m.tipo === 'Entrada') { g.entradas += q; g.bal += q; }
      else if (m.tipo === 'Saída' || m.tipo === 'Perda') g.bal -= q;
      else if (m.tipo === 'Ajuste') g.bal = q;            // Ajuste define o saldo (robusto a null)
    }
    let reconciliados = 0;
    for (const p of (produtos || [])) {
      const g = agg[p.id];
      if (!g || g.entradas === 0) continue;
      const saldoHist = Number(g.bal.toFixed(3));
      if (Math.abs(Number(p.qtd) - saldoHist) <= 0.001) continue;   // já fecha — não é dado furado
      const custoUnit = Number(p.custo || 0);
      const gap = Number((Number(p.qtd) - saldoHist).toFixed(3));   // acerto necessário
      // Ajuste corretivo: alinha o histórico ao estoque real. A qtd não muda.
      await supabase.from('movimentacoes').insert({
        produto_id: p.id, produto_nome: p.nome, categoria: p.categoria,
        tipo: 'Ajuste', qtd: Number(p.qtd), unidade: p.unidade,
        custo: custoUnit, valor: Number((custoUnit * Math.abs(gap)).toFixed(2)),
        motivo: 'Reconciliação (acerto de histórico)', responsavel: req.user.nome,
        obs: 'sincronização automática',
        qtd_antes: saldoHist, qtd_depois: Number(p.qtd), created_at: nowSP(),
      });
      reconciliados++;
    }
    await audit('reconciliar_fantasmas', { reconciliados, alvo: alvoId || 'todos' }, req.user, getClientIp(req));
    res.json({ reconciliados });
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

// ==================== INVENTÁRIO SEMANAL ====================
// Abre um inventário (foto do estoque) — geral ou de uma categoria. Captura, por
// item, a qtd que o sistema acha e há quantos dias está parado (sem movimento).
app.post('/api/inventario/abrir', auth, requireRole('admin', 'gerente'), async (req, res) => {
  try {
    const categoria = sanitizeText(req.body?.categoria || '', 80) || null;
    const { data: aberto } = await supabase.from('inventarios').select('id, categoria').eq('status', 'aberto').limit(1);
    if (aberto && aberto.length) return res.status(400).json({ erro: `Já existe um inventário aberto (${aberto[0].categoria || 'geral'}). Feche-o antes de abrir outro.` });
    let pq = supabase.from('produtos').select('id, nome, categoria, unidade, qtd, custo').or('ativo.eq.1,ativo.is.null');
    if (categoria) pq = pq.eq('categoria', categoria);
    const { data: produtos } = await pq.order('categoria').order('nome');
    if (!produtos || !produtos.length) return res.status(400).json({ erro: 'Nenhum produto encontrado para inventariar.' });
    const ids = produtos.map(p => p.id);
    const { data: movs } = await supabase.from('movimentacoes').select('produto_id, created_at').in('produto_id', ids).order('created_at', { ascending: false });
    const ultimo = {};
    for (const m of (movs || [])) { if (!ultimo[m.produto_id]) ultimo[m.produto_id] = m.created_at; }
    const agora = Date.now();
    const { data: inv, error: invErr } = await supabase.from('inventarios')
      .insert({ data: dateSP(), categoria, status: 'aberto', responsavel: req.user.nome, total_itens: produtos.length, criado_em: nowSP() })
      .select().single();
    if (invErr) return res.status(500).json({ erro: 'Erro ao abrir inventário.' });
    const itens = produtos.map(p => {
      const last = ultimo[p.id];
      const dias = last ? Math.floor((agora - new Date(last).getTime()) / 86400000) : null;
      return { inventario_id: inv.id, produto_id: p.id, produto_nome: p.nome, categoria: p.categoria,
        unidade: p.unidade, custo: Number(p.custo || 0), qtd_sistema: Number(p.qtd), qtd_contada: null,
        dias_parado: dias };
    });
    for (let i = 0; i < itens.length; i += 200) await supabase.from('inventario_itens').insert(itens.slice(i, i + 200));
    await audit('inventario_abrir', { inventario_id: inv.id, categoria, total: produtos.length }, req.user, getClientIp(req));
    res.json({ ok: true, inventario: inv, total_itens: produtos.length });
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

// Retorna o inventário aberto (se houver) com seus itens para contagem.
app.get('/api/inventario/aberto', auth, async (req, res) => {
  try {
    const { data: inv } = await supabase.from('inventarios').select('*').eq('status', 'aberto').order('id', { ascending: false }).limit(1).maybeSingle();
    if (!inv) return res.json({ inventario: null });
    const { data: itens } = await supabase.from('inventario_itens').select('*').eq('inventario_id', inv.id).order('categoria').order('produto_nome');
    res.json({ inventario: inv, itens: itens || [] });
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

// Salva contagens parciais (a equipe vai preenchendo). Não altera estoque ainda.
app.post('/api/inventario/contar', auth, async (req, res) => {
  try {
    const invId = Number(req.body?.inventario_id);
    const itens = Array.isArray(req.body?.itens) ? req.body.itens : [];
    if (!invId || !itens.length) return res.status(400).json({ erro: 'Dados de contagem inválidos.' });
    const { data: inv } = await supabase.from('inventarios').select('id, status').eq('id', invId).maybeSingle();
    if (!inv || inv.status !== 'aberto') return res.status(400).json({ erro: 'Inventário não está aberto.' });
    let salvos = 0;
    for (const it of itens) {
      const pid = Number(it.produto_id);
      const q = it.qtd_contada === null || it.qtd_contada === '' ? null : parseNonNegativeNumber(it.qtd_contada);
      if (!pid) continue;
      await supabase.from('inventario_itens').update({ qtd_contada: q }).eq('inventario_id', invId).eq('produto_id', pid);
      salvos++;
    }
    res.json({ ok: true, salvos });
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

// Fecha o inventário: aplica a contagem como verdade (Ajustes marcados obs='inventario'),
// categoriza divergências, levanta os "parados suspeitos" (consta mas não foi contado e
// não se mexe) e grava o log na agenda.
app.post('/api/inventario/fechar', auth, requireRole('admin', 'gerente'), async (req, res) => {
  try {
    const invId = Number(req.body?.inventario_id);
    const causas = (req.body && typeof req.body.causas === 'object') ? req.body.causas : {};
    const { data: inv } = await supabase.from('inventarios').select('*').eq('id', invId).maybeSingle();
    if (!inv || inv.status !== 'aberto') return res.status(400).json({ erro: 'Inventário não está aberto.' });
    const { data: itens } = await supabase.from('inventario_itens').select('*').eq('inventario_id', invId);
    const dataBR = (inv.data || dateSP()).split('-').reverse().join('/');
    let divergentes = 0, suspeitos = 0, valorSumico = 0, valorSobra = 0;
    const topSumico = [], suspeitosList = [], errosLanc = [];

    for (const it of (itens || [])) {
      const sistema = Number(it.qtd_sistema);
      const custo = Number(it.custo || 0);
      const thr = THRESHOLDS_ALERTA[it.categoria] || THRESHOLD_PADRAO;
      const parado = it.dias_parado !== null && it.dias_parado >= thr;

      if (it.qtd_contada === null) {
        // Não contado: NUNCA zera (pode só não ter sido verificado). Se ainda consta
        // com estoque, entra na lista "a verificar" e gera alerta pedindo a conferência.
        if (sistema > 0) {
          suspeitos++;
          suspeitosList.push({ produto_id: it.produto_id, nome: it.produto_nome, categoria: it.categoria,
            qtd_sistema: sistema, unidade: it.unidade, dias_parado: it.dias_parado, parado });
          await supabase.from('inventario_itens').update({ causa: 'nao_contado',
            obs: parado ? `não contado · parado ${it.dias_parado}d — verificar` : 'não contado — verificar' }).eq('id', it.id);
        } else {
          await supabase.from('inventario_itens').update({ causa: 'nao_contado' }).eq('id', it.id);
        }
        continue;
      }

      const contada = Number(it.qtd_contada);
      const div = Number((contada - sistema).toFixed(3));
      const valorDiv = Number((Math.abs(div) * custo).toFixed(2));
      let causa = sanitizeText(causas[it.produto_id] || '', 20);
      if (!causa) causa = div < 0 ? 'sumico' : div > 0 ? 'sobra' : 'ok';

      if (Math.abs(div) > 0.001) {
        await aplicarAjusteInventario(it, contada, inv, req.user.nome, causa);
        divergentes++;
        if (div < 0) { valorSumico += valorDiv; topSumico.push({ nome: it.produto_nome, qtd: Math.abs(div), valor: valorDiv }); }
        else valorSobra += valorDiv;
        if (causa === 'erro_lancamento') errosLanc.push({ nome: it.produto_nome, div, unidade: it.unidade });
      }
      await supabase.from('inventario_itens').update({ qtd_contada: contada, divergencia: div, valor_divergencia: valorDiv, causa }).eq('id', it.id);
    }

    await supabase.from('inventarios').update({ status: 'fechado', fechado_em: nowSP(),
      itens_contados: (itens || []).filter(i => i.qtd_contada !== null).length,
      itens_divergentes: divergentes, itens_suspeitos: suspeitos,
      valor_sumico: Number(valorSumico.toFixed(2)), valor_sobra: Number(valorSobra.toFixed(2)) }).eq('id', invId);

    // Log na agenda — observação (resumo), erro (erros de lançamento) e alerta (a verificar).
    topSumico.sort((a, b) => b.valor - a.valor);
    // Itens a verificar: parados primeiro, depois maior tempo parado.
    suspeitosList.sort((a, b) => (Number(b.parado) - Number(a.parado)) || ((b.dias_parado||0) - (a.dias_parado||0)));
    const resumoTxt = `Inventário ${dataBR}${inv.categoria ? ' ('+inv.categoria+')' : ''} fechado por ${req.user.nome}: ` +
      `${(itens||[]).filter(i=>i.qtd_contada!==null).length}/${(itens||[]).length} contados, ${divergentes} divergências, ` +
      `R$ ${valorSumico.toFixed(2)} sumido, R$ ${valorSobra.toFixed(2)} sobra, ${suspeitos} a verificar.` +
      (topSumico.length ? ` Top sumiço: ${topSumico.slice(0,5).map(t=>`${t.nome} (R$${t.valor.toFixed(2)})`).join(', ')}.` : '');
    await supabase.from('ia_agenda').insert({ tipo: 'observacao', texto: resumoTxt.slice(0, 500), usuario_nome: req.user.nome, criado_em: nowSP() });
    if (errosLanc.length) await supabase.from('ia_agenda').insert({ tipo: 'erro',
      texto: `Inventário ${dataBR}: ${errosLanc.length} erro(s) de lançamento detectado(s): ${errosLanc.slice(0,8).map(e=>`${e.nome} (${e.div>0?'+':''}${e.div} ${e.unidade})`).join(', ')}.`.slice(0,500),
      usuario_nome: req.user.nome, criado_em: nowSP() });
    if (suspeitosList.length) await supabase.from('ia_agenda').insert({ tipo: 'alerta',
      texto: `Inventário ${dataBR}: ${suspeitosList.length} item(ns) constam no estoque mas NÃO foram contados — solicite verificação (varredura), o estoque deles foi mantido: ${suspeitosList.slice(0,8).map(s=>`${s.nome} (${s.qtd_sistema} ${s.unidade}${s.parado?', parado '+s.dias_parado+'d':''})`).join(', ')}.`.slice(0,500),
      usuario_nome: req.user.nome, criado_em: nowSP() });

    await audit('inventario_fechar', { inventario_id: invId, divergentes, suspeitos, valor_sumico: valorSumico }, req.user, getClientIp(req));
    res.json({ ok: true, divergentes, suspeitos, valor_sumico: Number(valorSumico.toFixed(2)),
      valor_sobra: Number(valorSobra.toFixed(2)), top_sumico: topSumico.slice(0, 10), suspeitos_lista: suspeitosList });
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

// Aplica a contagem de um item como Ajuste rastreável (obs='inventario'): a conferência
// reconhece esse ajuste como "acertado no inventário", não como sumiço misterioso.
// Race condition corrigida: o qtd_antes do log usa a quantidade ATUAL do produto (lida
// agora), não o qtd_sistema capturado na abertura — movimentos feitos DURANTE a contagem
// (saída da cozinha, entrada de compra) ficam com log correto e não inflam o "sumiço".
async function aplicarAjusteInventario(item, novaQtd, inv, responsavel, causa) {
  const alvo = Number(Number(novaQtd).toFixed(3));
  const custo = Number(item.custo || 0);
  // Lê a quantidade atual (a contagem física é a verdade, mas o log precisa do valor real de antes).
  const { data: prodAtual } = await supabase.from('produtos').select('qtd').eq('id', item.produto_id).maybeSingle();
  const antes = prodAtual ? Number(prodAtual.qtd) : Number(item.qtd_sistema);
  if (Math.abs(antes - Number(item.qtd_sistema)) > 0.001) {
    console.warn(`⚠️ Inventário #${inv.id}: "${item.produto_nome}" mudou durante a contagem (abertura: ${item.qtd_sistema}, agora: ${antes}). Ajuste aplicado com base no valor atual.`);
  }
  await supabase.from('produtos').update({ qtd: alvo }).eq('id', item.produto_id);
  await supabase.from('movimentacoes').insert({
    produto_id: item.produto_id, produto_nome: item.produto_nome, categoria: item.categoria,
    tipo: 'Ajuste', qtd: alvo, unidade: item.unidade,
    custo, valor: Number((custo * Math.abs(alvo - antes)).toFixed(2)),
    motivo: `Inventário #${inv.id} (${inv.data})${causa ? ' — ' + causa : ''}`,
    responsavel: responsavel || 'Inventário', obs: 'inventario',
    qtd_antes: antes, qtd_depois: alvo, created_at: nowSP(),
  });
}

// Histórico de inventários fechados (para tendência semana a semana).
app.get('/api/inventario/historico', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('inventarios').select('*').order('id', { ascending: false }).limit(30);
    res.json(data || []);
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

// Detalhe de um inventário (itens + divergências).
app.get('/api/inventario/:id', auth, async (req, res) => {
  try {
    const { data: inv } = await supabase.from('inventarios').select('*').eq('id', req.params.id).maybeSingle();
    if (!inv) return res.status(404).json({ erro: 'Inventário não encontrado.' });
    const { data: itens } = await supabase.from('inventario_itens').select('*').eq('inventario_id', inv.id).order('valor_divergencia', { ascending: true });
    res.json({ inventario: inv, itens: itens || [] });
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

// Edita a causa/obs de um item já inventariado (classificar a divergência depois do fechamento).
const CAUSAS_VALIDAS = ['sumico','perda','erro_lancamento','roubo','sobra','ok','nao_contado'];
app.put('/api/inventario/item/:id', auth, requireRole('admin', 'gerente'), async (req, res) => {
  try {
    const causa = sanitizeText(req.body?.causa || '', 20);
    if (causa && !CAUSAS_VALIDAS.includes(causa)) return res.status(400).json({ erro: 'Causa inválida.' });
    const obs = req.body?.obs !== undefined ? sanitizeText(req.body.obs, 200) : undefined;
    const { data: item } = await supabase.from('inventario_itens').select('*').eq('id', req.params.id).maybeSingle();
    if (!item) return res.status(404).json({ erro: 'Item não encontrado.' });
    const upd = {}; if (causa) upd.causa = causa; if (obs !== undefined) upd.obs = obs;
    await supabase.from('inventario_itens').update(upd).eq('id', item.id);
    // Se reclassificou como erro de lançamento, registra na agenda (log de erros).
    if (causa === 'erro_lancamento') {
      await supabase.from('ia_agenda').insert({ tipo: 'erro',
        texto: `Erro de lançamento confirmado no inventário: ${item.produto_nome} (divergência ${item.divergencia} ${item.unidade}).`.slice(0, 500),
        produto_nome: item.produto_nome, usuario_nome: req.user.nome, criado_em: nowSP() });
    }
    await audit('inventario_item_causa', { item_id: item.id, produto: item.produto_nome, causa }, req.user, getClientIp(req));
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ erro: 'Erro interno. Tente novamente ou fale com o administrador.' }); }
});

// ==================== GERENCIAR USUÁRIOS ====================
app.get('/api/users', auth, requireRole('admin'), async (req, res) => {
  const { data } = await supabase.from('users').select('id, username, nome, role, active, created_at, permissoes').order('role').order('nome');
  const out = (data || []).map(u => ({ ...u, permissoes_efetivas: permsEfetivas(u.role, u.permissoes) }));
  res.json(out);
});

app.post('/api/users', auth, requireRole('admin'), async (req, res) => {
  const username = sanitizeText(req.body?.username, 40).toLowerCase();
  const nome = sanitizeText(req.body?.nome, 60);
  const role = sanitizeText(req.body?.role, 20);
  const password = String(req.body?.password || '');
  if (!username || !nome || !password) return res.status(400).json({ erro: 'Preencha todos os campos.' });
  if (!['admin','gerente','operador'].includes(role)) return res.status(400).json({ erro: 'Perfil inválido.' });
  if (password.length < 6) return res.status(400).json({ erro: 'Senha precisa ter pelo menos 6 caracteres.' });
  const { error } = await supabase.from('users').insert({ username, nome, role, password_hash: hashPassword(password), active: 1 });
  if (error) {
    if (error.code === '23505') return res.status(400).json({ erro: 'Usuário já existe.' });
    return res.status(500).json({ erro: 'Erro ao criar usuário.' });
  }
  await audit('criar_usuario', { novo: username, role }, req.user, getClientIp(req));
  res.json({ ok: true });
});

app.put('/api/users/:id', auth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const active = req.body?.active !== undefined ? (req.body.active ? 1 : 0) : null;
  const nova_senha = String(req.body?.nova_senha || '');
  const role = sanitizeText(req.body?.role, 20);
  const nome = req.body?.nome !== undefined ? sanitizeText(req.body.nome, 60) : null;
  const novoUsername = req.body?.username !== undefined ? sanitizeText(req.body.username, 40).toLowerCase() : null;
  if (Number(id) === req.user.id && active === 0) return res.status(400).json({ erro: 'Você não pode desativar sua própria conta.' });
  const updates = {};
  if (active !== null) updates.active = active;
  if (role && ['admin','gerente','operador'].includes(role)) updates.role = role;
  if (nome !== null) {
    if (!nome) return res.status(400).json({ erro: 'O nome não pode ficar vazio.' });
    updates.nome = nome;
  }
  if (novoUsername !== null) {
    if (!novoUsername) return res.status(400).json({ erro: 'O login não pode ficar vazio.' });
    const { data: jaExiste } = await supabase.from('users').select('id').ilike('username', novoUsername).neq('id', id).maybeSingle();
    if (jaExiste) return res.status(400).json({ erro: 'Já existe um usuário com esse login.' });
    updates.username = novoUsername;
  }
  if (nova_senha) {
    if (nova_senha.length < 6) return res.status(400).json({ erro: 'Senha precisa ter pelo menos 6 caracteres.' });
    updates.password_hash = hashPassword(nova_senha);
  }
  // Liberações: aceita objeto permissoes { lancar, dia, planilha, contas, exportar, ia, auditoria, alertas, agenda, pendencias, admin }
  if (req.body?.permissoes && typeof req.body.permissoes === 'object') {
    const limpo = {};
    for (const k of PERM_KEYS) if (typeof req.body.permissoes[k] === 'boolean') limpo[k] = req.body.permissoes[k];
    updates.permissoes = limpo;
  }
  if (Object.keys(updates).length > 0) await supabase.from('users').update(updates).eq('id', id);
  await audit('editar_usuario', { id, active, role, permissoes: !!updates.permissoes }, req.user, getClientIp(req));
  res.json({ ok: true });
});

// ==================== SINÔNIMOS ====================
app.get('/api/sinonimos', auth, async (req, res) => {
  const { data } = await supabase.from('sinonimos').select('*').order('termo');
  res.json(data || []);
});

app.post('/api/sinonimos', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const termo = sanitizeText(req.body?.termo, 120);
  const produto_nome = sanitizeText(req.body?.produto_nome, 120);
  if (!termo || !produto_nome) return res.status(400).json({ erro: 'Termo e produto são obrigatórios.' });
  const { prod, opcoes } = await acharProdutoUnico(produto_nome);
  if (opcoes) return res.status(400).json({ erro: `Vários produtos batem com "${produto_nome}". Seja mais específico: ${opcoes.slice(0, 5).map(p => p.nome).join(' | ')}` });
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado no estoque.' });
  const { error } = await supabase.from('sinonimos').upsert({ termo: normalizeSearch(termo), produto_nome: prod.nome }, { onConflict: chaveConflito('termo') });
  if (error) return res.status(500).json({ erro: 'Erro ao salvar sinônimo.' });
  res.json({ ok: true });
});

app.post('/api/sinonimos/importar', auth, requireRole('admin'), async (req, res) => {
  const lista = req.body?.lista;
  if (!Array.isArray(lista) || !lista.length) return res.status(400).json({ erro: 'Lista inválida.' });
  let ok = 0, erros = [];
  for (const s of lista) {
    try {
      const termo = normalizeSearch(String(s.termo || ''));
      const { prod } = await acharProdutoUnico(String(s.produto_nome || ''));
      if (!termo || !prod) { erros.push(s.termo); continue; }
      await supabase.from('sinonimos').upsert({ termo, produto_nome: prod.nome }, { onConflict: chaveConflito('termo') });
      ok++;
    } catch(e) { erros.push(s.termo); }
  }
  res.json({ ok, erros });
});

app.delete('/api/sinonimos/:id', auth, requireRole('admin', 'gerente'), async (req, res) => {
  await supabase.from('sinonimos').delete().eq('id', req.params.id);
  res.json({ ok: true });
});

app.get('/api/manutencao/normalizar', auth, requireRole('admin'), async (req, res) => {
  const { data: todos } = await supabase.from('produtos').select('id, nome');
  for (const p of (todos || [])) await supabase.from('produtos').update({ nome_search: normalizeSearch(p.nome) }).eq('id', p.id);
  res.json({ ok: true, total: (todos||[]).length, msg: `${(todos||[]).length} produtos normalizados!` });
});

// ==================== AUDITORIA DE DIVERGÊNCIAS ====================
app.get('/api/auditoria/divergencias', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const dataInicio = req.query?.data_inicio || dateAgoDias(30);
  const dataFim = req.query?.data_fim || dateSP();
  const categoria = sanitizeText(req.query?.categoria || '', 80);
  const allMovs = await fetchTodas(() => {
    let q = supabase.from('movimentacoes').select('*').gte('created_at', dataInicio + 'T00:00:00-03:00').lte('created_at', dataFim + 'T23:59:59-03:00');
    if (categoria) q = q.eq('categoria', categoria);
    return q.order('id', { ascending: true });
  });
  const { data: produtos } = await supabase.from('produtos').select('id, nome, qtd, minimo');
  const prodPorId = {};
  for (const p of (produtos || [])) prodPorId[p.id] = p;

  // Agrupa por produto_id (estável a renomeações). Só cai no nome quando o id é null
  // (movimentações muito antigas). Isso evita que renomear um produto divida o histórico
  // e gere falso "sumiço".
  const groups = {};
  for (const m of (allMovs || [])) {
    const key = m.produto_id != null ? 'id:' + m.produto_id : 'nome:' + m.produto_nome;
    const nomeExib = (m.produto_id != null && prodPorId[m.produto_id]) ? prodPorId[m.produto_id].nome : m.produto_nome;
    if (!groups[key]) groups[key] = { produto_id: m.produto_id ?? null, produto_nome: nomeExib, categoria: m.categoria, unidade: m.unidade, total_entrada: 0, total_saida: 0, total_perda: 0, total_ajuste_delta: 0, num_ajustes: 0, valor_entrada: 0, valor_saida: 0, num_saidas: 0, num_entradas: 0 };
    const g = groups[key];
    if (m.tipo === 'Entrada') { g.total_entrada += Number(m.qtd); g.valor_entrada += Number(m.valor || 0); g.num_entradas++; }
    if (['Saída','Perda'].includes(m.tipo)) { g.total_saida += Number(m.qtd); g.valor_saida += Number(m.valor || 0); g.num_saidas++; }
    if (m.tipo === 'Perda') g.total_perda += Number(m.qtd);
    if (m.tipo === 'Ajuste') { g.total_ajuste_delta += (Number(m.qtd_depois || 0) - Number(m.qtd_antes || 0)); g.num_ajustes++; }
  }

  // ALERTA confiável = reconstrução cronológica do HISTÓRICO COMPLETO por produto_id:
  // Entrada soma, Saída/Perda subtrai, Ajuste DEFINE o saldo absoluto. Se o saldo ficou
  // negativo em algum momento, saiu mais do que tinha = saída sem lastro (entrada não lançada).
  const idsPeriodo = Object.values(groups).map(g => g.produto_id).filter(v => v != null);
  const piorSaldo = {};
  if (idsPeriodo.length) {
    const { data: hist } = await supabase.from('movimentacoes')
      .select('produto_id, tipo, qtd').in('produto_id', idsPeriodo)
      .order('created_at', { ascending: true }).order('id', { ascending: true });
    const saldo = {};
    for (const m of (hist || [])) {
      const k = m.produto_id;
      if (saldo[k] === undefined) saldo[k] = 0;
      if (m.tipo === 'Entrada') saldo[k] += Number(m.qtd);
      else if (m.tipo === 'Saída' || m.tipo === 'Perda') saldo[k] -= Number(m.qtd);
      else if (m.tipo === 'Ajuste') saldo[k] = Number(m.qtd);
      if (piorSaldo[k] === undefined || saldo[k] < piorSaldo[k]) piorSaldo[k] = saldo[k];
    }
  }

  const resultado = Object.values(groups).filter(g => g.total_entrada > 0 || g.total_saida > 0 || g.num_ajustes > 0).map(r => {
    const qtdAtual = r.produto_id != null && prodPorId[r.produto_id] ? Number(prodPorId[r.produto_id].qtd) : null;
    const saldo = Number((r.total_entrada - r.total_saida + r.total_ajuste_delta).toFixed(3));
    const pior = r.produto_id != null ? piorSaldo[r.produto_id] : undefined;
    const faltou = (pior !== undefined && pior < -0.01) ? Number((-pior).toFixed(3)) : 0;
    // "Consumiu até zerar e não repôs" — dica de reposição, não suspeita de sumiço.
    const zerouSemRepor = r.total_saida > 0 && r.total_entrada === 0 && (qtdAtual ?? 0) === 0;
    return { ...r, total_entrada: Number(r.total_entrada.toFixed(3)), total_saida: Number(r.total_saida.toFixed(3)),
      total_perda: Number(r.total_perda.toFixed(3)), total_ajuste_delta: Number(r.total_ajuste_delta.toFixed(3)),
      num_ajustes: r.num_ajustes, valor_entrada: Number(r.valor_entrada.toFixed(2)),
      valor_saida: Number(r.valor_saida.toFixed(2)), saldo, qtd_atual: qtdAtual,
      alerta: faltou > 0, faltou,
      sem_entrada: zerouSemRepor };
  }).sort((a, b) => (a.categoria + a.produto_nome).localeCompare(b.categoria + b.produto_nome));
  const detalhesSaidas = (allMovs || []).filter(m => ['Saída','Perda'].includes(m.tipo))
    .map(m => ({ produto_nome: m.produto_nome, tipo: m.tipo, qtd: m.qtd, unidade: m.unidade, motivo: m.motivo, responsavel: m.responsavel, obs: m.obs, created_at: m.created_at }))
    .sort((a, b) => (a.produto_nome + b.created_at).localeCompare(b.produto_nome + a.created_at));
  await audit('auditoria_divergencias', { dataInicio, dataFim, categoria }, req.user, getClientIp(req));
  res.json({ resultado, detalhesSaidas, dataInicio, dataFim });
});

// ==================== BACKUP AUTOMÁTICO ====================
async function criarBackupEstoque(motivo = 'automatico') {
  // `dados` guarda TODOS os produtos (incl. arquivados) — o backup precisa disso pra
  // restaurar de verdade. Mas o resumo (zerados/críticos/valor) só deve contar os ativos,
  // senão o snapshot registra números que nunca bateriam com o que a tela mostra.
  const { data: produtos } = await supabase.from('produtos').select('id, nome, categoria, unidade, qtd, minimo, custo, ativo');
  if (!produtos || !produtos.length) return null;
  const ativos = produtos.filter(p => p.ativo !== 0);
  const snapshot = { data_backup: nowSP(), motivo, total_produtos: produtos.length,
    valor_total: ativos.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0),
    zerados: ativos.filter(p => Number(p.qtd) === 0).length,
    criticos: ativos.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5).length,
    dados: JSON.stringify(produtos) };
  const { data, error } = await supabase.from('backups_estoque').insert(snapshot).select('id, data_backup').single();
  if (error) { console.error('❌ Erro no backup:', error.message); return null; }
  console.log(`✅ Backup #${data.id} criado em ${data.data_backup} (${motivo})`);
  return data;
}

let ultimoBackupDia = '';
setInterval(async () => {
  const agora = nowSP(), hora = agora.slice(11, 16), dia = agora.slice(0, 10);
  const HORA_BACKUP = process.env.HORA_BACKUP || '18:00';
  if (hora === HORA_BACKUP && dia !== ultimoBackupDia) { ultimoBackupDia = dia; await criarBackupEstoque('automatico_18h'); }
}, 60 * 1000);

app.post('/api/backup', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const motivo = sanitizeText(req.body?.motivo || 'manual', 100);
  const backup = await criarBackupEstoque(motivo);
  if (!backup) return res.status(500).json({ erro: 'Erro ao criar backup.' });
  await audit('backup_manual', { backup_id: backup.id, motivo }, req.user, getClientIp(req));
  res.json({ ok: true, backup });
});

app.get('/api/backups', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const { data } = await supabase.from('backups_estoque').select('id, data_backup, motivo, total_produtos, valor_total, zerados, criticos').order('id', { ascending: false }).limit(30);
  res.json(data || []);
});

app.post('/api/backup/:id/restaurar', auth, requireRole('admin'), async (req, res) => {
  const senhaAdmin = String(req.body?.senha_admin || '');
  const { data: userDb } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!verifyPassword(senhaAdmin, userDb.password_hash)) return res.status(401).json({ erro: 'Senha incorreta.' });
  const { data: backup } = await supabase.from('backups_estoque').select('*').eq('id', req.params.id).single();
  if (!backup) return res.status(404).json({ erro: 'Backup não encontrado.' });
  await criarBackupEstoque('pre_restauracao');
  const produtos = JSON.parse(backup.dados);
  const { data: prodsDb } = await supabase.from('produtos').select('id, nome, categoria, unidade, qtd, custo');
  const mapDb = {}; for (const pd of (prodsDb || [])) mapDb[pd.id] = pd;
  let restaurados = 0;
  for (const p of produtos) {
    // custo/mínimo/ativo direto; a QTD vira Ajuste para não desincronizar o histórico
    const { error } = await supabase.from('produtos').update({ custo: p.custo, minimo: p.minimo, ativo: p.ativo }).eq('id', p.id);
    const pd = mapDb[p.id];
    if (pd) await sincronizarQtd({ ...pd, custo: p.custo }, p.qtd, 'Restauração de backup', req.user.nome);
    if (!error) restaurados++;
  }
  await audit('restaurar_backup', { backup_id: backup.id, data_backup: backup.data_backup, restaurados }, req.user, getClientIp(req));
  res.json({ ok: true, restaurados, data_backup: backup.data_backup });
});

// ==================== WEBHOOK WHATSAPP ====================
// Segurança: SEM fallback hardcoded — o secret antigo ficou exposto no histórico do git.
// Se a variável não estiver no Railway, o webhook fica desativado (503) em vez de aceitar default.
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
if (!WEBHOOK_SECRET) console.error('⚠️ FATAL: WEBHOOK_SECRET não definido — webhook WhatsApp DESATIVADO até configurar no Railway.');

app.post('/api/webhook/whatsapp', webhookLimiter, async (req, res) => {
  if (!WEBHOOK_SECRET) return res.status(503).json({ erro: 'Webhook não configurado no servidor.' });
  const secret = req.headers['x-webhook-secret'] || req.body?.secret;
  if (secret !== WEBHOOK_SECRET) return res.status(403).json({ erro: 'Acesso negado.' });
  const acao = sanitizeText(req.body?.acao, 40);
  const produto_nome = sanitizeText(req.body?.produto, 120);
  const remetente = sanitizeText(req.body?.remetente, 40);

  if (acao === 'consultar') {
    if (!produto_nome) return res.json({ resposta: 'Me diz o nome do produto que quer consultar.' });
    const { data: resultados } = await supabase.from('produtos').select('nome, categoria, qtd, unidade, minimo, custo').ilike('nome_search', `%${normalizeSearch(produto_nome)}%`).or('ativo.eq.1,ativo.is.null').order('nome').limit(5);
    if (!resultados || !resultados.length) return res.json({ resposta: `Não encontrei "${produto_nome}" no estoque.` });
    const linhas = resultados.map(p => { const st = Number(p.qtd) === 0 ? '🔴 ZERADO' : Number(p.qtd) <= Number(p.minimo)*0.5 ? '🟠 CRÍTICO' : Number(p.qtd) < Number(p.minimo) ? '🟡 ATENÇÃO' : '🟢 OK'; return `📦 *${p.nome}*\n   ${p.qtd} ${p.unidade} (mín: ${p.minimo}) ${st}\n   Custo: R$${Number(p.custo).toFixed(2)}`; });
    return res.json({ resposta: linhas.join('\n\n') });
  }

  if (acao === 'resumo') {
    const { data: all } = await supabase.from('produtos').select('qtd, minimo, custo').or('ativo.eq.1,ativo.is.null');
    const prods = all || [];
    const hojeSP = dateSP();
    const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true }).gte('created_at', hojeSP + 'T00:00:00-03:00').lte('created_at', hojeSP + 'T23:59:59-03:00');
    return res.json({ resposta: `📊 *RESUMO DO ESTOQUE*\n📅 ${hojeSP}\n\n📦 Total: ${prods.length}\n🔴 Zerados: ${prods.filter(p=>Number(p.qtd)===0).length}\n🟠 Críticos: ${prods.filter(p=>Number(p.qtd)>0&&Number(p.qtd)<=Number(p.minimo)*0.5).length}\n🟡 Atenção: ${prods.filter(p=>Number(p.qtd)>Number(p.minimo)*0.5&&Number(p.qtd)<Number(p.minimo)).length}\n💰 Valor total: R$ ${prods.reduce((s,p)=>s+Number(p.qtd)*Number(p.custo),0).toFixed(2)}\n📋 Lançamentos hoje: ${lancHoje||0}` });
  }

  if (acao === 'zerados') {
    const { data } = await supabase.from('produtos').select('nome, categoria').eq('qtd', 0).or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    if (!data || !data.length) return res.json({ resposta: '✅ Nenhum produto zerado!' });
    return res.json({ resposta: `🔴 *PRODUTOS ZERADOS (${data.length})*\n\n${data.map(p=>`• ${p.nome} (${p.categoria})`).join('\n')}` });
  }

  if (acao === 'criticos') {
    const { data } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, unidade').gt('qtd', 0).or('ativo.eq.1,ativo.is.null').order('nome');
    const crit = (data || []).filter(p => Number(p.qtd) <= Number(p.minimo) * 0.5);
    if (!crit.length) return res.json({ resposta: '✅ Nenhum produto em nível crítico!' });
    return res.json({ resposta: `🟠 *PRODUTOS CRÍTICOS (${crit.length})*\n\n${crit.map(p=>`• ${p.nome}: ${p.qtd}/${p.minimo} ${p.unidade}`).join('\n')}` });
  }

  if (acao === 'entrada' || acao === 'saida') {
    const tipo = acao === 'entrada' ? 'Entrada' : 'Saída';
    const qtd = parsePositiveNumber(req.body?.qtd);
    if (!produto_nome || !qtd) return res.json({ resposta: `Para lançar ${tipo.toLowerCase()}, envie: produto, quantidade` });
    // Preço opcional na Entrada: custo (unitário) ou valor (total da compra) → atualiza o custo do produto.
    const custoInfW = parsePositiveNumber(req.body?.custo);
    const valorInfW = parsePositiveNumber(req.body?.valor);
    const custoNovoW = tipo === 'Entrada'
      ? (custoInfW !== null ? custoInfW : (valorInfW !== null ? Number((valorInfW / qtd).toFixed(4)) : null))
      : null;
    // Matcher completo: acento-insensível + aceita código (BOV-01) e apelido cadastrado.
    const { prod, opcoes } = await acharProdutoUnico(produto_nome);
    if (opcoes) {
      const ops = opcoes.slice(0, 6).map(p => `• ${p.nome}${p.codigo ? ` (${p.codigo})` : ''}`).join('\n');
      return res.json({ resposta: `Encontrei ${opcoes.length} produtos com "${produto_nome}". Seja mais especifico (pode usar o código):\n\n${ops}` });
    }
    if (!prod) return res.json({ resposta: `Não encontrei "${produto_nome}" no estoque.` });
    // Blindagem de concorrência: trava otimista com retry — evita que duas baixas
    // simultâneas do mesmo produto se sobrescrevam (perda de dado).
    let novaQtd, prodAtual = prod, sucesso = false;
    for (let tent = 0; tent < 4 && !sucesso; tent++) {
      novaQtd = Number(prodAtual.qtd);
      if (tipo === 'Entrada') novaQtd = Number((novaQtd + qtd).toFixed(3));
      else {
        if (qtd > novaQtd) return res.json({ resposta: `❌ Estoque insuficiente de ${prodAtual.nome}. Disponível: ${prodAtual.qtd} ${prodAtual.unidade}` });
        novaQtd = Number((novaQtd - qtd).toFixed(3));
      }
      const updDataW = custoNovoW !== null ? { qtd: novaQtd, custo: custoNovoW } : { qtd: novaQtd };
      const { data: upd } = await supabase.from('produtos').update(updDataW).eq('id', prodAtual.id).eq('qtd', prodAtual.qtd).select('id');
      if (upd && upd.length) { sucesso = true; break; }
      const { data: re } = await supabase.from('produtos').select('*').eq('id', prod.id).single();
      if (!re) break;
      prodAtual = re;
    }
    if (!sucesso) return res.json({ resposta: `❌ Não consegui atualizar ${prod.nome} agora (outro lançamento simultâneo). Tente de novo em instantes.` });
    const qtdAntesW = Number(prodAtual.qtd);
    const custoUnitW = custoNovoW !== null ? custoNovoW : Number(prod.custo || 0);
    const { data: movWpp, error: movErr } = await supabase.from('movimentacoes').insert({
      produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria, tipo, qtd, unidade: prod.unidade,
      custo: custoUnitW, valor: Number((custoUnitW*qtd).toFixed(2)),
      motivo: tipo === 'Entrada' ? 'Compra' : 'Produção', responsavel: remetente || 'WhatsApp', obs: 'via WhatsApp', created_at: nowSP(),
      qtd_antes: qtdAntesW, qtd_depois: novaQtd, // foto antes→depois (auditoria cruzada)
    }).select('id').single();
    if (movErr) { await supabase.from('produtos').update({ qtd: qtdAntesW, custo: prodAtual.custo }).eq('id', prod.id).eq('qtd', novaQtd); return res.json({ resposta: `❌ Erro ao registrar movimentação de ${prod.nome}.` }); }
    if (tipo === 'Entrada') await lancarCompraNasContas({ produto: prod, qtd, custoUnit: custoUnitW, responsavel: remetente || 'WhatsApp', obs: 'via WhatsApp', movId: movWpp?.id });
    await audit('movimentacao_whatsapp', { produto: prod.nome, tipo, qtd, nova_qtd: novaQtd, custo_novo: custoNovoW, remetente }, null, '');
    const linhaCusto = custoNovoW !== null && Math.abs(custoNovoW - Number(prod.custo || 0)) >= 0.01
      ? `\n💲 Custo: R$${Number(prod.custo || 0).toFixed(2)} → R$${custoNovoW.toFixed(2)}` : '';
    return res.json({ resposta: `✅ *${tipo.toUpperCase()}* registrada!\n\n📦 ${prod.nome}\n📏 ${qtd} ${prod.unidade}\n📊 Estoque agora: ${novaQtd} ${prod.unidade}${linhaCusto}` });
  }

  if (acao === 'compras') {
    const { data } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, unidade, grupo_troca').or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    const todos = data || [];
    const semMinimo = todos.filter(p => Number(p.minimo) <= 0 && Number(p.qtd) === 0).length;
    const baixos = todos.filter(p => Number(p.minimo) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5);
    // Grupo de troca: se um irmão tem estoque, o item baixo sai do urgente (você escolhe pelo preço).
    const estoquePorGrupo = {};
    for (const p of todos) {
      if (p.grupo_troca && Number(p.qtd) > 0) {
        if (!estoquePorGrupo[p.grupo_troca]) estoquePorGrupo[p.grupo_troca] = [];
        estoquePorGrupo[p.grupo_troca].push(p);
      }
    }
    const lista = [], comSubstituto = [];
    for (const p of baixos) {
      const irmaos = (p.grupo_troca && estoquePorGrupo[p.grupo_troca] || []).filter(i => i.nome !== p.nome);
      if (irmaos.length) comSubstituto.push({ ...p, irmao: irmaos[0] });
      else lista.push(p);
    }
    const nota = semMinimo > 0 ? `\n\n(+ ${semMinimo} zerados sem mínimo definido — defina o mínimo no app para entrarem na lista)` : '';
    let msg;
    if (!lista.length && !comSubstituto.length) msg = '✅ Estoque OK! Nada para comprar urgente.' + nota;
    else {
      msg = lista.length ? `🛒 *LISTA DE COMPRAS (${lista.length} itens)*\n\n${lista.map(p=>`• ${p.nome}: tem ${p.qtd}, comprar ~${Math.max(0,Number(p.minimo)*2-Number(p.qtd)).toFixed(1)} ${p.unidade}`).join('\n')}` : '✅ Nada urgente sem alternativa.';
      if (comSubstituto.length) {
        msg += `\n\n🔄 *Baixos COM substituto em estoque* (escolha pelo preço):\n`;
        msg += comSubstituto.map(p => `• ${p.nome}: tem ${p.qtd} — substituto: ${p.irmao.nome} (${p.irmao.qtd} ${p.irmao.unidade})`).join('\n');
      }
      msg += nota;
    }
    return res.json({ resposta: msg });
  }

  if (acao === 'fechamento' || acao === 'realidade') {
    // Webhook do WhatsApp já é autenticado pelo x-webhook-secret (não tem usuário logado).
    // Só exige permissão de usuário quando a chamada vem da UI (req.user presente).
    if (req.user && !(await usuarioTemPerm(req, 'dia'))) {
      return res.status(403).json({ erro: 'Acesso não liberado para este recurso. Fale com o administrador.' });
    }
    const realidade = await montarRealidadeDia(dateSP());
    return res.json({
      resposta: montarMensagemFechamentoDia(realidade),
      total: realidade.movimentos.total,
      vendas: realidade.vendas,
      venda_lancada: realidade.venda_lancada,
      pratos_vendidos: realidade.pratos_vendidos,
      ticket_medio: realidade.ticket_medio,
      pagamentos: realidade.pagamentos,
      cortes: realidade.cortes,
      despesas_caixa: realidade.despesas,
      despesas_lista: realidade.despesas_lista,
      compras_estoque: realidade.compras_estoque,
      consumo_estoque: realidade.consumo_estoque,
      perdas: realidade.perdas,
      lucro_bruto_estimado: realidade.lucro_bruto_estimado,
      resultado_dia_estimado: realidade.resultado_dia_estimado,
      fluxo_caixa: realidade.fluxo_caixa,
      anomalias: realidade.movimentos.anomalias,
      configuracao_pendente: realidade.configuracao_pendente,
    });
  }

  if (acao === 'conferencia') {
    // Conferência por ORIGEM: inventário (causas categorizadas) + ajustes manuais.
    // Exclui 'sincronização automática' (reset/backup) — não é sumiço.
    const dias = Math.min(Math.max(parseInt(req.body?.dias) || 7, 1), 60);
    const desde = dateAgoDias(dias);
    const dataBR = dateSP().split('-').reverse().join('/');

    // 1) Inventários fechados no período — fonte oficial do sumiço.
    const { data: invs } = await supabase.from('inventarios')
      .select('id, data, categoria, valor_sumico, valor_sobra, itens_divergentes')
      .eq('status', 'fechado').gte('fechado_em', desde + 'T00:00:00-03:00').order('fechado_em');
    const invList = invs || [];
    const porCausa = { sumico: 0, roubo: 0, perda: 0, erro_lancamento: 0, sobra: 0 };
    const sumidoInv = {};
    if (invList.length) {
      const { data: itens } = await supabase.from('inventario_itens')
        .select('produto_nome, divergencia, valor_divergencia, causa')
        .in('inventario_id', invList.map(i => i.id)).not('causa', 'in', '("ok","nao_contado")');
      for (const it of (itens || [])) {
        const v = Math.abs(Number(it.valor_divergencia || 0));
        if (!v) continue;
        const c = porCausa[it.causa] !== undefined ? it.causa : (Number(it.divergencia) < 0 ? 'sumico' : 'sobra');
        porCausa[c] += v;
        if ((c === 'sumico' || c === 'roubo') && Number(it.divergencia) < 0) {
          const k = it.produto_nome || '?';
          if (!sumidoInv[k]) sumidoInv[k] = { qtd: 0, valor: 0 };
          sumidoInv[k].qtd += Math.abs(Number(it.divergencia));
          sumidoInv[k].valor += v;
        }
      }
    }

    // 2) Movimentações do período: ajustes manuais (fora do inventário) + perdas declaradas.
    const { data: movs } = await supabase.from('movimentacoes')
      .select('produto_nome, tipo, qtd, qtd_antes, qtd_depois, custo, responsavel, obs')
      .in('tipo', ['Ajuste', 'Perda']).gte('created_at', desde + 'T00:00:00-03:00');
    const manuais = []; let nSinc = 0, nAjusteInv = 0, perdasValor = 0, manualNegValor = 0;
    for (const m of (movs || [])) {
      const obsN = normalizeSearch(m.obs || '');
      if (m.tipo === 'Perda') { perdasValor += Number(m.qtd || 0) * Number(m.custo || 0); continue; }
      if (obsN.includes('sincronizacao automatica')) { nSinc++; continue; }
      if (obsN.includes('inventario')) { nAjusteInv++; continue; }
      if (m.qtd_antes === null || m.qtd_depois === null) continue; // sem antes/depois não dá pra medir
      const delta = Number(m.qtd_depois) - Number(m.qtd_antes);
      const valorDelta = Math.abs(delta) * Number(m.custo || 0);
      if (delta < 0) manualNegValor += valorDelta;
      manuais.push({ nome: m.produto_nome, delta: Number(delta.toFixed(3)), valor: Number(valorDelta.toFixed(2)), responsavel: m.responsavel || '?' });
    }

    // Sumiço real = SÓ o que o inventário apurou como sumico/roubo. Ajuste manual é
    // quase sempre correção (ex.: typo de digitação) — listado, mas NÃO conta como perda.
    const sumicoReal = porCausa.sumico + porCausa.roubo;
    if (!invList.length && !manuais.length) {
      return res.json({ resposta: `🔎 *CONFERÊNCIA — últimos ${dias} dias*\n📅 ${dataBR}\n\n⚠️ Nenhum inventário fechado nem ajuste manual no período.\n\nSem contagem física não dá para saber se está sumindo item. Faça o inventário de sábado.`, total_sumido: 0, contagens: 0 });
    }

    let msg = `🔎 *CONFERÊNCIA — últimos ${dias} dias*\n📅 ${dataBR}\n\n`;
    if (invList.length) {
      msg += `🧾 *Inventário(s): ${invList.length}* (${invList.map(i => i.categoria || 'geral').join(', ')})\n`;
      if (porCausa.sumico + porCausa.roubo > 0) {
        const top = Object.entries(sumidoInv).sort((a, b) => b[1].valor - a[1].valor).slice(0, 10);
        msg += `   💸 Sumiço real: R$ ${(porCausa.sumico + porCausa.roubo).toFixed(2)}\n`;
        msg += top.map(([n, d]) => `      • ${n}: -${Number(d.qtd).toFixed(d.qtd % 1 === 0 ? 0 : 1)} (R$ ${d.valor.toFixed(2)})`).join('\n') + '\n';
      } else msg += `   ✅ Contagem bateu — nenhum sumiço real.\n`;
      if (porCausa.erro_lancamento > 0) msg += `   ✏️ Erro de lançamento (corrigido, não é perda): R$ ${porCausa.erro_lancamento.toFixed(2)}\n`;
      if (porCausa.perda > 0) msg += `   🗑️ Perda apurada na contagem: R$ ${porCausa.perda.toFixed(2)}\n`;
      if (porCausa.sobra > 0) msg += `   📦 Sobra: R$ ${porCausa.sobra.toFixed(2)}\n`;
    } else {
      msg += `🧾 Nenhum inventário fechado no período — faça o de sábado.\n`;
    }
    if (manuais.length) {
      msg += `\n⚙️ *Ajustes manuais: ${manuais.length}* (correções — não contam como perda)\n`;
      msg += manuais.slice(0, 8).map(a => `   • ${a.nome}: ${a.delta > 0 ? '+' : ''}${a.delta} (R$ ${a.valor.toFixed(2)}) — ${a.responsavel}`).join('\n');
      if (manuais.length > 8) msg += `\n   …e mais ${manuais.length - 8}`;
      if (manualNegValor > 200) msg += `\n   ⚠️ Ajustes negativos somam R$ ${manualNegValor.toFixed(2)} — prefira apurar pelo inventário, onde a causa é classificada.`;
      msg += '\n';
    }
    if (perdasValor > 0) msg += `\n🗑️ Perdas declaradas na semana: R$ ${perdasValor.toFixed(2)}`;
    if (nSinc > 0) msg += `\n🚫 Ignoradas ${nSinc} sincronização(ões) automática(s) de backup.`;
    msg += `\n\n💰 *DINHEIRO REALMENTE PERDIDO: R$ ${sumicoReal.toFixed(2)}*`;
    if (sumicoReal > 0) msg += `\n_Causa comum: saída não lançada. Cobre a equipe no fechamento diário._`;
    return res.json({ resposta: msg, total_sumido: Number(sumicoReal.toFixed(2)), contagens: invList.length, ajustes_manuais: manuais.length, por_causa: porCausa, perdas_valor: Number(perdasValor.toFixed(2)), sincronizacoes_ignoradas: nSinc, ajustes_inventario_ignorados: nAjusteInv });
  }

  if (acao === 'conferencia_mensal') {
    // Consolidado do mês: tendência dos inventários + comparação com o mês anterior.
    // Aceita mes=AAAA-MM; padrão = mês anterior (roda dia 1º).
    const mesParam = /^\d{4}-\d{2}$/.test(String(req.body?.mes || '')) ? String(req.body.mes) : null;
    const hoje = dateSP();
    const mesRef = mesParam || (() => { const d = new Date(hoje + 'T12:00:00-03:00'); d.setMonth(d.getMonth() - 1); return d.toISOString().slice(0, 7); })();
    const mesAnt = (() => { const d = new Date(mesRef + '-15T12:00:00-03:00'); d.setMonth(d.getMonth() - 1); return d.toISOString().slice(0, 7); })();

    async function resumoMes(mes) {
      // limite superior = dia 1º do mês seguinte (evita data inválida tipo 06-31)
      const dProx = new Date(mes + '-15T12:00:00-03:00'); dProx.setMonth(dProx.getMonth() + 1);
      const proxMes = dProx.toISOString().slice(0, 7) + '-01';
      const { data: invs } = await supabase.from('inventarios')
        .select('id, data, categoria').eq('status', 'fechado')
        .gte('data', mes + '-01').lt('data', proxMes).order('data');
      const lista = invs || [];
      const r = { mes, inventarios: lista.length, sumico: 0, roubo: 0, perda: 0, erro_lancamento: 0, sobra: 0, porProduto: {} };
      if (!lista.length) return r;
      const { data: itens } = await supabase.from('inventario_itens')
        .select('produto_nome, divergencia, valor_divergencia, causa, inventario_id')
        .in('inventario_id', lista.map(i => i.id)).not('causa', 'in', '("ok","nao_contado")');
      for (const it of (itens || [])) {
        const v = Math.abs(Number(it.valor_divergencia || 0));
        if (!v) continue;
        const c = r[it.causa] !== undefined ? it.causa : (Number(it.divergencia) < 0 ? 'sumico' : 'sobra');
        r[c] += v;
        if ((c === 'sumico' || c === 'roubo') && Number(it.divergencia) < 0) {
          const k = it.produto_nome || '?';
          if (!r.porProduto[k]) r.porProduto[k] = { valor: 0, vezes: new Set() };
          r.porProduto[k].valor += v;
          r.porProduto[k].vezes.add(it.inventario_id);
        }
      }
      return r;
    }

    const [atual, anterior] = await Promise.all([resumoMes(mesRef), resumoMes(mesAnt)]);
    const sumicoAtual = atual.sumico + atual.roubo;
    const sumicoAnt = anterior.sumico + anterior.roubo;
    const mesBR = mesRef.split('-').reverse().join('/');
    let msg = `📅 *BALANÇO MENSAL DE ESTOQUE — ${mesBR}*\n\n`;
    if (!atual.inventarios) {
      msg += `⚠️ Nenhum inventário fechado em ${mesBR}. Sem contagem não há balanço — mantenha o inventário de sábado.`;
    } else {
      msg += `🧾 Inventários no mês: ${atual.inventarios}\n`;
      msg += `💸 Sumiço real: R$ ${sumicoAtual.toFixed(2)}`;
      if (anterior.inventarios) {
        const dif = sumicoAtual - sumicoAnt;
        const pct = sumicoAnt > 0 ? Math.abs(dif / sumicoAnt * 100).toFixed(0) : null;
        msg += dif <= 0 ? ` (${pct ? `melhorou ${pct}% — ` : ''}mês anterior R$ ${sumicoAnt.toFixed(2)}) ✅` : ` (${pct ? `PIOROU ${pct}% — ` : ''}mês anterior R$ ${sumicoAnt.toFixed(2)}) ⚠️`;
      }
      msg += '\n';
      if (atual.erro_lancamento > 0) msg += `✏️ Erros de lançamento corrigidos: R$ ${atual.erro_lancamento.toFixed(2)}\n`;
      if (atual.perda > 0) msg += `🗑️ Perdas apuradas: R$ ${atual.perda.toFixed(2)}\n`;
      if (atual.sobra > 0) msg += `📦 Sobras: R$ ${atual.sobra.toFixed(2)}\n`;
      const topProd = Object.entries(atual.porProduto).map(([n, d]) => ({ nome: n, valor: d.valor, vezes: d.vezes.size }))
        .sort((a, b) => b.valor - a.valor).slice(0, 8);
      if (topProd.length) {
        msg += `\n🎯 *Produtos problema do mês:*\n`;
        msg += topProd.map(p => `• ${p.nome}: R$ ${p.valor.toFixed(2)}${p.vezes > 1 ? ` (sumiu em ${p.vezes} inventários!)` : ''}`).join('\n');
        const reincidentes = topProd.filter(p => p.vezes > 1);
        if (reincidentes.length) msg += `\n\n⚠️ _Reincidentes merecem atenção especial: ${reincidentes.map(p => p.nome).join(', ')}._`;
      }
    }
    return res.json({ resposta: msg, mes: mesRef, sumico_real: Number(sumicoAtual.toFixed(2)), mes_anterior: { mes: mesAnt, sumico_real: Number(sumicoAnt.toFixed(2)), inventarios: anterior.inventarios }, inventarios: atual.inventarios });
  }

  res.json({ resposta: `🐰 *Toca do Coelho — Estoque*\n\nComandos: consultar | resumo | zerados | criticos | compras | entrada | saida | fechamento | realidade | conferencia | conferencia_mensal` });
});

app.get('/api/webhook/relatorio-diario', webhookLimiter, async (req, res) => {
  if (!WEBHOOK_SECRET) return res.status(503).json({ erro: 'Webhook não configurado no servidor.' });
  const secret = req.headers['x-webhook-secret'] || req.query?.secret;
  if (secret !== WEBHOOK_SECRET) return res.status(403).json({ erro: 'Acesso negado.' });
  const { data: all } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, custo, unidade').or('ativo.eq.1,ativo.is.null');
  const prods = all || [];
  const zerados = prods.filter(p => Number(p.qtd) === 0);
  const criticos = prods.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5);
  const valor = prods.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0);
  const hojeSP = dateSP();
  const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true }).gte('created_at', hojeSP + 'T00:00:00-03:00').lte('created_at', hojeSP + 'T23:59:59-03:00');
  let msg = `📊 *RELATÓRIO DIÁRIO — ${hojeSP}*\n🐰 Toca do Coelho\n\n📦 ${prods.length} produtos | 💰 R$ ${valor.toFixed(2)}\n📋 ${lancHoje||0} lançamentos hoje\n\n`;
  if (zerados.length) { msg += `🔴 *ZERADOS (${zerados.length})*\n${zerados.slice(0,15).map(p=>`• ${p.nome}`).join('\n')}${zerados.length>15?`\n... e mais ${zerados.length-15}`:''}\n\n`; }
  if (criticos.length) { msg += `🟠 *CRÍTICOS (${criticos.length})*\n${criticos.slice(0,10).map(p=>`• ${p.nome}: ${p.qtd}/${p.minimo} ${p.unidade}`).join('\n')}\n\n`; }
  // Alerta estoque parado alto giro
  const CATS_GIRO_REL = ['Hortifruti', 'Aves', 'Massa Fresca', 'Carnes Bovinas', 'Carnes Suínas', 'Pescados', 'Laticínios', 'Outras Proteínas', 'Bebidas'];
  const { data: prodGiro } = await supabase.from('produtos').select('id, nome, categoria, grupo_troca').or('ativo.eq.1,ativo.is.null').in('categoria', CATS_GIRO_REL);
  if (prodGiro && prodGiro.length > 0) {
    const idsGiro = prodGiro.map(p => p.id);
    const { data: movsGiro } = await supabase.from('movimentacoes').select('produto_id, created_at').in('produto_id', idsGiro).order('created_at', { ascending: false });
    const lastMG = {};
    for (const m of (movsGiro || [])) { if (!lastMG[m.produto_id]) lastMG[m.produto_id] = m.created_at; }
    // grupo de troca: irmão girando = grupo vivo (Alcatra parada com Coxão Mole em uso não alarma)
    const lastGrupoRel = {};
    for (const p of prodGiro) {
      if (p.grupo_troca && lastMG[p.id]) {
        const t = new Date(lastMG[p.id]).getTime();
        if (!lastGrupoRel[p.grupo_troca] || t > lastGrupoRel[p.grupo_troca]) lastGrupoRel[p.grupo_troca] = t;
      }
    }
    const paradosRel = prodGiro.filter(p => {
      // Mesma constante do /api/alertas/estoque-parado — antes usava "|| 10" fixo aqui, um
      // terço do padrão real (THRESHOLD_PADRAO=30). Hoje as 9 categorias deste relatório já
      // têm limite próprio definido, então isso não mudava nada NA PRÁTICA ainda — mas se uma
      // categoria nova entrar na lista sem limite definido, os dois relatórios divergiam.
      const th = THRESHOLDS_ALERTA[p.categoria] || THRESHOLD_PADRAO;
      if (p.grupo_troca && lastGrupoRel[p.grupo_troca] && (Date.now() - lastGrupoRel[p.grupo_troca]) < th * 86400000) return false;
      const last = lastMG[p.id];
      if (!last) return true;
      return Math.floor((Date.now() - new Date(last).getTime()) / 86400000) >= th;
    });
    if (paradosRel.length > 0) {
      msg += `\n\n⚠️ *ALTO GIRO SEM MOVIMENTO (${paradosRel.length})*\n${paradosRel.slice(0,12).map(p => `• ${p.nome} (${p.categoria})`).join('\n')}${paradosRel.length > 12 ? `\n... +${paradosRel.length-12}` : ''}`;
    }
  }
  msg += `_Backup automático às 18h ✅_`;
  res.json({ mensagem: msg, zerados: zerados.length, criticos: criticos.length, valor_total: valor });
});

app.get('*', (req, res) => { res.set('Cache-Control', 'no-cache, no-store, must-revalidate'); res.sendFile(path.join(__dirname, 'public', 'index.html')); });

// Middleware de erro do Express (4 argumentos) -- é aqui que o next(err) do
// wrapper acima (e qualquer catch(next) explícito nas rotas) desemboca. Sem
// isso o Express usaria a página de erro padrão em HTML; aqui a resposta segue
// sempre JSON, como o resto da API. TenantError vira 400 (pedido mal formado
// pelo cliente -- faltou tenant), o resto 500.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  console.error('[erro não tratado]', req.method, req.originalUrl, err && err.stack || err);
  const status = err && err.name === 'TenantError' ? 400 : (err && err.statusCode) || 500;
  res.status(status).json({ erro: (err && err.message) || 'Erro interno.' });
});

// ==================== START ====================
// No modo multi-restaurante o seed não se aplica: produtos e usuários pertencem a um
// restaurante, e cada um nasce com os seus (ou importa o catálogo-modelo). O erro que
// isso dava no boot era o isolamento funcionando — consulta a tabela de dado sem
// restaurante definido é recusada de propósito.
(MULTI_TENANT ? Promise.resolve() : seed()).then(async () => {
  await initSessionsBackend();
  app.listen(PORT, () => {
    console.log(`🐰 Toca do Coelho — Estoque (Supabase) rodando em http://localhost:${PORT}`);
    console.log(`⏰ Backup automático configurado para ${process.env.HORA_BACKUP || '18:00'}`);
  });
}).catch(err => { console.error('❌ Erro ao inicializar:', err.message); process.exit(1); });

