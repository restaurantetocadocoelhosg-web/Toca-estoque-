// Sobe o app REAL (server.js) contra o ambiente descartável, com um restaurante e três usuários logados.
// Uso nos testes:  const ctx = await subirApp();  ...  await ctx.parar();
const path = require('path');
const crypto = require('crypto');
const { subirAmbiente } = require('./ambiente');

const SERVER = path.join(__dirname, '..', '..', 'server.js');

async function subirApp() {
  const amb = await subirAmbiente();
  await amb.db.query(`insert into tenants (id, nome, slug, plano, ativo) values (1, 'Restaurante Teste', 'teste', 'completo', true)`);
  const tokens = {};
  for (const role of ['admin', 'gerente', 'operador']) {
    const { rows } = await amb.db.query(
      `insert into users (username, nome, role, password_hash, active, tenant_id) values ($1, $2, $3, 'nao-usado-em-teste', 1, 1) returning id`,
      [`teste_${role}`, `Teste ${role}`, role]);
    const token = crypto.randomBytes(24).toString('hex');
    await amb.db.query(`insert into sessions (token, user_id, username, nome, role, last_activity) values ($1, $2, $3, $4, $5, now())`,
      [token, rows[0].id, `teste_${role}`, `Teste ${role}`, role]);
    tokens[role] = token;
  }

  // Variáveis do app apontando SÓ para o ambiente local. Sobrescreve qualquer .env carregado.
  Object.assign(process.env, {
    NODE_ENV: 'test', SUPABASE_URL: amb.url, SUPABASE_SERVICE_KEY: amb.chave, SUPABASE_SCHEMA: 'public',
    MULTI_TENANT: 'on', ANTHROPIC_API_KEY: '', WEBHOOK_SECRET: 'segredo-de-teste-local', TZ: 'America/Sao_Paulo',
  });
  delete require.cache[require.resolve(SERVER)];
  const { app, initSessionsBackend } = require(SERVER);
  await initSessionsBackend();
  const servidor = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const base = `http://127.0.0.1:${servidor.address().port}`;

  async function apiToken(token, metodo, caminho, corpo) {
    const r = await fetch(base + caminho, {
      method: metodo,
      headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), 'content-type': 'application/json' },
      body: corpo === undefined ? undefined : JSON.stringify(corpo),
    });
    let json = null;
    try { json = await r.json(); } catch { /* sem corpo */ }
    return { status: r.status, json };
  }
  const api = (role, metodo, caminho, corpo) => apiToken(tokens[role], metodo, caminho, corpo);

  // Mais uma sessão aberta para o usuário do papel (ex.: "outro aparelho").
  async function novaSessao(role) {
    const { rows: [u] } = await amb.db.query('select id from users where username = $1', [`teste_${role}`]);
    const token = crypto.randomBytes(24).toString('hex');
    await amb.db.query(`insert into sessions (token, user_id, username, nome, role, last_activity) values ($1, $2, $3, $4, $5, now())`,
      [token, u.id, `teste_${role}`, `Teste ${role}`, role]);
    return { token, userId: u.id };
  }

  async function criarProduto({ nome = 'Produto Teste', unidade = 'un', qtd = 0, custo = 1, categoria = 'Teste' } = {}) {
    const { rows } = await amb.db.query(
      `insert into produtos (nome, nome_search, categoria, unidade, qtd, minimo, custo, ativo, tenant_id) values ($1, lower($1), $2, $3, $4, 0, $5, 1, 1) returning id`,
      [nome, categoria, unidade, qtd, custo]);
    return rows[0].id;
  }
  const saldo = async (id) => Number((await amb.db.query('select qtd from produtos where id = $1', [id])).rows[0].qtd);
  const movimentos = async (id) => (await amb.db.query('select * from movimentacoes where produto_id = $1 order by id', [id])).rows;

  return {
    // Depois de mexer em função/tabela pelo SQL: o PostgREST relê o esquema (assíncrono).
    async recarregarEsquemaRest() { await amb.recarregarEsquemaRest(); await new Promise((r) => setTimeout(r, 800)); },
    // Espera o PostgREST enxergar (ou deixar de enxergar) uma função. Tempo fixo não basta: com o
    // cache velho a chamada dá 42883 (não PGRST202), e o teste passaria pelo motivo errado.
    async esperarFuncaoRest(nome, deveExistir, limiteMs = 10000) {
      const fim = Date.now() + limiteMs;
      for (;;) {
        await amb.recarregarEsquemaRest();
        // Assinatura completa (sem ela o PostgREST diz PGRST202 mesmo com a função existindo), com
        // valores que a função recusa na 1ª validação: a sondagem nunca grava nada.
        const args = nome === 'estoque_cancelar' ? { p_tenant: 0, p_mov_id: 0 }
          : { p_tenant: 0, p_produto_id: 0, p_tipo: 'SONDA', p_qtd: 1, p_custo: null, p_atualiza_custo: false, p_valor: null, p_motivo: null, p_responsavel: null, p_obs: null, p_created_at: null, p_evento_id: null };
        const r = await fetch(`${amb.url}/rest/v1/rpc/${nome}`, { method: 'POST', headers: { apikey: amb.chave, authorization: `Bearer ${amb.chave}`, 'content-type': 'application/json' }, body: JSON.stringify(args) });
        const corpo = await r.json().catch(() => ({}));
        const ausente = corpo.code === 'PGRST202';
        if (ausente !== deveExistir) return;
        if (Date.now() > fim) throw new Error(`PostgREST não atualizou ${nome} (deveExistir=${deveExistir})`);
        await new Promise((res) => setTimeout(res, 300));
      }
    },
    base, api, apiToken, novaSessao, db: amb.db, novaConexao: amb.novaConexao, criarProduto, saldo, movimentos,
    async parar() { await new Promise((r) => servidor.close(r)); await amb.parar(); },
  };
}

module.exports = { subirApp };
