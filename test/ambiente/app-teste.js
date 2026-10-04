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

  async function api(role, metodo, caminho, corpo) {
    const r = await fetch(base + caminho, {
      method: metodo,
      headers: { authorization: `Bearer ${tokens[role]}`, 'content-type': 'application/json' },
      body: corpo === undefined ? undefined : JSON.stringify(corpo),
    });
    let json = null;
    try { json = await r.json(); } catch { /* sem corpo */ }
    return { status: r.status, json };
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
    base, api, db: amb.db, novaConexao: amb.novaConexao, criarProduto, saldo, movimentos,
    async parar() { await new Promise((r) => servidor.close(r)); await amb.parar(); },
  };
}

module.exports = { subirApp };
