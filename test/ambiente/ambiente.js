// Ambiente DESCARTÁVEL de teste: Postgres 17 local (embedded-postgres) + PostgREST 16 (o mesmo motor REST
// do Supabase) + uma ponte em /rest/v1, que é o caminho que o supabase-js usa.
//
// Nada aqui conecta à produção. O banco nasce vazio a cada execução a partir de schema-producao.sql (só
// estrutura, extraída em leitura) e é apagado no fim.
//
// Requer: node_modules/embedded-postgres (devDependency) e test/.ambiente/bin/postgrest.exe (baixado do
// GitHub oficial do PostgREST; a pasta é ignorada pelo git). Ver test/README.md.
const path = require('path');
const fs = require('fs');
const net = require('net');
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const EmbeddedPostgres = require('embedded-postgres').default;
const { Client } = require('pg');

const RAIZ = path.join(__dirname, '..', '..');
const BIN_POSTGREST = path.join(RAIZ, 'test', '.ambiente', 'bin', process.platform === 'win32' ? 'postgrest.exe' : 'postgrest');
const PG_BIN = path.join(RAIZ, 'node_modules', '@embedded-postgres', `${process.platform === 'win32' ? 'windows' : process.platform}-x64`, 'native', 'bin');

function portaLivre() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.unref();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

const b64url = (b) => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
function jwt(payload, segredo) {
  const cab = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const corpo = b64url(JSON.stringify(payload));
  const ass = b64url(crypto.createHmac('sha256', segredo).update(`${cab}.${corpo}`).digest());
  return `${cab}.${corpo}.${ass}`;
}

async function esperar(fn, ms = 20000) {
  const ate = Date.now() + ms;
  for (;;) {
    try { if (await fn()) return; } catch { /* ainda subindo */ }
    if (Date.now() > ate) throw new Error('timeout esperando o ambiente subir');
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function subirAmbienteUmaVez({ sqlExtra = [] } = {}) {
  if (!fs.existsSync(BIN_POSTGREST)) throw new Error(`PostgREST não encontrado em ${BIN_POSTGREST}. Ver test/README.md`);
  const id = crypto.randomBytes(4).toString('hex');
  const dir = path.join(RAIZ, 'test', '.ambiente', `pg-${id}`);
  const portaPg = await portaLivre();
  const senha = crypto.randomBytes(12).toString('hex');
  const pg = new EmbeddedPostgres({ databaseDir: dir, user: 'postgres', password: senha, port: portaPg, persistent: false, onLog: () => {}, onError: () => {},
    // UTF-8 como na produção: o padrão do Windows (WIN1252) recusa emoji, e o app grava 📅 na observação do retroativo.
    initdbFlags: ['--encoding=UTF8', '--locale=C'] });
  await pg.initialise();
  await pg.start();

  const cfgPg = { host: '127.0.0.1', port: portaPg, user: 'postgres', password: senha, database: 'postgres' };
  const admin = new Client(cfgPg);
  await admin.connect();
  // Valores FIXOS de propósito: o ambiente é só local e descartável, e segredos aleatórios coincidiram com
  // abortos intermitentes do PostgREST no Windows (código 3).
  const segredo = 'segredo-local-de-teste-com-mais-de-32-caracteres-fixo';
  const senhaAuth = 'senha_local_de_teste';
  // Papéis no formato do Supabase: o PostgREST entra como authenticator e assume service_role pelo JWT.
  await admin.query(`
    create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
    create role authenticator login password '${senhaAuth}' noinherit;
    grant anon, authenticated, service_role to authenticator;
  `);
  await admin.query(fs.readFileSync(path.join(__dirname, 'schema-producao.sql'), 'utf8'));
  for (const s of sqlExtra) await admin.query(s);
  await admin.query(`
    grant usage on schema public to anon, authenticated, service_role;
    grant all on all tables in schema public to service_role;
    grant all on all sequences in schema public to service_role;
    grant execute on all functions in schema public to service_role;
  `);

  const conf = path.join(dir, '..', `postgrest-${id}.conf`);
  // No Windows a variável chama "Path"; criar "PATH" ao lado gera duas e o processo filho pode pegar a errada.
  const chavePath = Object.keys(process.env).find((k) => k.toUpperCase() === 'PATH') || 'PATH';
  const envFilho = { ...process.env, [chavePath]: `${PG_BIN}${path.delimiter}${process.env[chavePath] || ''}` };
  // A partida do PostgREST no Windows falha de vez em quando (sai com código 3 logo no início).
  // Tenta de novo, em outra porta, antes de desistir: teste instável por causa do ambiente não serve.
  let proc, portaRest, ultimoErro = '';
  for (let tentativa = 1; tentativa <= 4 && !proc; tentativa++) {
    portaRest = await portaLivre();
    fs.writeFileSync(conf, [
      `db-uri = "postgres://authenticator:${senhaAuth}@127.0.0.1:${portaPg}/postgres"`,
      'db-schemas = "public"',
      'db-anon-role = "anon"',
      `jwt-secret = "${segredo}"`,
      `server-port = ${portaRest}`,
      'server-host = "127.0.0.1"',
      'db-pool = 10',
      // Igual ao Supabase: cada consulta devolve no máximo 1.000 linhas (é o que torna F9 reproduzível).
      'db-max-rows = 1000',
      'log-level = "error"',
    ].join('\n'));
    const p = spawn(BIN_POSTGREST, [conf], { env: envFilho, stdio: ['ignore', 'pipe', 'pipe'] });
    let log = '';
    p.stdout.on('data', (d) => { log += d; });
    p.stderr.on('data', (d) => { log += d; });
    try {
      await esperar(() => new Promise((ok) => {
        if (p.exitCode !== null) return ok(false);
        http.get(`http://127.0.0.1:${portaRest}/`, (r) => { r.resume(); ok(r.statusCode < 500); }).on('error', () => ok(false));
      }), 8000);
      proc = p;
    } catch {
      p.kill();
      ultimoErro = `${log.slice(-400) || '(sem saída)'} | código ${p.exitCode}`;
    }
  }
  if (!proc) {
    // Descarta esta instância inteira (banco + arquivos) antes de desistir dela.
    await admin.end().catch(() => {});
    await pg.stop().catch(() => {});
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(conf, { force: true });
    throw new Error(`PostgREST não subiu após 4 tentativas: ${ultimoErro}`);
  }

  // Ponte /rest/v1 → PostgREST (o supabase-js sempre fala com <url>/rest/v1/...).
  const portaPonte = await portaLivre();
  const ponte = http.createServer((req, res) => {
    const alvo = req.url.replace(/^\/rest\/v1/, '') || '/';
    const p = http.request({ host: '127.0.0.1', port: portaRest, path: alvo, method: req.method, headers: req.headers }, (r) => {
      res.writeHead(r.statusCode, r.headers);
      r.pipe(res);
    });
    p.on('error', (e) => { res.writeHead(502); res.end(String(e.message)); });
    req.pipe(p);
  });
  await new Promise((r) => ponte.listen(portaPonte, '127.0.0.1', r));

  const chaveServico = jwt({ role: 'service_role', iss: 'teste-local', iat: Math.floor(Date.now() / 1000) }, segredo);
  let parado = false;
  return {
    url: `http://127.0.0.1:${portaPonte}`,
    chave: chaveServico,
    db: admin,
    novaConexao: async () => { const c = new Client(cfgPg); await c.connect(); return c; },
    recarregarEsquemaRest: () => admin.query(`notify pgrst, 'reload schema'`),
    async parar() {
      if (parado) return;
      parado = true;
      await new Promise((r) => ponte.close(r));
      proc.kill();
      await admin.end().catch(() => {});
      await pg.stop().catch(() => {});
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(conf, { force: true });
    },
  };
}

// Em ~1 de 8 execuções no Windows o PostgREST aborta (código 3) em TODAS as tentativas contra aquela
// instância do Postgres. Causa não identificada; a saída prática é descartar a instância e subir outra.
async function subirAmbiente(opcoes) {
  let ultimo;
  for (let i = 1; i <= 3; i++) {
    try { return await subirAmbienteUmaVez(opcoes); } catch (e) { ultimo = e; }
  }
  throw ultimo;
}

module.exports = { subirAmbiente };
