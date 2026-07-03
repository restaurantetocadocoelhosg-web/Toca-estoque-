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

// ==================== SUPABASE ====================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ SUPABASE_URL e SUPABASE_SERVICE_KEY são obrigatórios!');
  process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

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
const PERM_KEYS = ['lancar','exportar','ia','auditoria','alertas','agenda','pendencias','admin'];
function permsPorRole(role) {
  // 'pendencias' (resolver itens em dúvida da nota do WhatsApp): admin-only por padrão;
  // admin libera por pessoa no painel de liberações.
  if (role === 'admin')   return { lancar:true, exportar:true, ia:true, auditoria:true, alertas:true, agenda:true, pendencias:true, admin:true };
  if (role === 'gerente') return { lancar:true, exportar:true, ia:true, auditoria:true, alertas:true, agenda:true, pendencias:false, admin:false };
  return { lancar:true, exportar:true, ia:false, auditoria:false, alertas:true, agenda:true, pendencias:false, admin:false }; // operador (padrão = acesso que já tinha; admin libera IA/auditoria/pendencias por pessoa)
}
function permsEfetivas(role, permissoes) {
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
    .from('users').select('id, username, nome, role, active').eq('id', session.user_id).single();
  if (!user || !user.active) {
    await deleteSession(token);
    return res.status(401).json({ erro: 'Usuário inativo ou inválido.' });
  }

  await touchSession(token);
  req.user = user;
  req.token = token;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role))
      return res.status(403).json({ erro: 'Você não tem permissão para esta ação.' });
    next();
  };
}

// Enforcement de liberações no servidor (admin sempre passa).
function requirePerm(key) {
  return async (req, res, next) => {
    if (req.user.role === 'admin') return next();
    let permsCol = null;
    try { const { data: u } = await supabase.from('users').select('permissoes').eq('id', req.user.id).single(); permsCol = u && u.permissoes; } catch(e) {}
    const perms = permsEfetivas(req.user.role, permsCol);
    if (perms[key]) return next();
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

  const token = await createSession(user);
  await audit('login', { username: user.username }, user, getClientIp(req));
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
      pode_exportar: perms.exportar, pode_lancar: perms.lancar,
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
  let query = supabase.from('produtos').select('*');
  if (arquivados === '1' && req.user.role === 'admin') query = query.eq('ativo', 0);
  else query = query.or('ativo.eq.1,ativo.is.null');
  if (q) { const qq = sanitizeText(q, 100); query = query.or(`nome_search.ilike.%${normalizeSearch(qq)}%,codigo.ilike.%${qq.toUpperCase()}%`); }
  if (cat) query = query.eq('categoria', sanitizeText(cat, 80));
  query = query.order('categoria').order('nome');
  const { data: rows, error } = await query;
  if (error) return res.status(500).json({ erro: 'Erro ao buscar produtos.' });
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
  const { data } = await supabase.from('produtos').select('id, nome, codigo, categoria, unidade, qtd, minimo, custo')
    .or(`nome_search.ilike.%${normalizeSearch(q)}%,codigo.ilike.%${q.toUpperCase()}%`).or('ativo.eq.1,ativo.is.null').order('nome').limit(15);
  res.json(data || []);
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
app.post('/api/categorias', auth, requireRole('admin', 'gerente'), async (req, res) => {
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

app.put('/api/categorias/renomear', auth, requireRole('admin'), async (req, res) => {
  const de = sanitizeText(req.body?.de, 80);
  const para = sanitizeText(req.body?.para, 80);
  if (!de || !para || de === para) return res.status(400).json({ erro: 'Informe a categoria atual e o novo nome.' });
  const { data: afetados } = await supabase.from('produtos').select('id').eq('categoria', de);
  await supabase.from('produtos').update({ categoria: para }).eq('categoria', de);
  await supabase.from('categorias').delete().eq('nome', de);
  await supabase.from('categorias').upsert({ nome: para }, { onConflict: 'nome' });
  await audit('renomear_categoria', { de, para, produtos_afetados: (afetados || []).length }, req.user, getClientIp(req));
  res.json({ ok: true, produtos_afetados: (afetados || []).length });
});

app.delete('/api/categorias/:nome', auth, requireRole('admin'), async (req, res) => {
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
  if ((tipo === 'Saída' || tipo === 'Perda') && !req.body.forcar) {
    const trintaDias = dateAgoDias(30);
    const { data: hist } = await supabase.from('movimentacoes')
      .select('qtd').eq('produto_id', prod.id)
      .in('tipo', ['Saída', 'Perda']).gte('created_at', trintaDias + 'T00:00:00-03:00');
    if (hist && hist.length >= 5) {
      const totalConsumo = hist.reduce((s, m) => s + Number(m.qtd), 0);
      const mediaDiaria = totalConsumo / 30;
      if (mediaDiaria > 0 && qtd > mediaDiaria * 3) {
        if (req.user.role === 'operador') {
          return res.status(409).json({
            alerta: true, codigo: 'QUANTIDADE_SUSPEITA',
            media_diaria: Number(mediaDiaria.toFixed(2)), qtd_lancada: qtd, unidade: prod.unidade,
            msg: `Quantidade ${qtd} ${prod.unidade} é ${(qtd/mediaDiaria).toFixed(1)}× acima da média diária (${mediaDiaria.toFixed(1)} ${prod.unidade}). Chame o gerente para confirmar.`
          });
        } else {
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

  const { error: movErr } = await supabase.from('movimentacoes').insert({
    produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
    tipo, qtd: tipo === 'Ajuste' ? novaQtd : qtd, unidade: prod.unidade,
    custo: custoUnit, valor, motivo, responsavel: req.user.nome, obs,
    qtd_antes: qtdAntes, qtd_depois: novaQtd,
    created_at: nowSP(),
  });
  if (movErr) {
    await supabase.from('produtos').update({ qtd: qtdAntes, custo: prodAtual.custo }).eq('id', prod.id).eq('qtd', novaQtd);
    return res.status(500).json({ erro: 'Erro ao registrar movimentação.' });
  }

  await audit('movimentacao', { produto_id: prod.id, produto_nome: prod.nome, tipo, qtd, nova_qtd: novaQtd, motivo }, req.user, getClientIp(req));
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
      { onConflict: 'produto_id,data', ignoreDuplicates: true });
  } catch(e) { console.error('Snapshot diario erro:', e.message); }
}

// ==================== DASHBOARD ====================
app.get('/api/dashboard', auth, async (req, res) => {
  ensureSnapshotDiario().catch(() => {});
  const { data: produtos } = await supabase.from('produtos').select('qtd, minimo, custo');
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

// ==================== EXPORTAR ====================
app.get('/api/exportar/:tipo', auth, requirePerm('exportar'), async (req, res) => {
  const { tipo } = req.params;
  let rows, headers, filename;
  if (tipo === 'estoque') {
    const { data } = await supabase.from('produtos').select('nome, categoria, unidade, qtd, minimo, custo').order('categoria').order('nome');
    headers = ['Produto','Categoria','Unidade','Qtd Atual','Mínimo','Custo Unit.','Valor Total','Status'];
    rows = (data || []).map(r => {
      let st = Number(r.qtd) === 0 ? 'ZERADO' : Number(r.qtd) <= Number(r.minimo) * 0.5 ? 'CRITICO' : Number(r.qtd) < Number(r.minimo) ? 'ATENCAO' : 'OK';
      return [r.nome, r.categoria, r.unidade, r.qtd, r.minimo, r.custo, (Number(r.qtd) * Number(r.custo)).toFixed(2), st];
    });
    filename = 'estoque_toca_coelho.csv';
  } else if (tipo === 'movimentacoes') {
    const { data } = await supabase.from('movimentacoes').select('*').order('id', { ascending: false });
    headers = ['Data/Hora','Produto','Categoria','Tipo','Qtd','Unidade','Custo','Valor','Motivo','Responsável','Obs'];
    rows = (data || []).map(r => [r.created_at, r.produto_nome, r.categoria, r.tipo, r.qtd, r.unidade, r.custo, r.valor, r.motivo, r.responsavel, r.obs]);
    filename = 'movimentacoes_toca_coelho.csv';
  } else if (tipo === 'compras') {
    const { data } = await supabase.from('produtos').select('nome, categoria, unidade, qtd, minimo').order('categoria').order('nome');
    headers = ['Produto','Categoria','Unidade','Qtd Atual','Mínimo','Sugerido Comprar'];
    rows = (data || []).filter(r => Number(r.qtd) <= Number(r.minimo) * 0.5)
      .map(r => [r.nome, r.categoria, r.unidade, r.qtd, r.minimo, Math.max(0, Number(r.minimo) * 2 - Number(r.qtd)).toFixed(3)]);
    filename = 'lista_compras_toca_coelho.csv';
  } else return res.status(400).json({ erro: 'Tipo inválido' });
  await audit('exportar', { tipo }, req.user, getClientIp(req));
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
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

app.get('/api/relatorio/:tipo', auth, requirePerm('exportar'), async (req, res) => {
  try {
    const tipo = req.params.tipo;
    let html;

    if (tipo === 'estoque' || tipo === 'compras') {
      const ehCompras = tipo === 'compras';
      const { data } = await supabase.from('produtos').select('nome, categoria, unidade, qtd, minimo, custo')
        .or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
      let prods = data || [];
      if (ehCompras) prods = prods.filter(p => Number(p.qtd) <= Number(p.minimo) * 0.5);  // zerados + críticos
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
        // Prefill '{' força a resposta a começar como JSON (evita a IA responder em texto e o parse quebrar).
        messages: [{ role: 'user', content: [
          ...listaImg.map(b64 => ({ type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: b64 } })),
          { type: 'text', text: avisoFatias + `Você está lendo um CUPOM FISCAL / NOTA FISCAL (NFC-e) de compras de um restaurante brasileiro.\nExtraia TODOS os itens com nome, quantidade e unidade.\n\nESTRUTURA DA NOTA: cada item tem colunas — Descrição, QUANTIDADE (Qtd/Qtde/Quant), Unidade (UN/KG/CX/PCT), Valor Unitário (Vl Unit) e Valor Total (Vl Total). A QUANTIDADE é a coluna que importa — NUNCA o volume/peso que aparece no nome.\n\nCOMO ACERTAR A QUANTIDADE (regra de ouro):\n1. Pegue o número da COLUNA de quantidade (Qtd) da linha do item.\n2. CONFIRA dividindo: Valor Total ÷ Valor Unitário = quantidade. Use isso para corrigir leituras erradas. Ex: total 42,00 e unit 3,50 -> qtd 12.\n3. O volume/tamanho no nome (350ML, 500ML, 2L, 1KG, 5KG, 20KG) NUNCA é a quantidade.\n4. Multiplicador 'N x' ou 'x N' ou 'NX' ou 'A x B': a quantidade é o NÚMERO DE UNIDADES. Ex: 'COCA 350ML 12X' -> 12 | 'AGUA 500ML X 24' -> 24 | '350x12' -> 12 | 'REFRI 2L X 6' -> 6.\n5. IMPORTANTE: itens de compra de restaurante quase NUNCA têm quantidade 1. Se você leu 1, RELEIA a coluna de quantidade e o valor total — quase sempre a quantidade é maior.\n\nREGRA DE UNIDADE (o restaurante compra quase tudo por QUILO):\n- PROTEÍNAS são SEMPRE KG: file de frango, peito, coxa, sobrecoxa, asa, coracao, carne, boi, alcatra, patinho, acem, coxao, musculo, suino, porco, lombo, pernil, costela, linguica, bacon, salsicha, peixe, pescado, tilapia, salmao, camarao, bacalhau, file, mignon, fraldinha, picanha. Para proteína a qtd é o PESO em kg.\n- CAIXA/CX/FARDO COM PESO (ex 'FILE FRANGO CX 20KG', 'CARNE 18 KG') -> qtd = o peso em KG, não 1 caixa.\n- Hortifruti, grãos, farinhas a granel: KG quando vier em peso.\n- UN só para itens realmente unitários e fechados: latas, garrafas, vidros, potes, pacotes, descartáveis.\n- L para litro. CX só quando for contagem de caixas SEM peso.\n\nRESPONDA SOMENTE com JSON válido, sem markdown, no formato:\n{\"itens\":[{\"nome\":\"Nome do produto\",\"qtd\":12,\"unidade\":\"UN\"}]}\n\nExemplos:\n'COCA-COLA 350ML 12X 3,50 42,00' -> {nome:'Coca-Cola 350ml', qtd:12, unidade:'UN'}\n'AGUA 500ML X 24 UN 1,20 28,80' -> qtd:24, UN\n'FILE FRANGO CX 20KG' -> qtd:20, KG\n'PEITO FGO 18,5 KG' -> qtd:18.5, KG\n\nLeia com MUITA atenção cada linha. Em dúvida entre unidade e quilo numa proteína, escolha KG. Se não conseguir ler: {\"itens\":[],\"erro\":\"descrição do problema\"}` }
        ]},
        { role: 'assistant', content: '{' }]
      })
    });
    if (!response.ok) {
      const errBody = (await response.text()).slice(0, 500);
      console.error('Anthropic API error [ler-cupom]:', response.status, errBody);
      return { status: 502, erro: 'Erro na API (' + response.status + '): ' + errBody };
    }
    const data = await response.json();
    // Reconstrói com o prefill '{' e extrai o JSON de forma tolerante, caso a IA acrescente texto fora do objeto.
    const bruto = '{' + (data.content || []).map(b => b.text || '').join('');
    const tentaParse = (s) => { try { return JSON.parse(s); } catch(e) { return null; } };
    let parsed = tentaParse(bruto.replace(/```json|```/g, '').trim());
    if (!parsed) { const ini = bruto.indexOf('{'), fim = bruto.lastIndexOf('}'); if (ini >= 0 && fim > ini) parsed = tentaParse(bruto.slice(ini, fim + 1)); }
    if (!parsed) {
      console.error('ler-cupom: resposta não-JSON da IA:', bruto.slice(0, 300));
      await logErroAgenda('ler-cupom parse', 'IA respondeu fora do formato: ' + bruto.slice(0, 150), userLog);
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
      itens.push({
        nome_cupom: item.nome,
        qtd: Number(item.qtd) || 1,
        unidade_cupom: item.unidade || 'UN',
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
          candidatos: (item.candidatos || []).map(c => ({ id: c.id, nome: c.nome, unidade: c.unidade, codigo: c.codigo || null })),
          remetente, status: 'pendente', created_at: nowSP(),
        });
        if (item.candidatos && item.candidatos.length) confirmar.push({ nome_cupom: item.nome_cupom, qtd: item.qtd, sugestao: item.candidatos[0].nome });
        else naoachados.push(`${item.nome_cupom} (${item.qtd})`);
        continue;
      }
      // Entrada com trava otimista (mesma blindagem do webhook entrada)
      let prodAtual = item.produto, novaQtd = 0, sucesso = false;
      for (let tent = 0; tent < 4 && !sucesso; tent++) {
        novaQtd = Number((Number(prodAtual.qtd) + Number(item.qtd)).toFixed(3));
        const { data: upd } = await supabase.from('produtos').update({ qtd: novaQtd }).eq('id', prodAtual.id).eq('qtd', prodAtual.qtd).select('id');
        if (upd && upd.length) { sucesso = true; break; }
        const { data: re } = await supabase.from('produtos').select('*').eq('id', item.produto.id).single();
        if (!re) break;
        prodAtual = re;
      }
      if (!sucesso) { confirmar.push({ nome_cupom: item.nome_cupom, qtd: item.qtd, sugestao: item.produto.nome }); continue; }
      await supabase.from('movimentacoes').insert({
        produto_id: item.produto.id, produto_nome: item.produto.nome, categoria: item.produto.categoria,
        tipo: 'Entrada', qtd: item.qtd, unidade: item.produto.unidade,
        custo: item.produto.custo, valor: Number((Number(item.produto.custo) * item.qtd).toFixed(2)),
        motivo: 'Compra', responsavel: remetente, obs: 'nota via WhatsApp', created_at: nowSP(),
      });
      lancados.push({ nome: item.produto.nome, qtd: item.qtd, unidade: item.produto.unidade, estoque: novaQtd });
    }
    // Salva os itens em dúvida como pendências (resolver no app, aba Histórico → Pendentes).
    if (pendencias.length) { try { await supabase.from('nota_pendencias').insert(pendencias); } catch (e) { console.error('pendencias insert:', e.message); } }
    await audit('ler_nota_whatsapp', { remetente, lancados: lancados.length, confirmar: confirmar.length, nao_achados: naoachados.length, pendencias: pendencias.length }, null, '');

    let msg = `🧾 *NOTA PROCESSADA* (por ${remetente})\n\n`;
    if (lancados.length) {
      msg += `✅ *Lançados (${lancados.length}):*\n` + lancados.map(l => `• ${l.nome}: +${l.qtd} ${l.unidade} (estoque: ${l.estoque})`).join('\n') + '\n';
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
  const qtd = Number(pend.qtd) || 0;
  if (qtd <= 0) return res.status(400).json({ erro: 'Quantidade inválida na pendência.' });

  // Entrada com trava otimista (mesma blindagem dos outros lançamentos).
  let prodAtual = prod, novaQtd = 0, sucesso = false;
  for (let tent = 0; tent < 4 && !sucesso; tent++) {
    novaQtd = Number((Number(prodAtual.qtd) + qtd).toFixed(3));
    const { data: upd } = await supabase.from('produtos').update({ qtd: novaQtd }).eq('id', prodAtual.id).eq('qtd', prodAtual.qtd).select('id');
    if (upd && upd.length) { sucesso = true; break; }
    const { data: re } = await supabase.from('produtos').select('*').eq('id', prod.id).single();
    if (!re) return res.status(500).json({ erro: 'Erro ao atualizar estoque.' });
    prodAtual = re;
  }
  if (!sucesso) return res.status(409).json({ erro: 'Outro lançamento simultâneo alterou o estoque. Tente de novo.' });

  const { error: movErr } = await supabase.from('movimentacoes').insert({
    produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
    tipo: 'Entrada', qtd, unidade: prod.unidade,
    custo: prod.custo, valor: Number((Number(prod.custo) * qtd).toFixed(2)),
    motivo: 'Compra', responsavel: req.user.nome, obs: 'nota WhatsApp (resolvido no app)', created_at: nowSP(),
  });
  if (movErr) { await supabase.from('produtos').update({ qtd: prodAtual.qtd }).eq('id', prod.id).eq('qtd', novaQtd); return res.status(500).json({ erro: 'Erro ao registrar movimentação.' }); }

  // "Memorizar": salva o apelido (nome da nota → produto), pra próxima lançar sozinho.
  if (memorizar && pend.produto_cupom) {
    try { await supabase.from('sinonimos').upsert({ termo: normalizeSearch(pend.produto_cupom), produto_nome: prod.nome }, { onConflict: 'termo' }); } catch (e) {}
  }
  await supabase.from('nota_pendencias').update({ status: 'resolvido', resolvido_em: nowSP(), resolvido_por: req.user.nome }).eq('id', pend.id);
  await audit('pendencia_resolver', { pendencia_id: pend.id, produto: prod.nome, qtd, memorizar }, req.user, getClientIp(req));
  res.json({ ok: true, produto: prod.nome, qtd, nova_qtd: novaQtd });
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
        const { data: all } = await supabase.from('produtos').select('qtd, minimo, custo');
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
    '2. Todo número (qtd, custo, valor, lançamentos de hoje) vem SEMPRE de uma chamada de ferramenta FEITA AGORA. NUNCA invente e NUNCA reaproveite números citados antes nesta conversa nem de relatórios anteriores — o estoque muda o tempo todo e aquilo já pode estar velho. Se perguntarem "o que mexeu hoje", chame ver_movimentacoes(hoje=true) na hora; se perguntarem saldo, chame buscar_produto na hora.\n' +
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
        // Haiku 4.5: ~3x mais rápido que o Sonnet no loop de ferramentas — evita o timeout do
        // celular (antes a conferência levava 24-34s e o app cortava a conexão). Qualidade
        // mais que suficiente pra consultar estoque/movimentações e resumir.
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 4096, system: systemPrompt, tools: IA_TOOLS, messages })
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
    const { data: movs } = await supabase.from('movimentacoes')
      .select('produto_id, tipo, qtd, obs, created_at, responsavel')
      .in('produto_id', ids)
      .order('created_at', { ascending: true });
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
    const { data: movs } = await supabase.from('movimentacoes')
      .select('produto_id, tipo, qtd, obs, created_at').in('produto_id', ids)
      .order('created_at', { ascending: true });
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
  // Liberações: aceita objeto permissoes { lancar, exportar, ia, auditoria, alertas, agenda, admin }
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
  const { error } = await supabase.from('sinonimos').upsert({ termo: normalizeSearch(termo), produto_nome: prod.nome }, { onConflict: 'termo' });
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
      await supabase.from('sinonimos').upsert({ termo, produto_nome: prod.nome }, { onConflict: 'termo' });
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
  let movQuery = supabase.from('movimentacoes').select('*').gte('created_at', dataInicio + 'T00:00:00-03:00').lte('created_at', dataFim + 'T23:59:59-03:00');
  if (categoria) movQuery = movQuery.eq('categoria', categoria);
  const { data: allMovs } = await movQuery;
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
  const { data: produtos } = await supabase.from('produtos').select('id, nome, categoria, unidade, qtd, minimo, custo, ativo');
  if (!produtos || !produtos.length) return null;
  const snapshot = { data_backup: nowSP(), motivo, total_produtos: produtos.length,
    valor_total: produtos.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0),
    zerados: produtos.filter(p => Number(p.qtd) === 0).length,
    criticos: produtos.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5).length,
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
    const { data: all } = await supabase.from('produtos').select('qtd, minimo, custo');
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
      const { data: upd } = await supabase.from('produtos').update({ qtd: novaQtd }).eq('id', prodAtual.id).eq('qtd', prodAtual.qtd).select('id');
      if (upd && upd.length) { sucesso = true; break; }
      const { data: re } = await supabase.from('produtos').select('*').eq('id', prod.id).single();
      if (!re) break;
      prodAtual = re;
    }
    if (!sucesso) return res.json({ resposta: `❌ Não consegui atualizar ${prod.nome} agora (outro lançamento simultâneo). Tente de novo em instantes.` });
    const qtdAntesW = Number(prodAtual.qtd);
    const { error: movErr } = await supabase.from('movimentacoes').insert({
      produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria, tipo, qtd, unidade: prod.unidade,
      custo: prod.custo, valor: Number((Number(prod.custo)*qtd).toFixed(2)),
      motivo: tipo === 'Entrada' ? 'Compra' : 'Produção', responsavel: remetente || 'WhatsApp', obs: 'via WhatsApp', created_at: nowSP(),
    });
    if (movErr) { await supabase.from('produtos').update({ qtd: qtdAntesW }).eq('id', prod.id).eq('qtd', novaQtd); return res.json({ resposta: `❌ Erro ao registrar movimentação de ${prod.nome}.` }); }
    await audit('movimentacao_whatsapp', { produto: prod.nome, tipo, qtd, nova_qtd: novaQtd, remetente }, null, '');
    return res.json({ resposta: `✅ *${tipo.toUpperCase()}* registrada!\n\n📦 ${prod.nome}\n📏 ${qtd} ${prod.unidade}\n📊 Estoque agora: ${novaQtd} ${prod.unidade}` });
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

  if (acao === 'fechamento') {
    const hojeSP = dateSP();
    const dataBR = hojeSP.split('-').reverse().join('/');
    const { data: movs } = await supabase.from('movimentacoes')
      .select('tipo, qtd, valor, responsavel, produto_nome, obs')
      .gte('created_at', hojeSP + 'T00:00:00-03:00').lte('created_at', hojeSP + 'T23:59:59-03:00');
    const lista = movs || [];
    if (!lista.length) {
      return res.json({ resposta: `📋 *FECHAMENTO DE ESTOQUE — ${dataBR}*\n\n⚠️ NENHUMA movimentação registrada hoje!\n\nA equipe não lançou entradas/saídas no sistema. Cobre os colaboradores do dia.`, vazio: true, total: 0 });
    }
    const porResp = {};
    let totEnt = 0, totSai = 0, totPerda = 0, totAjuste = 0, valor = 0, anomalias = 0;
    let valorEnt = 0, valorSai = 0, valorPerda = 0, valorAjuste = 0;
    for (const m of lista) {
      const r = m.responsavel || 'Não identificado';
      if (!porResp[r]) porResp[r] = { ent: 0, sai: 0, perda: 0, ajuste: 0 };
      const v = Number(m.valor) || 0;
      if (m.tipo === 'Entrada') { porResp[r].ent++; totEnt++; valorEnt += v; }
      else if (m.tipo === 'Saída') { porResp[r].sai++; totSai++; valorSai += v; }
      else if (m.tipo === 'Perda') { porResp[r].perda++; totPerda++; valorPerda += v; }
      else if (m.tipo === 'Ajuste') { porResp[r].ajuste++; totAjuste++; valorAjuste += v; }
      valor += v;
      if (m.obs && /anomalia/i.test(m.obs)) anomalias++;
    }
    const saldo = valorEnt - valorSai - valorPerda;
    const linhasResp = Object.entries(porResp)
      .sort((a, b) => (b[1].ent+b[1].sai+b[1].perda+b[1].ajuste) - (a[1].ent+a[1].sai+a[1].perda+a[1].ajuste))
      .map(([r, d]) => {
        const partes = [];
        if (d.ent) partes.push(`${d.ent} ent`);
        if (d.sai) partes.push(`${d.sai} saí`);
        if (d.perda) partes.push(`${d.perda} perda`);
        if (d.ajuste) partes.push(`${d.ajuste} ajuste`);
        return `• ${r}: ${d.ent+d.sai+d.perda+d.ajuste} (${partes.join(', ')})`;
      }).join('\n');
    let msg = `📋 *FECHAMENTO DE ESTOQUE — ${dataBR}*\n\n`;
    msg += `📊 Total: ${lista.length} movimentações\n`;
    msg += `📥 Entradas: ${totEnt} | 📤 Saídas: ${totSai}`;
    if (totPerda) msg += ` | 🗑️ Perdas: ${totPerda}`;
    if (totAjuste) msg += ` | ⚙️ Ajustes: ${totAjuste}`;
    msg += `\n\n💰 *Valores do dia:*\n`;
    msg += `📥 Entradas: R$ ${valorEnt.toFixed(2)}\n`;
    msg += `📤 Saídas:   R$ ${valorSai.toFixed(2)}\n`;
    if (valorPerda) msg += `🗑️ Perdas:   R$ ${valorPerda.toFixed(2)}\n`;
    if (valorAjuste) msg += `⚙️ Ajustes:  R$ ${valorAjuste.toFixed(2)}\n`;
    msg += `📊 Saldo:    R$ ${saldo.toFixed(2)}\n\n`;
    msg += `👤 *Quem lançou hoje:*\n${linhasResp}`;
    if (anomalias > 0) msg += `\n\n⚠️ ${anomalias} lançamento(s) com quantidade anômala — revise no app.`;
    if (totPerda > 0) msg += `\n🗑️ ${totPerda} perda(s) registrada(s) hoje — confira os motivos.`;
    return res.json({ resposta: msg, total: lista.length, entradas: totEnt, saidas: totSai, perdas: totPerda, ajustes: totAjuste, valor: Number(valor.toFixed(2)), valor_entradas: Number(valorEnt.toFixed(2)), valor_saidas: Number(valorSai.toFixed(2)), valor_perdas: Number(valorPerda.toFixed(2)), valor_ajustes: Number(valorAjuste.toFixed(2)), saldo: Number(saldo.toFixed(2)), por_responsavel: porResp, anomalias });
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

  res.json({ resposta: `🐰 *Toca do Coelho — Estoque*\n\nComandos: consultar | resumo | zerados | criticos | compras | entrada | saida | fechamento | conferencia | conferencia_mensal` });
});

app.get('/api/webhook/relatorio-diario', webhookLimiter, async (req, res) => {
  if (!WEBHOOK_SECRET) return res.status(503).json({ erro: 'Webhook não configurado no servidor.' });
  const secret = req.headers['x-webhook-secret'] || req.query?.secret;
  if (secret !== WEBHOOK_SECRET) return res.status(403).json({ erro: 'Acesso negado.' });
  const { data: all } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, custo, unidade');
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
      const th = THRESHOLDS_ALERTA[p.categoria] || 10;
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

// ==================== START ====================
seed().then(async () => {
  await initSessionsBackend();
  app.listen(PORT, () => {
    console.log(`🐰 Toca do Coelho — Estoque (Supabase) rodando em http://localhost:${PORT}`);
    console.log(`⏰ Backup automático configurado para ${process.env.HORA_BACKUP || '18:00'}`);
  });
}).catch(err => { console.error('❌ Erro ao inicializar:', err.message); process.exit(1); });

