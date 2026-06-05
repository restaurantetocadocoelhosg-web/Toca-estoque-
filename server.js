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
  return String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, max);
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
const PERM_KEYS = ['lancar','exportar','ia','auditoria','alertas','agenda','admin'];
function permsPorRole(role) {
  if (role === 'admin')   return { lancar:true, exportar:true, ia:true, auditoria:true, alertas:true, agenda:true, admin:true };
  if (role === 'gerente') return { lancar:true, exportar:true, ia:true, auditoria:true, alertas:true, agenda:true, admin:false };
  return { lancar:true, exportar:true, ia:false, auditoria:false, alertas:true, agenda:true, admin:false }; // operador (padrão = acesso que já tinha; admin libera IA/auditoria por pessoa)
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
async function seed() {
  const { count } = await supabase.from('users').select('id', { count: 'exact', head: true });
  if (count === 0) {
    const seedUsers = [
      { username: 'admin', nome: 'Administrador', role: 'admin', password_hash: hashPassword(process.env.ADMIN_PASSWORD || 'Toca123!'), active: 1 },
      { username: 'nayara.admin', nome: 'Nayara', role: 'admin', password_hash: hashPassword(process.env.SEED_PASSWORD_NAYARA || 'Nayara@2026Tc'), active: 1 },
      { username: 'simone.gerente', nome: 'Simone', role: 'gerente', password_hash: hashPassword(process.env.SEED_PASSWORD_SIMONE || 'Simone@2026Tc'), active: 1 },
      { username: 'estoque.operacao', nome: 'Estoque', role: 'operador', password_hash: hashPassword(process.env.SEED_PASSWORD_ESTOQUE || 'Estoque@2026Tc'), active: 1 },
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
  if (q) query = query.ilike('nome_search', `%${normalizeSearch(sanitizeText(q, 100))}%`);
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
  const { data } = await supabase.from('produtos').select('id, nome, categoria, unidade, qtd, minimo, custo')
    .ilike('nome_search', `%${normalizeSearch(q)}%`).or('ativo.eq.1,ativo.is.null').order('nome').limit(15);
  res.json(data || []);
});

app.get('/api/categorias', auth, async (req, res) => {
  const { data } = await supabase.from('produtos').select('categoria').or('ativo.eq.1,ativo.is.null').order('categoria');
  const unique = [...new Set((data || []).map(r => r.categoria).filter(Boolean))];
  res.json(unique);
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
  const { data: atualizado, error } = await supabase.from('produtos').update({
    nome, nome_search: normalizeSearch(nome), categoria, unidade, custo, minimo,
  }).eq('id', req.params.id).select().single();
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

// ==================== ROTAS MOVIMENTAÇÕES ====================
app.post('/api/movimentacoes', auth, async (req, res) => {
  const produto_nome = sanitizeText(req.body?.produto_nome, 120);
  const tipo = sanitizeText(req.body?.tipo, 20);
  const motivo = sanitizeText(req.body?.motivo, 80);
  let obs = sanitizeText(req.body?.obs, 200);
  const qtdInput = req.body?.qtd;

  if (!produto_nome || !['Entrada', 'Saída', 'Perda', 'Ajuste'].includes(tipo))
    return res.status(400).json({ erro: 'Produto e tipo válidos são obrigatórios.' });

  const { data: prod } = await supabase.from('produtos').select('*').ilike('nome', produto_nome).single();
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });

  let qtd = tipo === 'Ajuste' ? parseNonNegativeNumber(qtdInput) : parsePositiveNumber(qtdInput);
  if (qtd === null)
    return res.status(400).json({ erro: tipo === 'Ajuste' ? 'Ajuste deve ser zero ou maior.' : 'Quantidade deve ser maior que zero.' });

  const custoBody = req.body?.custo === '' || req.body?.custo === null || req.body?.custo === undefined
    ? null : parseNonNegativeNumber(req.body?.custo);
  if (req.body?.custo !== '' && req.body?.custo !== null && req.body?.custo !== undefined && custoBody === null)
    return res.status(400).json({ erro: 'Custo informado é inválido.' });

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
  await supabase.from('produtos').update({ qtd: novaQtd }).eq('id', prod.id);
  await supabase.from('movimentacoes').delete().eq('id', mov.id);
  await audit('cancelar_movimentacao', { mov_id: mov.id, produto: mov.produto_nome, tipo: mov.tipo, qtd: mov.qtd }, req.user, getClientIp(req));
  res.json({ ok: true, novaQtd });
});

app.get('/api/movimentacoes', auth, async (req, res) => {
  const tipo = sanitizeText(req.query?.tipo, 20);
  const q = sanitizeText(req.query?.q, 100);
  const limit = Math.min(Math.max(parseInt(req.query?.limit || '200', 10), 1), 500);
  let query = supabase.from('movimentacoes').select('*');
  if (tipo) query = query.eq('tipo', tipo);
  if (q) query = query.or(`produto_nome.ilike.%${q}%,motivo.ilike.%${q}%,obs.ilike.%${q}%,responsavel.ilike.%${q}%`);
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
app.post('/api/ler-cupom', auth, requirePerm('lancar'), async (req, res) => {
  const { imagem, mediaType } = req.body;
  if (!imagem) return res.status(400).json({ erro: 'Imagem não enviada.' });
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(500).json({ erro: 'ANTHROPIC_API_KEY não configurada no servidor.' });
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6', max_tokens: 16384,
        messages: [{ role: 'user', content: [
          { type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: imagem } },
          { type: 'text', text: `Você está lendo um CUPOM FISCAL / NOTA FISCAL (NFC-e) de compras de um restaurante brasileiro.\nExtraia TODOS os itens com nome, quantidade e unidade.\n\nESTRUTURA DA NOTA: cada item tem colunas — Descrição, QUANTIDADE (Qtd/Qtde/Quant), Unidade (UN/KG/CX/PCT), Valor Unitário (Vl Unit) e Valor Total (Vl Total). A QUANTIDADE é a coluna que importa — NUNCA o volume/peso que aparece no nome.\n\nCOMO ACERTAR A QUANTIDADE (regra de ouro):\n1. Pegue o número da COLUNA de quantidade (Qtd) da linha do item.\n2. CONFIRA dividindo: Valor Total ÷ Valor Unitário = quantidade. Use isso para corrigir leituras erradas. Ex: total 42,00 e unit 3,50 -> qtd 12.\n3. O volume/tamanho no nome (350ML, 500ML, 2L, 1KG, 5KG, 20KG) NUNCA é a quantidade.\n4. Multiplicador 'N x' ou 'x N' ou 'NX' ou 'A x B': a quantidade é o NÚMERO DE UNIDADES. Ex: 'COCA 350ML 12X' -> 12 | 'AGUA 500ML X 24' -> 24 | '350x12' -> 12 | 'REFRI 2L X 6' -> 6.\n5. IMPORTANTE: itens de compra de restaurante quase NUNCA têm quantidade 1. Se você leu 1, RELEIA a coluna de quantidade e o valor total — quase sempre a quantidade é maior.\n\nREGRA DE UNIDADE (o restaurante compra quase tudo por QUILO):\n- PROTEÍNAS são SEMPRE KG: file de frango, peito, coxa, sobrecoxa, asa, coracao, carne, boi, alcatra, patinho, acem, coxao, musculo, suino, porco, lombo, pernil, costela, linguica, bacon, salsicha, peixe, pescado, tilapia, salmao, camarao, bacalhau, file, mignon, fraldinha, picanha. Para proteína a qtd é o PESO em kg.\n- CAIXA/CX/FARDO COM PESO (ex 'FILE FRANGO CX 20KG', 'CARNE 18 KG') -> qtd = o peso em KG, não 1 caixa.\n- Hortifruti, grãos, farinhas a granel: KG quando vier em peso.\n- UN só para itens realmente unitários e fechados: latas, garrafas, vidros, potes, pacotes, descartáveis.\n- L para litro. CX só quando for contagem de caixas SEM peso.\n\nRESPONDA SOMENTE com JSON válido, sem markdown, no formato:\n{\"itens\":[{\"nome\":\"Nome do produto\",\"qtd\":12,\"unidade\":\"UN\"}]}\n\nExemplos:\n'COCA-COLA 350ML 12X 3,50 42,00' -> {nome:'Coca-Cola 350ml', qtd:12, unidade:'UN'}\n'AGUA 500ML X 24 UN 1,20 28,80' -> qtd:24, UN\n'FILE FRANGO CX 20KG' -> qtd:20, KG\n'PEITO FGO 18,5 KG' -> qtd:18.5, KG\n\nLeia com MUITA atenção cada linha. Em dúvida entre unidade e quilo numa proteína, escolha KG. Se não conseguir ler: {\"itens\":[],\"erro\":\"descrição do problema\"}` }
        ]}]
      })
    });
    if (!response.ok) {
      const errBody = (await response.text()).slice(0, 500);
      console.error('Anthropic API error [ler-cupom]:', response.status, errBody);
      return res.status(502).json({ erro: 'Erro na API (' + response.status + '): ' + errBody });
    }
    const data = await response.json();
    const text = (data.content || []).map(b => b.text || '').join('');
    let parsed;
    try { parsed = JSON.parse(text.replace(/```json|```/g, '').trim()); }
    catch(e) { return res.status(422).json({ erro: 'Foto ilegível. Tente uma imagem mais nítida e bem iluminada.' }); }
    if (parsed.erro) return res.json({ itens: [], aviso: parsed.erro });

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
      let candidatos = [], via_sinonimo = false;
      const prodNomeSinonimo = sinoMap[qNorm];
      if (prodNomeSinonimo) {
        const sp = prodByNomeLower[prodNomeSinonimo.toLowerCase()];
        if (sp) { candidatos = [sp]; via_sinonimo = true; }
      }
      if (!candidatos.length) {
        const palavras = qNorm.split(/\s+/).filter(w => w.length > 2);
        const scoreMap = new Map();
        for (const p of todosProds) {
          const ns = (p.nome_search || p.nome || '').toLowerCase();
          let score = 0;
          for (const w of palavras) if (ns.includes(w)) score++;
          if (score > 0) scoreMap.set(p.id, { produto: p, score });
        }
        if (scoreMap.size > 0) {
          candidatos = Array.from(scoreMap.values())
            .sort((a, b) => b.score - a.score).slice(0, 3).map(r => r.produto);
        } else {
          candidatos = todosProds
            .filter(p => (p.nome_search || p.nome || '').toLowerCase().includes(qNorm))
            .slice(0, 3);
        }
      }
      itens.push({ nome_cupom: item.nome, qtd: Number(item.qtd) || 1, unidade_cupom: item.unidade || 'UN', candidatos, produto: candidatos[0] || null, via_sinonimo });
    }
    await audit('ler_cupom', { total_itens: itens.length }, req.user, getClientIp(req));
    res.json({ itens });
  } catch(e) {
    console.error('Erro ler-cupom:', e.message);
    await logErroAgenda('ler-cupom', e, req.user);
    res.status(500).json({ erro: 'Erro interno: ' + e.message });
  }
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

async function executarFerramenta(nome, input, user) {
  try {
    switch (nome) {

      case 'buscar_produto': {
        const q = sanitizeText(input.nome, 100);
        const { data } = await supabase.from('produtos')
          .select('id, nome, categoria, qtd, minimo, custo, unidade')
          .ilike('nome_search', `%${normalizeSearch(q)}%`)
          .or('ativo.eq.1,ativo.is.null').order('nome').limit(10);
        return {
          encontrados: (data || []).length,
          produtos: (data || []).map(p => {
            const st = Number(p.qtd) === 0 ? 'ZERADO' : Number(p.qtd) <= Number(p.minimo) * 0.5 ? 'CRITICO' : Number(p.qtd) < Number(p.minimo) ? 'ATENCAO' : 'OK';
            return { ...p, status: st, valor_em_estoque: Number((Number(p.qtd) * Number(p.custo)).toFixed(2)) };
          })
        };
      }

      case 'listar_produtos': {
        let q = supabase.from('produtos').select('id, nome, categoria, qtd, minimo, custo, unidade').or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
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
        const { data: prod } = await supabase.from('produtos').select('id, nome, qtd, unidade, minimo').ilike('nome', nomeBusca).single();
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
        if (input.produto_nome) q = q.ilike('produto_nome', `%${sanitizeText(input.produto_nome, 100)}%`);
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
        const { data: prod } = await supabase.from('produtos').select('*').ilike('nome', nomeBusca).single();
        if (!prod) return { sucesso: false, erro: `Produto "${nomeBusca}" não encontrado. Use buscar_produto para ver nomes exatos.` };
        let novaQtd = Number(prod.qtd);
        if (tipo === 'Entrada') novaQtd = Number((novaQtd + qtd).toFixed(3));
        else if (tipo === 'Saída' || tipo === 'Perda') {
          if (qtd > novaQtd) return { sucesso: false, erro: `Estoque insuficiente: disponível ${prod.qtd} ${prod.unidade}` };
          novaQtd = Number((novaQtd - qtd).toFixed(3));
        } else novaQtd = Number(qtd.toFixed(3));
        const custoUnit = input.custo !== undefined ? (parseNonNegativeNumber(input.custo) || Number(prod.custo || 0)) : Number(prod.custo || 0);
        const valorBase = tipo === 'Ajuste' ? Math.abs(novaQtd - Number(prod.qtd)) : qtd;
        const valor = Number((custoUnit * valorBase).toFixed(2));
        const updateData = { qtd: novaQtd };
        if (tipo === 'Entrada' && input.custo !== undefined) updateData.custo = custoUnit;
        const { error: updErr } = await supabase.from('produtos').update(updateData).eq('id', prod.id);
        if (updErr) return { sucesso: false, erro: 'Erro ao atualizar estoque' };
        const { error: movErr } = await supabase.from('movimentacoes').insert({
          produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
          tipo, qtd: tipo === 'Ajuste' ? novaQtd : qtd, unidade: prod.unidade,
          custo: custoUnit, valor, motivo: sanitizeText(input.motivo || 'Via assistente IA', 80),
          responsavel: user && user.nome ? user.nome : 'IA', obs: 'Registrado pelo assistente IA',
          qtd_antes: Number(prod.qtd), qtd_depois: novaQtd, created_at: nowSP(),
        });
        if (movErr) { await supabase.from('produtos').update({ qtd: prod.qtd }).eq('id', prod.id); return { sucesso: false, erro: 'Erro ao registrar movimentação' }; }
        await audit('movimentacao_ia', { produto: prod.nome, tipo, qtd, nova_qtd: novaQtd }, user, '');
        return { sucesso: true, produto: prod.nome, tipo, qtd, qtd_antes: Number(prod.qtd), qtd_depois: novaQtd, unidade: prod.unidade };
      }

      case 'atualizar_produto': {
        if (!['admin','gerente'].includes(user && user.role)) return { sucesso: false, erro: 'Permissão insuficiente. Requer gerente ou admin.' };
        const nomeBusca = sanitizeText(input.produto_nome, 120);
        const { data: prod } = await supabase.from('produtos').select('*').ilike('nome', nomeBusca).single();
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
app.post('/api/chat', auth, requirePerm('ia'), async (req, res) => {
  let isInit = !!(req.body && req.body.init);
  // Só o admin dispara a varredura automática; outros usuários não rodam análise ao abrir.
  if (isInit && req.user.role !== 'admin') {
    return res.json({ resposta: '', movimentos_executados: [], pulado: 'nao_admin' });
  }
  // Admin: se já rodou hoje, devolve o resultado em cache (não reprocessa).
  if (isInit && varreduraCache.dia === dateSP() && varreduraCache.resposta) {
    return res.json({ resposta: varreduraCache.resposta, movimentos_executados: [], cache: true });
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
    '- Se a busca trouxer vários parecidos, NÃO chute: liste as opções numeradas e pergunte qual. Só peça esclarecimento quando for realmente ambíguo — se dá pra entender, responda direto.\n' +
    '- Perguntas curtas (ex.: "e o frango?") devem ser entendidas no contexto do histórico da conversa.\n\n' +
    'COMO AGIR:\n' +
    '1. Responda SEMPRE em português brasileiro, direto e curto. Nada de repetir a pergunta nem enrolar.\n' +
    '2. Todo número (qtd, custo, valor) vem das ferramentas — NUNCA invente.\n' +
    '3. Seja proativo: ao buscar, se notar algo grave (zerado urgente, giro parado, anomalia), avise e registre na agenda.\n' +
    '4. Antes de registrar movimentação, confirme produto + quantidade + tipo (salvo se já estiver claro). Depois, mostre o NOVO saldo.\n' +
    '5. Ao terminar uma tarefa, diga em 1 linha o que foi feito.\n\n' +
    'FORMATO DAS RESPOSTAS (o app mostra TEXTO PURO com quebras de linha e emojis — NÃO use markdown: nada de **negrito**, # ou tabelas):\n' +
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

    if (isInit) varreduraCache = { dia: dateSP(), resposta: textoFinal };
    await audit('chat_ia', { pergunta: isInit ? '__boot__' : pergunta.slice(0, 100), lancamentos: movimentosExecutados.length }, req.user, getClientIp(req));
    res.json({ resposta: textoFinal, movimentos_executados: movimentosExecutados });
  } catch(e) {
    await logErroAgenda('chat', e, req.user);
    res.status(500).json({ erro: 'Erro interno: ' + e.message });
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
    const { data: produtos } = await supabase.from('produtos').select('id, nome, categoria, qtd, unidade, minimo').or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    const ids = (produtos || []).map(p => p.id);
    if (!ids.length) return res.json({ alertas: [], resumo: { total: 0, criticos: 0, atencao: 0, sem_historico: 0 } });
    const { data: todosMov } = await supabase.from('movimentacoes').select('produto_id, created_at, tipo, responsavel').in('produto_id', ids).order('created_at', { ascending: false });
    const lastMovMap = {};
    for (const m of (todosMov || [])) { if (!lastMovMap[m.produto_id]) lastMovMap[m.produto_id] = m; }
    const agora = Date.now();
    const alertas = [];
    for (const p of (produtos || [])) {
      const thDias = THRESHOLDS_ALERTA[p.categoria] || THRESHOLD_PADRAO;
      const lastMov = lastMovMap[p.id];
      const diasParado = lastMov ? Math.floor((agora - new Date(lastMov.created_at).getTime()) / 86400000) : null;
      if (diasParado === null || diasParado >= thDias) {
        const urgencia = diasParado === null ? 'SEM_HISTORICO' : diasParado >= thDias * 2 ? 'CRITICO' : 'ATENCAO';
        alertas.push({ produto_id: p.id, nome: p.nome, categoria: p.categoria, qtd: p.qtd, unidade: p.unidade,
          dias_parado: diasParado, ultimo_movimento: lastMov?.created_at || null,
          ultimo_responsavel: lastMov?.responsavel || null, threshold_dias: thDias, urgencia });
      }
    }
    alertas.sort((a, b) => { const o = { SEM_HISTORICO: 0, CRITICO: 1, ATENCAO: 2 };
      return o[a.urgencia] !== o[b.urgencia] ? o[a.urgencia] - o[b.urgencia] : (b.dias_parado||999) - (a.dias_parado||999); });
    const resumo = { total: alertas.length,
      criticos: alertas.filter(a => a.urgencia === 'CRITICO').length,
      atencao: alertas.filter(a => a.urgencia === 'ATENCAO').length,
      sem_historico: alertas.filter(a => a.urgencia === 'SEM_HISTORICO').length };
    await audit('alertas_estoque_parado', resumo, req.user, getClientIp(req));
    res.json({ alertas, resumo });
  } catch(e) { res.status(500).json({ erro: 'Erro interno: ' + e.message }); }
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
      .select('produto_id, tipo, qtd, qtd_antes, qtd_depois, obs, created_at, responsavel')
      .in('produto_id', ids)
      .order('created_at', { ascending: false });
    const movByProd = {};
    for (const m of (movs || [])) {
      if (!movByProd[m.produto_id]) movByProd[m.produto_id] = { entradas: 0, saidas: 0, ajusteDelta: 0, ajusteDown: 0, nAjuste: 0, ultimo: null, ultimo_responsavel: null };
      const g = movByProd[m.produto_id];
      if (m.tipo === 'Entrada') g.entradas += Number(m.qtd);
      else if (m.tipo === 'Saída' || m.tipo === 'Perda') g.saidas += Number(m.qtd);
      else if (m.tipo === 'Ajuste') {
        const delta = Number(m.qtd_depois || 0) - Number(m.qtd_antes || 0);
        g.ajusteDelta += delta; g.nAjuste++;
        // Ajuste de sincronização (reset/restauração) é administrativo, NÃO contagem física —
        // entra no saldo (p/ não acusar desync) mas não conta como "sumiço".
        if (delta < 0 && m.obs !== 'sincronização automática') g.ajusteDown += Math.abs(delta);
      }
      if (!g.ultimo) { g.ultimo = m.created_at; g.ultimo_responsavel = m.responsavel; }
    }
    // Conferência cruzada: reconstrói o saldo pelo histórico (entrada − saída ± ajuste)
    // e compara com a qtd real. Classifica em vez de acusar todo zerado às cegas.
    const fantasmas = [];
    for (const p of (produtos || [])) {
      const h = movByProd[p.id];
      if (!h || h.entradas === 0) continue;            // nunca teve entrada: não é fantasma
      const saldoHist = Number((h.entradas - h.saidas + h.ajusteDelta).toFixed(3));
      let classe, label, explica;
      if (Math.abs(saldoHist) > 0.001) {
        // Histórico fecha com saldo, mas o estoque está 0: a qtd foi zerada POR FORA
        // do app (reset/importação/edição em massa) — é dado furado, não consumo.
        classe = 'desync'; label = '🟡 dado furado';
        explica = `o histórico fecha em ${saldoHist} ${p.unidade}, mas o estoque está 0 — foi zerado por fora do app (reset/importação), não por uso`;
      } else if (h.ajusteDown > 0.001 && h.saidas === 0) {
        // Contagem física zerou o item sem nenhuma saída lançada = uso não registrado.
        classe = 'sumico'; label = '🔴 sumiu sem baixa';
        explica = `a contagem zerou ${Number(h.ajusteDown.toFixed(3))} ${p.unidade} sem nenhuma saída lançada — alguém usou sem registrar`;
      } else {
        continue;                                       // explicado por saída/contagem normal
      }
      fantasmas.push({ produto_id: p.id, nome: p.nome, categoria: p.categoria, unidade: p.unidade,
        total_entradas: Number(h.entradas.toFixed(3)), total_saidas: Number(h.saidas.toFixed(3)),
        ajustes: h.nAjuste, saldo_historico: saldoHist, classe, label, explica,
        ultimo_movimento: h.ultimo, ultimo_responsavel: h.ultimo_responsavel });
    }
    const ordem = { sumico: 0, desync: 1 };
    fantasmas.sort((a, b) => (ordem[a.classe] - ordem[b.classe]) || (new Date(b.ultimo_movimento) - new Date(a.ultimo_movimento)));
    res.json({ fantasmas });
  } catch(e) { res.status(500).json({ erro: 'Erro interno: ' + e.message }); }
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
      .select('produto_id, tipo, qtd, qtd_antes, qtd_depois').in('produto_id', ids);
    const agg = {};
    for (const m of (movs || [])) {
      if (!agg[m.produto_id]) agg[m.produto_id] = { entradas: 0, saidas: 0, ajusteDelta: 0 };
      const g = agg[m.produto_id];
      if (m.tipo === 'Entrada') g.entradas += Number(m.qtd);
      else if (m.tipo === 'Saída' || m.tipo === 'Perda') g.saidas += Number(m.qtd);
      else if (m.tipo === 'Ajuste') g.ajusteDelta += (Number(m.qtd_depois || 0) - Number(m.qtd_antes || 0));
    }
    let reconciliados = 0;
    for (const p of (produtos || [])) {
      const g = agg[p.id];
      if (!g || g.entradas === 0) continue;
      const saldoHist = Number((g.entradas - g.saidas + g.ajusteDelta).toFixed(3));
      if (Math.abs(saldoHist) <= 0.001) continue;       // já fecha — não é dado furado
      const custoUnit = Number(p.custo || 0);
      // Ajuste corretivo: delta = (qtd real − saldo do histórico) = −saldoHist. qtd fica igual.
      await supabase.from('movimentacoes').insert({
        produto_id: p.id, produto_nome: p.nome, categoria: p.categoria,
        tipo: 'Ajuste', qtd: Number(p.qtd), unidade: p.unidade,
        custo: custoUnit, valor: Number((custoUnit * Math.abs(saldoHist)).toFixed(2)),
        motivo: 'Reconciliação (acerto de histórico)', responsavel: req.user.nome,
        obs: 'sincronização automática',
        qtd_antes: saldoHist, qtd_depois: Number(p.qtd), created_at: nowSP(),
      });
      reconciliados++;
    }
    await audit('reconciliar_fantasmas', { reconciliados, alvo: alvoId || 'todos' }, req.user, getClientIp(req));
    res.json({ reconciliados });
  } catch(e) { res.status(500).json({ erro: 'Erro interno: ' + e.message }); }
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
  const { data: prod } = await supabase.from('produtos').select('nome').ilike('nome', produto_nome).single();
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
      const { data: prod } = await supabase.from('produtos').select('nome').ilike('nome', s.produto_nome).single();
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
  const groups = {};
  for (const m of (allMovs || [])) {
    const key = m.produto_nome;
    if (!groups[key]) groups[key] = { produto_nome: m.produto_nome, categoria: m.categoria, unidade: m.unidade, total_entrada: 0, total_saida: 0, total_perda: 0, total_ajuste_delta: 0, num_ajustes: 0, valor_entrada: 0, valor_saida: 0, num_saidas: 0, num_entradas: 0 };
    const g = groups[key];
    if (m.tipo === 'Entrada') { g.total_entrada += Number(m.qtd); g.valor_entrada += Number(m.valor || 0); g.num_entradas++; }
    if (['Saída','Perda'].includes(m.tipo)) { g.total_saida += Number(m.qtd); g.valor_saida += Number(m.valor || 0); g.num_saidas++; }
    if (m.tipo === 'Perda') g.total_perda += Number(m.qtd);
    if (m.tipo === 'Ajuste') { g.total_ajuste_delta += (Number(m.qtd_depois || 0) - Number(m.qtd_antes || 0)); g.num_ajustes++; }
  }
  const { data: produtos } = await supabase.from('produtos').select('nome, qtd, minimo');
  const estoqueMap = {};
  for (const p of (produtos || [])) estoqueMap[p.nome] = { qtd: Number(p.qtd), minimo: Number(p.minimo) };
  const resultado = Object.values(groups).filter(g => g.total_entrada > 0 || g.total_saida > 0 || g.num_ajustes > 0).map(r => {
    const qtdAtual = estoqueMap[r.produto_nome]?.qtd ?? null;
    // Saldo do PERÍODO = movimento líquido (entrada − saída ± ajustes). NÃO é o estoque
    // absoluto — só bate com a qtd_atual se o período cobrir desde a última base do item.
    const saldo = Number((r.total_entrada - r.total_saida + r.total_ajuste_delta).toFixed(3));
    return { ...r, total_entrada: Number(r.total_entrada.toFixed(3)), total_saida: Number(r.total_saida.toFixed(3)),
      total_perda: Number(r.total_perda.toFixed(3)), total_ajuste_delta: Number(r.total_ajuste_delta.toFixed(3)),
      num_ajustes: r.num_ajustes, valor_entrada: Number(r.valor_entrada.toFixed(2)),
      valor_saida: Number(r.valor_saida.toFixed(2)), saldo, qtd_atual: qtdAtual,
      alerta: r.total_saida > 0 && r.total_entrada > 0 && r.total_saida > r.total_entrada * 1.5,
      sem_entrada: r.total_saida > 0 && r.total_entrada === 0 };
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
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'toca-webhook-2026';

app.post('/api/webhook/whatsapp', async (req, res) => {
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
    const buscaNorm = normalizeSearch(produto_nome);
    const { data: matches } = await supabase.from('produtos').select('*').ilike('nome_search', `%${buscaNorm}%`).or('ativo.eq.1,ativo.is.null').order('nome').limit(6);
    if (!matches || !matches.length) return res.json({ resposta: `Não encontrei "${produto_nome}" no estoque.` });
    let prod = matches.length === 1 ? matches[0] : matches.find(p => normalizeSearch(p.nome) === buscaNorm);
    if (!prod) {
      const ops = matches.slice(0, 6).map(p => `• ${p.nome}`).join('\n');
      return res.json({ resposta: `Encontrei ${matches.length} produtos com "${produto_nome}". Seja mais especifico:\n\n${ops}` });
    }
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
    const { data } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, unidade').or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    const todos = data || [];
    const semMinimo = todos.filter(p => Number(p.minimo) <= 0 && Number(p.qtd) === 0).length;
    const lista = todos.filter(p => Number(p.minimo) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5);
    const nota = semMinimo > 0 ? `\n\n(+ ${semMinimo} zerados sem mínimo definido — defina o mínimo no app para entrarem na lista)` : '';
    if (!lista.length) return res.json({ resposta: '✅ Estoque OK! Nada para comprar urgente.' + nota });
    return res.json({ resposta: `🛒 *LISTA DE COMPRAS (${lista.length} itens)*\n\n${lista.map(p=>`• ${p.nome}: tem ${p.qtd}, comprar ~${Math.max(0,Number(p.minimo)*2-Number(p.qtd)).toFixed(1)} ${p.unidade}`).join('\n')}${nota}` });
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
    for (const m of lista) {
      const r = m.responsavel || 'Não identificado';
      if (!porResp[r]) porResp[r] = { ent: 0, sai: 0, perda: 0, ajuste: 0 };
      if (m.tipo === 'Entrada') { porResp[r].ent++; totEnt++; }
      else if (m.tipo === 'Saída') { porResp[r].sai++; totSai++; }
      else if (m.tipo === 'Perda') { porResp[r].perda++; totPerda++; }
      else if (m.tipo === 'Ajuste') { porResp[r].ajuste++; totAjuste++; }
      valor += Number(m.valor) || 0;
      if (m.obs && /anomalia/i.test(m.obs)) anomalias++;
    }
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
    msg += `\n💰 Valor movimentado: R$ ${valor.toFixed(2)}\n\n`;
    msg += `👤 *Quem lançou hoje:*\n${linhasResp}`;
    if (anomalias > 0) msg += `\n\n⚠️ ${anomalias} lançamento(s) com quantidade anômala — revise no app.`;
    if (totPerda > 0) msg += `\n🗑️ ${totPerda} perda(s) registrada(s) hoje — confira os motivos.`;
    return res.json({ resposta: msg, total: lista.length, entradas: totEnt, saidas: totSai, perdas: totPerda, ajustes: totAjuste, valor: Number(valor.toFixed(2)), por_responsavel: porResp, anomalias });
  }

  if (acao === 'conferencia') {
    const dias = Math.min(Math.max(parseInt(req.body?.dias) || 7, 1), 60);
    const desde = dateAgoDias(dias);
    const { data: movs } = await supabase.from('movimentacoes')
      .select('produto_nome, categoria, tipo, qtd, qtd_antes, qtd_depois, custo')
      .in('tipo', ['Ajuste','Perda']).gte('created_at', desde + 'T00:00:00-03:00');
    const lista = movs || [];
    const sumido = {}; let totalValor = 0; let nAjustes = 0; let totalPerdaValor = 0;
    for (const m of lista) {
      if (m.tipo === 'Ajuste') {
        nAjustes++;
        const delta = Number(m.qtd_depois || 0) - Number(m.qtd_antes || 0);
        if (delta < 0) {
          const k = m.produto_nome || '?';
          if (!sumido[k]) sumido[k] = { qtd: 0, valor: 0 };
          sumido[k].qtd += Math.abs(delta);
          sumido[k].valor += Math.abs(delta) * Number(m.custo || 0);
          totalValor += Math.abs(delta) * Number(m.custo || 0);
        }
      } else if (m.tipo === 'Perda') {
        totalPerdaValor += Number(m.qtd || 0) * Number(m.custo || 0);
      }
    }
    const dataBR = dateSP().split('-').reverse().join('/');
    if (nAjustes === 0) {
      return res.json({ resposta: `🔎 *CONFERÊNCIA DE ESTOQUE — últimos ${dias} dias*\n📅 ${dataBR}\n\n⚠️ Nenhuma contagem física (ajuste) foi feita no período.\n\nSem contagem, não dá para saber se está sumindo item. Faça a contagem dos itens de alto giro (carnes, refrigerantes, ovos) e lance os ajustes no app.`, total_sumido: 0, contagens: 0 });
    }
    const top = Object.entries(sumido).sort((a,b)=>b[1].valor-a[1].valor).slice(0,12);
    let msg = `🔎 *CONFERÊNCIA DE ESTOQUE — últimos ${dias} dias*\n📅 ${dataBR}\n\n`;
    if (!top.length) {
      msg += `✅ Tudo bateu! ${nAjustes} contagem(ns) feita(s) e nenhum item sumido. 👏`;
    } else {
      msg += `💸 *Itens que sumiram* (contagem achou MENOS que o sistema):\n\n`;
      msg += top.map(([nome, d]) => `• ${nome}: -${Number(d.qtd).toFixed(d.qtd % 1 === 0 ? 0 : 1)} (R$ ${d.valor.toFixed(2)})`).join('\n');
      msg += `\n\n💰 *Total sumido: R$ ${totalValor.toFixed(2)}*`;
      msg += `\n📋 ${nAjustes} contagem(ns) no período.`;
      msg += `\n\n_Causa comum: saída não lançada. Cobre a equipe no fechamento diário._`;
    }
    if (totalPerdaValor > 0) msg += `\n🗑️ Perdas declaradas: R$ ${totalPerdaValor.toFixed(2)}`;
    return res.json({ resposta: msg, total_sumido: Number(totalValor.toFixed(2)), contagens: nAjustes, perdas_valor: Number(totalPerdaValor.toFixed(2)), itens: top.map(([n,d])=>({nome:n,qtd:d.qtd,valor:Number(d.valor.toFixed(2))})) });
  }

  res.json({ resposta: `🐰 *Toca do Coelho — Estoque*\n\nComandos: consultar | resumo | zerados | criticos | compras | entrada | saida | fechamento | conferencia` });
});

app.get('/api/webhook/relatorio-diario', async (req, res) => {
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
  const { data: prodGiro } = await supabase.from('produtos').select('id, nome, categoria').or('ativo.eq.1,ativo.is.null').in('categoria', CATS_GIRO_REL);
  if (prodGiro && prodGiro.length > 0) {
    const idsGiro = prodGiro.map(p => p.id);
    const { data: movsGiro } = await supabase.from('movimentacoes').select('produto_id, created_at').in('produto_id', idsGiro).order('created_at', { ascending: false });
    const lastMG = {};
    for (const m of (movsGiro || [])) { if (!lastMG[m.produto_id]) lastMG[m.produto_id] = m.created_at; }
    const paradosRel = prodGiro.filter(p => {
      const last = lastMG[p.id];
      if (!last) return true;
      return Math.floor((Date.now() - new Date(last).getTime()) / 86400000) >= (THRESHOLDS_ALERTA[p.categoria] || 10);
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
