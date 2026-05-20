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
app.use(express.static(path.join(__dirname, 'public')));

// ==================== HELPERS ====================
function nowIso() { return new Date().toISOString(); }

function nowSP() {
  const partes = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  }).formatToParts(new Date());
  const get = (type) => partes.find(p => p.type === type)?.value || '';
  return `${get('year')}-${get('month')}-${get('day')} ${get('hour')}:${get('minute')}:${get('second')}`;
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

app.get('/api/me', auth, (req, res) => {
  res.json({
    user: { id: req.user.id, username: req.user.username, nome: req.user.nome, role: req.user.role },
    permissions: {
      pode_resetar: req.user.role === 'admin',
      pode_editar_produto: ['admin', 'gerente'].includes(req.user.role),
      pode_exportar: true, pode_lancar: true,
    },
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
  if (q) query = query.ilike('nome', `%${sanitizeText(q, 100)}%`);
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
  const obs = sanitizeText(req.body?.obs, 200);
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
    const trintaDias = new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10);
    const { data: hist } = await supabase.from('movimentacoes')
      .select('qtd').eq('produto_id', prod.id)
      .in('tipo', ['Saída', 'Perda']).gte('created_at', trintaDias);
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

  let novaQtd = Number(prod.qtd);
  if (tipo === 'Entrada') novaQtd = Number((novaQtd + qtd).toFixed(3));
  else if (tipo === 'Saída' || tipo === 'Perda') {
    if (qtd > novaQtd) return res.status(400).json({ erro: `Estoque insuficiente. Disponível: ${prod.qtd} ${prod.unidade}.` });
    novaQtd = Number((novaQtd - qtd).toFixed(3));
  } else if (tipo === 'Ajuste') novaQtd = Number(qtd.toFixed(3));

  const custoUnit = custoBody !== null ? custoBody : Number(prod.custo || 0);
  const valorBase = tipo === 'Ajuste' ? Math.abs(novaQtd - Number(prod.qtd)) : qtd;
  const valor = Number((custoUnit * valorBase).toFixed(2));
  const updateData = { qtd: novaQtd };
  if (tipo === 'Entrada' && custoBody !== null) updateData.custo = custoUnit;

  const { error: updateErr } = await supabase.from('produtos').update(updateData).eq('id', prod.id);
  if (updateErr) return res.status(500).json({ erro: 'Erro ao atualizar estoque.' });

  const qtdAntes = Number(prod.qtd);
  const { error: movErr } = await supabase.from('movimentacoes').insert({
    produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
    tipo, qtd: tipo === 'Ajuste' ? novaQtd : qtd, unidade: prod.unidade,
    custo: custoUnit, valor, motivo, responsavel: req.user.nome, obs,
    qtd_antes: qtdAntes, qtd_depois: novaQtd,
    created_at: nowSP(),
  });
  if (movErr) {
    await supabase.from('produtos').update({ qtd: prod.qtd, custo: prod.custo }).eq('id', prod.id);
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
  if (dataInicio) query = query.gte('created_at', dataInicio);
  if (dataFim) query = query.lte('created_at', dataFim + 'T23:59:59');
  query = query.order('id', { ascending: false }).limit(limit);
  const { data } = await query;
  res.json(data || []);
});

// ==================== SNAPSHOT DIÁRIO ====================
async function ensureSnapshotDiario() {
  try {
    const hoje = nowSP().slice(0, 10);
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
  const hojeSP = nowSP().slice(0, 10);
  const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true })
    .gte('created_at', hojeSP).lte('created_at', hojeSP + 'T23:59:59');
  const { data: ultimos } = await supabase.from('movimentacoes').select('*').order('id', { ascending: false }).limit(8);
  res.json({ zerados, criticos, atencao, valorTotal, lancHoje: lancHoje || 0, ultimos: ultimos || [] });
});

// ==================== EXPORTAR ====================
app.get('/api/exportar/:tipo', auth, async (req, res) => {
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
app.post('/api/resetar', auth, requireRole('admin'), async (req, res) => {
  const confirmacao = sanitizeText(req.body?.confirmacao, 20).toUpperCase();
  if (confirmacao !== 'RESTAURAR') return res.status(400).json({ erro: 'Confirmação inválida. Digite RESTAURAR para continuar.' });
  const senhaAdmin = String(req.body?.senha_admin || '');
  const { data: userDb } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!verifyPassword(senhaAdmin, userDb.password_hash)) return res.status(401).json({ erro: 'Senha de administrador incorreta.' });
  const seedPath = path.join(__dirname, 'produtos_seed.json');
  if (!fs.existsSync(seedPath)) return res.status(404).json({ erro: 'Seed não encontrado.' });
  const produtos = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
  for (const p of produtos)
    await supabase.from('produtos').update({ qtd: p.qtd, custo: p.custo, minimo: p.minimo }).eq('nome', p.nome);
  await audit('resetar_estoque', { total_produtos: produtos.length }, req.user, getClientIp(req));
  res.json({ ok: true });
});

// ==================== LER CUPOM (IA) ====================
app.post('/api/ler-cupom', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const { imagem, mediaType } = req.body;
  if (!imagem) return res.status(400).json({ erro: 'Imagem não enviada.' });
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(500).json({ erro: 'ANTHROPIC_API_KEY não configurada no servidor.' });
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6', max_tokens: 4096,
        messages: [{ role: 'user', content: [
          { type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: imagem } },
          { type: 'text', text: `Você está lendo um cupom fiscal ou nota fiscal de um restaurante brasileiro.\nExtraia TODOS os itens comprados com nome do produto e quantidade.\nResponda SOMENTE com JSON válido, sem texto extra, sem markdown, no formato:\n{"itens":[{"nome":"Nome do produto","qtd":1.0,"unidade":"KG"}]}\nUse unidade KG para peso, UN para unidade, L para litro, CX para caixa.\nSe não conseguir ler: {"itens":[],"erro":"descrição do problema"}` }
        ]}]
      })
    });
    if (!response.ok) return res.status(502).json({ erro: 'Erro na API: ' + (await response.text()).slice(0, 300) });
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

    const itens = [];
    for (const item of (parsed.itens || [])) {
      const qNorm = normalizeSearch(item.nome);
      let candidatos = [], produtoExato = null;
      const prodNomeSinonimo = sinoMap[qNorm];
      if (prodNomeSinonimo) {
        const { data: p } = await supabase.from('produtos').select('id, nome, categoria, unidade, qtd, minimo, custo').ilike('nome', prodNomeSinonimo).single();
        if (p) { produtoExato = p; candidatos = [p]; }
      }
      if (!produtoExato) {
        const palavras = qNorm.split(/\s+/).filter(p => p.length > 2);
        if (palavras.length > 1) {
          const scoreMap = new Map();
          for (const palavra of palavras) {
            const { data: matches } = await supabase.from('produtos').select('id, nome, categoria, unidade, qtd, minimo, custo').ilike('nome_search', `%${palavra}%`).order('nome').limit(10);
            for (const m of (matches || [])) { const e = scoreMap.get(m.id) || { produto: m, score: 0 }; e.score++; scoreMap.set(m.id, e); }
          }
          if (scoreMap.size > 0) candidatos = Array.from(scoreMap.values()).sort((a, b) => b.score - a.score).slice(0, 3).map(r => r.produto);
        }
        if (!candidatos.length) {
          const { data: fallback } = await supabase.from('produtos').select('id, nome, categoria, unidade, qtd, minimo, custo').ilike('nome_search', `%${qNorm}%`).order('nome').limit(3);
          candidatos = fallback || [];
        }
      }
      itens.push({ nome_cupom: item.nome, qtd: Number(item.qtd) || 1, unidade_cupom: item.unidade || 'UN', candidatos, produto: candidatos[0] || null, via_sinonimo: !!produtoExato });
    }
    await audit('ler_cupom', { total_itens: itens.length }, req.user, getClientIp(req));
    res.json({ itens });
  } catch(e) {
    console.error('Erro ler-cupom:', e.message);
    res.status(500).json({ erro: 'Erro interno: ' + e.message });
  }
});

// ==================== ASSISTENTE IA ====================
app.post('/api/chat', auth, async (req, res) => {
  const pergunta = sanitizeText(req.body?.pergunta, 500);
  const historico = Array.isArray(req.body?.historico) ? req.body.historico.slice(-8) : [];
  if (!pergunta) return res.status(400).json({ erro: 'Pergunta não informada.' });
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(500).json({ erro: 'API não configurada.' });
  const { data: allProd } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, custo, unidade');
  const all = allProd || [];
  const totalProd = all.length;
  const zerados = all.filter(p => Number(p.qtd) === 0).length;
  const criticos = all.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5).length;
  const atencao_count = all.filter(p => Number(p.qtd) > Number(p.minimo) * 0.5 && Number(p.qtd) < Number(p.minimo)).length;
  const valorTotal = all.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0);
  const prodZerados = all.filter(p => Number(p.qtd) === 0).slice(0, 50);
  const prodCriticos = all.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5).slice(0, 50);
  const prodAtencao = all.filter(p => Number(p.qtd) > Number(p.minimo) * 0.5 && Number(p.qtd) < Number(p.minimo)).slice(0, 30);
  const hojeSP = nowSP().slice(0, 10);
  const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true }).gte('created_at', hojeSP).lte('created_at', hojeSP + 'T23:59:59');
  const { data: ultimosMov } = await supabase.from('movimentacoes').select('produto_nome, tipo, qtd, unidade, motivo, responsavel, created_at').gte('created_at', hojeSP).lte('created_at', hojeSP + 'T23:59:59').order('created_at', { ascending: false }).limit(200);
  const thirtyDaysAgo = new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10);
  const { data: movConsumo } = await supabase.from('movimentacoes').select('produto_nome, qtd, unidade').in('tipo', ['Saída', 'Perda']).gte('created_at', thirtyDaysAgo);
  const consumoMap = {};
  for (const m of (movConsumo || [])) { if (!consumoMap[m.produto_nome]) consumoMap[m.produto_nome] = { total: 0, unidade: m.unidade }; consumoMap[m.produto_nome].total += Number(m.qtd); }
  const maisConsumidos = Object.entries(consumoMap).sort((a, b) => b[1].total - a[1].total).slice(0, 10);
  // Alertas de giro parado para IA
  const CATS_ALTO_GIRO_IA = ['Hortifruti', 'Aves', 'Massa Fresca', 'Carnes Bovinas', 'Carnes Suínas', 'Pescados', 'Laticínios', 'Outras Proteínas', 'Bebidas'];
  const THRESHOLDS_IA = { 'Hortifruti': 7, 'Aves': 7, 'Massa Fresca': 7, 'Carnes Bovinas': 10, 'Carnes Suínas': 10, 'Pescados': 10, 'Laticínios': 10, 'Outras Proteínas': 10, 'Bebidas': 15 };
  const { data: lastMovGiro } = await supabase.from('movimentacoes')
    .select('produto_nome, created_at').in('categoria', CATS_ALTO_GIRO_IA).order('created_at', { ascending: false });
  const lastMovByNomeIA = {};
  for (const m of (lastMovGiro || [])) { if (!lastMovByNomeIA[m.produto_nome]) lastMovByNomeIA[m.produto_nome] = m.created_at; }
  const alertasParadosIA = all.filter(p => THRESHOLDS_IA[p.categoria]).reduce((acc, p) => {
    const last = lastMovByNomeIA[p.nome];
    const dias = last ? Math.floor((Date.now() - new Date(last).getTime()) / 86400000) : null;
    if (dias === null || dias >= THRESHOLDS_IA[p.categoria])
      acc.push({ nome: p.nome, cat: p.categoria, dias: dias !== null ? dias : 'sem histórico', qtd: p.qtd, unidade: p.unidade });
    return acc;
  }, []);
  const catMap = {};
  for (const p of all) {
    if (!catMap[p.categoria]) catMap[p.categoria] = { n: 0, valor: 0, prods: [] };
    catMap[p.categoria].n++;
    catMap[p.categoria].valor += Number(p.qtd) * Number(p.custo);
    const st = Number(p.qtd) === 0 ? 'ZERADO' : Number(p.qtd) <= Number(p.minimo) * 0.5 ? 'CRITICO' : Number(p.qtd) < Number(p.minimo) ? 'ATENCAO' : 'OK';
    catMap[p.categoria].prods.push(`[${st}] ${p.nome}: ${p.qtd} ${p.unidade}`);
  }
  const cats = Object.entries(catMap).sort((a, b) => a[0].localeCompare(b[0]));
  const contexto = `Você é o assistente de estoque do restaurante "Toca do Coelho" em São Gonçalo, Rio de Janeiro.\nResponda SEMPRE em português brasileiro. Seja direto e preciso.\nHoje é ${hojeSP}.\n\nREGRAS CRÍTICAS — NUNCA VIOLE:\n1. Use SOMENTE os dados fornecidos. NUNCA invente, estime ou suponha valores.\n2. "Itens em falta" = APENAS os de ZERADOS e CRÍTICOS.\n3. Ao listar produtos: nome + quantidade atual + mínimo.\n4. Produto não encontrado nos dados = diga "não há registro" (nunca "está OK" sem confirmar).\n5. Se houver itens em ALERTA GIRO PARADO, mencione os mais críticos proativamente.\n6. Ao executar lançamentos: confirme nome exato + tipo + quantidade ANTES do ACAO_JSON.\n\nCAPACIDADE DE LAN\u00c7AMENTO EM LOTE:\nQuando o usu\u00e1rio pedir para dar ENTRADA, SA\u00cdDA ou PERDA de itens (lista de texto), voc\u00ea DEVE:\n1. Identificar cada produto pelo nome EXATO conforme TODOS OS PRODUTOS POR CATEGORIA.\n2. Responder com confirma\u00e7\u00e3o clara em texto (liste os itens que vai lan\u00e7ar).\n3. Na \u00daltima linha da resposta incluir: ACAO_JSON:{\"movimentos\":[{\"produto_nome\":\"Nome Exato\",\"tipo\":\"Entrada\",\"qtd\":5.0}]}\nTipos v\u00e1lidos: Entrada, Sa\u00edda, Perda\nSe n\u00e3o encontrar o nome exato, use o mais parecido e informe.\nSem pedido de lan\u00e7amento \u2192 N\u00c3O inclua ACAO_JSON.\n\nRESUMO DO ESTOQUE:\n- Total: ${totalProd} | Zerados: ${zerados} | Críticos: ${criticos} | Atenção: ${atencao_count}\n- Valor total: R$ ${Number(valorTotal).toFixed(2)} | Lançamentos hoje: ${lancHoje || 0}\n\n=== ZERADOS (${prodZerados.length}) ===\n${prodZerados.map(p => `• ${p.nome} | ${p.categoria}`).join('\n') || 'Nenhum.'}\n\n=== CRÍTICOS (${prodCriticos.length}) ===\n${prodCriticos.map(p => `• ${p.nome} | qtd: ${p.qtd} | mínimo: ${p.minimo} ${p.unidade}`).join('\n') || 'Nenhum.'}\n\n=== ATENÇÃO (${prodAtencao.length}) ===\n${prodAtencao.map(p => `• ${p.nome} | qtd: ${p.qtd} | mínimo: ${p.minimo} ${p.unidade}`).join('\n') || 'Nenhum.'}\n\n=== MAIS CONSUMIDOS (30 dias) ===\n${maisConsumidos.map(([nome, d]) => `• ${nome}: ${d.total.toFixed(2)} ${d.unidade}`).join('\n') || 'Sem dados.'}\n\n=== MOVIMENTAÇÕES HOJE (${(ultimosMov||[]).length}) ===\n${(ultimosMov || []).map(m => `• [${m.created_at.slice(11,16)}] ${m.tipo} — ${m.produto_nome} ${m.qtd} ${m.unidade||''} (${m.responsavel||''})`).join('\n')}\n\n=== TODOS OS PRODUTOS POR CATEGORIA ===\n${cats.map(([cat, d]) => `[${cat}] (${d.n} itens):\n${d.prods.join('\n')}`).join('\n\n')}\n\n=== ⚠️ ALERTA GIRO PARADO (verificar urgente) ===\n${alertasParadosIA.length === 0 ? 'Todos os itens de alto giro estão com movimentão normal.' : alertasParadosIA.map(a => `• ${a.nome} (${a.cat}): ${a.dias} dias sem mov. | Estoque: ${a.qtd} ${a.unidade}`).join('\n')}`;
  try {
    const messages = [...historico.map(h => ({ role: h.role, content: h.content })), { role: 'user', content: pergunta }];
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 4096, system: contexto, messages })
    });
    if (!response.ok) return res.status(502).json({ erro: 'Erro na API: ' + (await response.text()).slice(0, 200) });
    const data = await response.json();
    const respostaRaw = (data.content||[]).map(b => b.text||'').join('').trim();

    // Detecta e executa lançamentos em lote
    const acaoMatch = respostaRaw.match(/ACAO_JSON:(\{[\s\S]*?\})\s*$/);
    let textoFinal = respostaRaw;
    let movimentosExecutados = [];

    if (acaoMatch) {
      textoFinal = respostaRaw.replace(/ACAO_JSON:[\s\S]*$/, '').trim();
      try {
        const acao = JSON.parse(acaoMatch[1]);
        for (const mov of (acao.movimentos || [])) {
          const nomeBusca = String(mov.produto_nome || '');
          const tipo = ['Entrada','Saída','Perda'].includes(mov.tipo) ? mov.tipo : 'Entrada';
          const qtdMov = Number(mov.qtd) || 0;
          if (!nomeBusca || qtdMov <= 0) continue;
          const { data: prod } = await supabase.from('produtos').select('*').ilike('nome', nomeBusca).single();
          if (!prod) { movimentosExecutados.push({ nome: nomeBusca, ok: false, erro: 'Produto não encontrado' }); continue; }
          let novaQtd = Number(prod.qtd);
          if (tipo === 'Entrada') novaQtd = Number((novaQtd + qtdMov).toFixed(3));
          else if (tipo === 'Saída' || tipo === 'Perda') {
            if (qtdMov > novaQtd) { movimentosExecutados.push({ nome: prod.nome, ok: false, erro: `Estoque insuficiente (${prod.qtd} ${prod.unidade})` }); continue; }
            novaQtd = Number((novaQtd - qtdMov).toFixed(3));
          }
          const { error: updErr } = await supabase.from('produtos').update({ qtd: novaQtd }).eq('id', prod.id);
          if (updErr) { movimentosExecutados.push({ nome: prod.nome, ok: false, erro: 'Erro ao atualizar' }); continue; }
          await supabase.from('movimentacoes').insert({
            produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
            tipo, qtd: qtdMov, unidade: prod.unidade,
            custo: Number(prod.custo || 0), valor: Number((Number(prod.custo || 0) * qtdMov).toFixed(2)),
            motivo: tipo === 'Entrada' ? 'Compra (IA chat)' : 'Lançamento IA chat',
            responsavel: req.user.nome, obs: `via chat IA: ${pergunta.slice(0, 80)}`,
            qtd_antes: Number(prod.qtd), qtd_depois: novaQtd,
            created_at: nowSP(),
          });
          movimentosExecutados.push({ nome: prod.nome, tipo, qtd: qtdMov, unidade: prod.unidade, ok: true });
        }
        if (movimentosExecutados.length > 0) {
          const okCount = movimentosExecutados.filter(m => m.ok).length;
          const linhas = movimentosExecutados.map(m => m.ok
            ? `✅ ${m.tipo} — ${m.nome}: ${m.qtd} ${m.unidade}`
            : `❌ ${m.nome}: ${m.erro}`
          );
          textoFinal += `\n\n**Lançamentos executados (${okCount}/${movimentosExecutados.length}):**\n${linhas.join('\n')}`;
        }
      } catch(eAcao) { console.error('Erro ao executar acao chat:', eAcao.message); }
    }

    await audit('chat_ia', { pergunta: pergunta.slice(0,100), lancamentos: movimentosExecutados.length }, req.user, getClientIp(req));
    res.json({ resposta: textoFinal, movimentos_executados: movimentosExecutados });
  } catch(e) { res.status(500).json({ erro: 'Erro interno: ' + e.message }); }
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

// ==================== GERENCIAR USUÁRIOS ====================
app.get('/api/users', auth, requireRole('admin'), async (req, res) => {
  const { data } = await supabase.from('users').select('id, username, nome, role, active, created_at').order('role').order('nome');
  res.json(data || []);
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
  if (Number(id) === req.user.id && active === 0) return res.status(400).json({ erro: 'Você não pode desativar sua própria conta.' });
  const updates = {};
  if (active !== null) updates.active = active;
  if (role && ['admin','gerente','operador'].includes(role)) updates.role = role;
  if (nova_senha) {
    if (nova_senha.length < 6) return res.status(400).json({ erro: 'Senha precisa ter pelo menos 6 caracteres.' });
    updates.password_hash = hashPassword(nova_senha);
  }
  if (Object.keys(updates).length > 0) await supabase.from('users').update(updates).eq('id', id);
  await audit('editar_usuario', { id, active, role }, req.user, getClientIp(req));
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
  const dataInicio = req.query?.data_inicio || new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10);
  const dataFim = req.query?.data_fim || nowSP().slice(0,10);
  const categoria = sanitizeText(req.query?.categoria || '', 80);
  let movQuery = supabase.from('movimentacoes').select('*').gte('created_at', dataInicio).lte('created_at', dataFim + 'T23:59:59');
  if (categoria) movQuery = movQuery.eq('categoria', categoria);
  const { data: allMovs } = await movQuery;
  const groups = {};
  for (const m of (allMovs || [])) {
    const key = m.produto_nome;
    if (!groups[key]) groups[key] = { produto_nome: m.produto_nome, categoria: m.categoria, unidade: m.unidade, total_entrada: 0, total_saida: 0, total_perda: 0, valor_entrada: 0, valor_saida: 0, num_saidas: 0, num_entradas: 0 };
    const g = groups[key];
    if (m.tipo === 'Entrada') { g.total_entrada += Number(m.qtd); g.valor_entrada += Number(m.valor || 0); g.num_entradas++; }
    if (['Saída','Perda'].includes(m.tipo)) { g.total_saida += Number(m.qtd); g.valor_saida += Number(m.valor || 0); g.num_saidas++; }
    if (m.tipo === 'Perda') g.total_perda += Number(m.qtd);
  }
  const { data: produtos } = await supabase.from('produtos').select('nome, qtd, minimo');
  const estoqueMap = {};
  for (const p of (produtos || [])) estoqueMap[p.nome] = { qtd: Number(p.qtd), minimo: Number(p.minimo) };
  const resultado = Object.values(groups).filter(g => g.total_entrada > 0 || g.total_saida > 0).map(r => {
    const qtdAtual = estoqueMap[r.produto_nome]?.qtd ?? null;
    const saldo = Number((r.total_entrada - r.total_saida).toFixed(3));
    return { ...r, total_entrada: Number(r.total_entrada.toFixed(3)), total_saida: Number(r.total_saida.toFixed(3)),
      total_perda: Number(r.total_perda.toFixed(3)), valor_entrada: Number(r.valor_entrada.toFixed(2)),
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
  let restaurados = 0;
  for (const p of produtos) {
    const { error } = await supabase.from('produtos').update({ qtd: p.qtd, custo: p.custo, minimo: p.minimo, ativo: p.ativo }).eq('id', p.id);
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
    const hojeSP = nowSP().slice(0, 10);
    const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true }).gte('created_at', hojeSP).lte('created_at', hojeSP + 'T23:59:59');
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
    const { data: prod } = await supabase.from('produtos').select('*').ilike('nome_search', `%${normalizeSearch(produto_nome)}%`).single();
    if (!prod) return res.json({ resposta: `Não encontrei "${produto_nome}" no estoque.` });
    let novaQtd = Number(prod.qtd);
    if (tipo === 'Entrada') novaQtd = Number((novaQtd + qtd).toFixed(3));
    else {
      if (qtd > novaQtd) return res.json({ resposta: `❌ Estoque insuficiente de ${prod.nome}. Disponível: ${prod.qtd} ${prod.unidade}` });
      novaQtd = Number((novaQtd - qtd).toFixed(3));
    }
    const { error: updateErr } = await supabase.from('produtos').update({ qtd: novaQtd }).eq('id', prod.id);
    if (updateErr) return res.json({ resposta: `❌ Erro ao atualizar estoque de ${prod.nome}.` });
    const { error: movErr } = await supabase.from('movimentacoes').insert({
      produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria, tipo, qtd, unidade: prod.unidade,
      custo: prod.custo, valor: Number((Number(prod.custo)*qtd).toFixed(2)),
      motivo: tipo === 'Entrada' ? 'Compra' : 'Produção', responsavel: remetente || 'WhatsApp', obs: 'via WhatsApp', created_at: nowSP(),
    });
    if (movErr) { await supabase.from('produtos').update({ qtd: prod.qtd }).eq('id', prod.id); return res.json({ resposta: `❌ Erro ao registrar movimentação de ${prod.nome}.` }); }
    await audit('movimentacao_whatsapp', { produto: prod.nome, tipo, qtd, nova_qtd: novaQtd, remetente }, null, '');
    return res.json({ resposta: `✅ *${tipo.toUpperCase()}* registrada!\n\n📦 ${prod.nome}\n📏 ${qtd} ${prod.unidade}\n📊 Estoque agora: ${novaQtd} ${prod.unidade}` });
  }

  if (acao === 'compras') {
    const { data } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, unidade').or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    const lista = (data || []).filter(p => Number(p.qtd) <= Number(p.minimo) * 0.5);
    if (!lista.length) return res.json({ resposta: '✅ Estoque OK! Nada para comprar urgente.' });
    return res.json({ resposta: `🛒 *LISTA DE COMPRAS (${lista.length} itens)*\n\n${lista.map(p=>`• ${p.nome}: tem ${p.qtd}, comprar ~${Math.max(0,Number(p.minimo)*2-Number(p.qtd)).toFixed(1)} ${p.unidade}`).join('\n')}` });
  }

  res.json({ resposta: `🐰 *Toca do Coelho — Estoque*\n\nComandos: consultar | resumo | zerados | criticos | compras | entrada | saida` });
});

app.get('/api/webhook/relatorio-diario', async (req, res) => {
  const secret = req.headers['x-webhook-secret'] || req.query?.secret;
  if (secret !== WEBHOOK_SECRET) return res.status(403).json({ erro: 'Acesso negado.' });
  const { data: all } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, custo, unidade');
  const prods = all || [];
  const zerados = prods.filter(p => Number(p.qtd) === 0);
  const criticos = prods.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5);
  const valor = prods.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0);
  const hojeSP = nowSP().slice(0, 10);
  const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true }).gte('created_at', hojeSP).lte('created_at', hojeSP + 'T23:59:59');
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

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ==================== START ====================
seed().then(async () => {
  await initSessionsBackend();
  app.listen(PORT, () => {
    console.log(`🐰 Toca do Coelho — Estoque (Supabase) rodando em http://localhost:${PORT}`);
    console.log(`⏰ Backup automático configurado para ${process.env.HORA_BACKUP || '18:00'}`);
  });
}).catch(err => { console.error('❌ Erro ao inicializar:', err.message); process.exit(1); });
