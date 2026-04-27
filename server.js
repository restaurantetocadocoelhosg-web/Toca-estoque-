process.env.TZ = 'America/Sao_Paulo';

const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== SUPABASE ====================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY; // service_role key (backend only!)
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ SUPABASE_URL e SUPABASE_SERVICE_KEY são obrigatórios!');
  process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const sessions = new Map();

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ==================== HELPERS ====================
function nowIso() {
  return new Date().toISOString();
}

function nowSP() {
  const partes = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
  }).formatToParts(new Date());
  const get = (type) => partes.find(p => p.type === type)?.value || '';
  return `${get('year')}-${get('month')}-${get('day')} ${get('hour')}:${get('minute')}:${get('second')}`;
}

function normalizeSearch(str) {
  return String(str || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim();
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
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

// ==================== SESSÕES ====================
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;

function createSession(user) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, {
    id: user.id, username: user.username, nome: user.nome,
    role: user.role, created_at: nowIso(), lastActivity: Date.now(),
  });
  return token;
}

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (now - session.lastActivity > IDLE_TIMEOUT_MS) sessions.delete(token);
  }
}, 60 * 1000);

function getToken(req) {
  const bearer = req.headers.authorization || '';
  if (bearer.startsWith('Bearer ')) return bearer.slice(7);
  return req.headers['x-auth-token'] || '';
}

function reqIpFallback(ip) { return ip || ''; }

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
  const session = sessions.get(token);
  if (!session) return res.status(401).json({ erro: 'Sessão expirada. Faça login novamente.' });
  if (Date.now() - session.lastActivity > IDLE_TIMEOUT_MS) {
    sessions.delete(token);
    return res.status(401).json({ erro: 'Sessão encerrada por inatividade. Faça login novamente.' });
  }
  const { data: user } = await supabase
    .from('users').select('id, username, nome, role, active').eq('id', session.id).single();
  if (!user || !user.active) {
    sessions.delete(token);
    return res.status(401).json({ erro: 'Usuário inativo ou inválido.' });
  }
  session.lastActivity = Date.now();
  req.user = user;
  req.token = token;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ erro: 'Você não tem permissão para esta ação.' });
    }
    next();
  };
}

// ==================== STATUS HELPERS ====================
function addStatusFilter(query, status) {
  if (status === 'zerado') return query.eq('qtd', 0);
  if (status === 'critico') return query.gt('qtd', 0).filter('qtd', 'lte', 'minimo*0.5');
  // Para filtros calculados usamos RPC ou filtramos no JS
  return query;
}

// ==================== SEED (primeira execução) ====================
async function seed() {
  // Seed users
  const { count } = await supabase.from('users').select('id', { count: 'exact', head: true });
  if (count === 0) {
    const seedUsers = [
      { username: 'admin', nome: 'Administrador', role: 'admin', password_hash: hashPassword(process.env.ADMIN_PASSWORD || 'Toca123!'), active: 1 },
      { username: 'nayara.admin', nome: 'Nayara', role: 'admin', password_hash: hashPassword('Nayara@2026Tc'), active: 1 },
      { username: 'simone.gerente', nome: 'Simone', role: 'gerente', password_hash: hashPassword('Simone@2026Tc'), active: 1 },
      { username: 'estoque.operacao', nome: 'Estoque', role: 'operador', password_hash: hashPassword('Estoque@2026Tc'), active: 1 },
    ];
    await supabase.from('users').insert(seedUsers);
    console.log('🔐 Usuários iniciais criados');
  }

  // Seed produtos
  const { count: prodCount } = await supabase.from('produtos').select('id', { count: 'exact', head: true });
  if (prodCount === 0) {
    const seedPath = path.join(__dirname, 'produtos_seed.json');
    if (fs.existsSync(seedPath)) {
      const produtos = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
      // Supabase insert em lotes de 500
      for (let i = 0; i < produtos.length; i += 500) {
        const batch = produtos.slice(i, i + 500).map(p => ({
          ...p,
          nome_search: normalizeSearch(p.nome),
          ativo: 1,
        }));
        await supabase.from('produtos').insert(batch);
      }
      console.log(`✅ ${produtos.length} produtos carregados no Supabase.`);
    }
  }

  // Popula nome_search nos que não têm
  const { data: semNorm } = await supabase
    .from('produtos').select('id, nome')
    .or('nome_search.is.null,nome_search.eq.');
  if (semNorm && semNorm.length > 0) {
    for (const p of semNorm) {
      await supabase.from('produtos').update({ nome_search: normalizeSearch(p.nome) }).eq('id', p.id);
    }
    console.log(`✅ nome_search populado para ${semNorm.length} produtos`);
  }
}

// ==================== AUTH ROUTES ====================
app.post('/api/login', async (req, res) => {
  const username = sanitizeText(req.body?.username, 40).toLowerCase();
  const password = String(req.body?.password || '');
  if (!username || !password) return res.status(400).json({ erro: 'Usuário e senha são obrigatórios.' });

  const { data: user } = await supabase
    .from('users').select('*').ilike('username', username).eq('active', 1).single();
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ erro: 'Usuário ou senha inválidos.' });
  }

  const token = createSession(user);
  await audit('login', { username: user.username }, user, req.ip);
  res.json({
    token,
    user: { id: user.id, username: user.username, nome: user.nome, role: user.role },
  });
});

app.post('/api/logout', auth, async (req, res) => {
  sessions.delete(req.token);
  await audit('logout', {}, req.user, req.ip);
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
  await audit('editar_perfil', { nome_anterior: req.user.nome, nome_novo: nome }, req.user, req.ip);
  res.json({ ok: true, nome });
});

app.post('/api/change-password', auth, async (req, res) => {
  const current = String(req.body?.current_password || '');
  const next = String(req.body?.new_password || '');
  const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!verifyPassword(current, user.password_hash)) return res.status(400).json({ erro: 'Senha atual incorreta.' });
  if (next.length < 6) return res.status(400).json({ erro: 'A nova senha precisa ter pelo menos 6 caracteres.' });
  await supabase.from('users').update({ password_hash: hashPassword(next) }).eq('id', req.user.id);
  await audit('change_password', {}, req.user, req.ip);
  res.json({ ok: true });
});

// ==================== ROTAS PRODUTOS ====================
app.get('/api/produtos', auth, async (req, res) => {
  const { cat, status, q, arquivados } = req.query;
  let query = supabase.from('produtos').select('*');

  if (arquivados === '1' && req.user.role === 'admin') {
    query = query.eq('ativo', 0);
  } else {
    query = query.or('ativo.eq.1,ativo.is.null');
  }
  if (q) query = query.ilike('nome', `%${sanitizeText(q, 100)}%`);
  if (cat) query = query.eq('categoria', sanitizeText(cat, 80));
  query = query.order('categoria').order('nome');

  const { data: rows, error } = await query;
  if (error) return res.status(500).json({ erro: 'Erro ao buscar produtos.' });

  // Filtrar status no JS (cálculos com minimo)
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
  const qNorm = normalizeSearch(q);
  const { data } = await supabase
    .from('produtos')
    .select('id, nome, categoria, unidade, qtd, minimo, custo')
    .ilike('nome_search', `%${qNorm}%`)
    .or('ativo.eq.1,ativo.is.null')
    .order('nome')
    .limit(15);
  res.json(data || []);
});

app.get('/api/categorias', auth, async (req, res) => {
  const { data } = await supabase.from('produtos').select('categoria').order('categoria');
  const unique = [...new Set((data || []).map(r => r.categoria))];
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
  await audit('criar_produto', { nome, categoria, unidade }, req.user, req.ip);
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
  await audit('produto_update', { id: produto.id, nome_anterior: produto.nome, nome, categoria, unidade, custo, minimo }, req.user, req.ip);
  res.json({ ok: true, produto: atualizado });
});

app.put('/api/produtos/:id/arquivar', auth, requireRole('admin'), async (req, res) => {
  const { data: prod } = await supabase.from('produtos').select('*').eq('id', req.params.id).single();
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });
  const novoAtivo = prod.ativo === 0 ? 1 : 0;
  await supabase.from('produtos').update({ ativo: novoAtivo }).eq('id', req.params.id);
  await audit('produto_arquivar', { produto_id: prod.id, nome: prod.nome, ativo: novoAtivo }, req.user, req.ip);
  res.json({ ok: true, ativo: novoAtivo });
});

app.get('/api/produtos/:id/historico', auth, async (req, res) => {
  const { data: prod } = await supabase.from('produtos').select('nome, qtd, unidade, ativo').eq('id', req.params.id).single();
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });
  const { data: movs } = await supabase
    .from('movimentacoes')
    .select('tipo, qtd, unidade, motivo, responsavel, obs, created_at')
    .eq('produto_id', req.params.id)
    .order('id', { ascending: false })
    .limit(20);
  res.json({ produto: prod, movimentacoes: movs || [] });
});

// ==================== ROTAS MOVIMENTAÇÕES ====================
app.post('/api/movimentacoes', auth, async (req, res) => {
  const produto_nome = sanitizeText(req.body?.produto_nome, 120);
  const tipo = sanitizeText(req.body?.tipo, 20);
  const motivo = sanitizeText(req.body?.motivo, 80);
  const obs = sanitizeText(req.body?.obs, 200);
  const qtdInput = req.body?.qtd;

  if (!produto_nome || !['Entrada', 'Saída', 'Perda', 'Ajuste'].includes(tipo)) {
    return res.status(400).json({ erro: 'Produto e tipo válidos são obrigatórios.' });
  }

  const { data: prod } = await supabase.from('produtos').select('*').ilike('nome', produto_nome).single();
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });

  let qtd;
  if (tipo === 'Ajuste') qtd = parseNonNegativeNumber(qtdInput);
  else qtd = parsePositiveNumber(qtdInput);
  if (qtd === null) {
    return res.status(400).json({ erro: tipo === 'Ajuste' ? 'Ajuste deve ser zero ou maior.' : 'Quantidade deve ser maior que zero.' });
  }

  const custoBody = req.body?.custo === '' || req.body?.custo === null || req.body?.custo === undefined
    ? null : parseNonNegativeNumber(req.body?.custo);
  if (req.body?.custo !== '' && req.body?.custo !== null && req.body?.custo !== undefined && custoBody === null) {
    return res.status(400).json({ erro: 'Custo informado é inválido.' });
  }

  let novaQtd = Number(prod.qtd);
  if (tipo === 'Entrada') {
    novaQtd = Number((novaQtd + qtd).toFixed(3));
  } else if (tipo === 'Saída' || tipo === 'Perda') {
    if (qtd > novaQtd) return res.status(400).json({ erro: `Estoque insuficiente. Disponível: ${prod.qtd} ${prod.unidade}.` });
    novaQtd = Number((novaQtd - qtd).toFixed(3));
  } else if (tipo === 'Ajuste') {
    novaQtd = Number(qtd.toFixed(3));
  }

  const custoUnit = custoBody !== null ? custoBody : Number(prod.custo || 0);
  const valorBase = tipo === 'Ajuste' ? Math.abs(novaQtd - Number(prod.qtd)) : qtd;
  const valor = Number((custoUnit * valorBase).toFixed(2));

  // Atualiza produto
  const updateData = { qtd: novaQtd };
  if (tipo === 'Entrada' && custoBody !== null) updateData.custo = custoUnit;
  await supabase.from('produtos').update(updateData).eq('id', prod.id);

  // Insere movimentação
  await supabase.from('movimentacoes').insert({
    produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
    tipo, qtd: tipo === 'Ajuste' ? novaQtd : qtd, unidade: prod.unidade,
    custo: custoUnit, valor, motivo, responsavel: req.user.nome, obs,
    created_at: nowSP(),
  });

  await audit('movimentacao', { produto_id: prod.id, produto_nome: prod.nome, tipo, qtd, nova_qtd: novaQtd, motivo }, req.user, req.ip);

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
  await audit('cancelar_movimentacao', { mov_id: mov.id, produto: mov.produto_nome, tipo: mov.tipo, qtd: mov.qtd }, req.user, req.ip);
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

// ==================== DASHBOARD ====================
app.get('/api/dashboard', auth, async (req, res) => {
  const { data: produtos } = await supabase.from('produtos').select('qtd, minimo, custo');
  const all = produtos || [];
  const zerados = all.filter(p => Number(p.qtd) === 0).length;
  const criticos = all.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5).length;
  const atencao = all.filter(p => Number(p.qtd) > Number(p.minimo) * 0.5 && Number(p.qtd) < Number(p.minimo)).length;
  const valorTotal = all.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0);

  const hojeSP = nowSP().slice(0, 10);
  const { count: lancHoje } = await supabase
    .from('movimentacoes').select('id', { count: 'exact', head: true })
    .gte('created_at', hojeSP).lte('created_at', hojeSP + 'T23:59:59');

  const { data: ultimos } = await supabase
    .from('movimentacoes').select('*').order('id', { ascending: false }).limit(8);

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
  } else {
    return res.status(400).json({ erro: 'Tipo inválido' });
  }

  await audit('exportar', { tipo }, req.user, req.ip);
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send('\uFEFF' + csv);
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

  for (const p of produtos) {
    await supabase.from('produtos').update({ qtd: p.qtd, custo: p.custo, minimo: p.minimo }).eq('nome', p.nome);
  }
  await audit('resetar_estoque', { total_produtos: produtos.length }, req.user, req.ip);
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
        model: 'claude-haiku-4-5-20251001', max_tokens: 1024,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: imagem } },
            { type: 'text', text: `Você está lendo um cupom fiscal ou nota fiscal de um restaurante brasileiro.
Extraia TODOS os itens comprados com nome do produto e quantidade.
Responda SOMENTE com JSON válido, sem texto extra, sem markdown, no formato:
{"itens":[{"nome":"Nome do produto","qtd":1.0,"unidade":"KG"}]}
Use unidade KG para peso, UN para unidade, L para litro, CX para caixa.
Se não conseguir ler: {"itens":[],"erro":"descrição do problema"}` }
          ]
        }]
      })
    });

    if (!response.ok) {
      const err = await response.text();
      return res.status(502).json({ erro: 'Erro na API: ' + err.slice(0, 300) });
    }

    const data = await response.json();
    const text = (data.content || []).map(b => b.text || '').join('');
    const clean = text.replace(/```json|```/g, '').trim();
    let parsed;
    try { parsed = JSON.parse(clean); } catch(e) {
      return res.status(422).json({ erro: 'Foto ilegível. Tente uma imagem mais nítida e bem iluminada.' });
    }
    if (parsed.erro) return res.json({ itens: [], aviso: parsed.erro });

    const itens = [];
    for (const item of (parsed.itens || [])) {
      const qNorm = normalizeSearch(item.nome);

      // Tenta sinônimo
      const { data: sinonimo } = await supabase.from('sinonimos').select('produto_nome').eq('termo', qNorm).single();
      let candidatos = [];
      let produtoExato = null;

      if (sinonimo) {
        const { data: p } = await supabase.from('produtos')
          .select('id, nome, categoria, unidade, qtd, minimo, custo')
          .ilike('nome', sinonimo.produto_nome).single();
        if (p) { produtoExato = p; candidatos = [p]; }
      }

      if (!produtoExato) {
        const palavras = qNorm.split(/\s+/).filter(p => p.length > 2);
        if (palavras.length > 1) {
          const scoreMap = new Map();
          for (const palavra of palavras) {
            const { data: matches } = await supabase.from('produtos')
              .select('id, nome, categoria, unidade, qtd, minimo, custo')
              .ilike('nome_search', `%${palavra}%`).order('nome').limit(10);
            for (const m of (matches || [])) {
              const entry = scoreMap.get(m.id) || { produto: m, score: 0 };
              entry.score++;
              scoreMap.set(m.id, entry);
            }
          }
          if (scoreMap.size > 0) {
            candidatos = Array.from(scoreMap.values())
              .sort((a, b) => b.score - a.score).slice(0, 3).map(r => r.produto);
          }
        }
        if (!candidatos.length) {
          const { data: fallback } = await supabase.from('produtos')
            .select('id, nome, categoria, unidade, qtd, minimo, custo')
            .ilike('nome_search', `%${qNorm}%`).order('nome').limit(3);
          candidatos = fallback || [];
        }
      }

      itens.push({
        nome_cupom: item.nome, qtd: Number(item.qtd) || 1,
        unidade_cupom: item.unidade || 'UN', candidatos,
        produto: candidatos[0] || null, via_sinonimo: !!produtoExato,
      });
    }

    await audit('ler_cupom', { total_itens: itens.length }, req.user, req.ip);
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
  const { count: lancHoje } = await supabase
    .from('movimentacoes').select('id', { count: 'exact', head: true })
    .gte('created_at', hojeSP).lte('created_at', hojeSP + 'T23:59:59');

  const { data: ultimosMov } = await supabase
    .from('movimentacoes').select('produto_nome, tipo, qtd, unidade, motivo, responsavel, created_at')
    .order('id', { ascending: false }).limit(15);

  const thirtyDaysAgo = new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10);
  const { data: movConsumo } = await supabase
    .from('movimentacoes').select('produto_nome, qtd, unidade')
    .in('tipo', ['Saída', 'Perda']).gte('created_at', thirtyDaysAgo);

  const consumoMap = {};
  for (const m of (movConsumo || [])) {
    const key = m.produto_nome;
    if (!consumoMap[key]) consumoMap[key] = { total: 0, unidade: m.unidade };
    consumoMap[key].total += Number(m.qtd);
  }
  const maisConsumidos = Object.entries(consumoMap)
    .sort((a, b) => b[1].total - a[1].total).slice(0, 10);

  const catMap = {};
  for (const p of all) {
    if (!catMap[p.categoria]) catMap[p.categoria] = { n: 0, valor: 0 };
    catMap[p.categoria].n++;
    catMap[p.categoria].valor += Number(p.qtd) * Number(p.custo);
  }
  const cats = Object.entries(catMap).sort((a, b) => b[1].valor - a[1].valor);

  const contexto = `Você é o assistente de estoque do restaurante "Toca do Coelho" em São Gonçalo, Rio de Janeiro.
Responda SEMPRE em português brasileiro. Seja direto e preciso.
Hoje é ${hojeSP}.

REGRAS CRÍTICAS — NUNCA VIOLE:
1. Use SOMENTE os dados abaixo. Nunca invente ou suponha quantidades.
2. "Itens em falta" = APENAS os listados em ZERADOS e CRÍTICOS. Nunca liste itens com status OK como "em falta".
3. Ao listar produtos, mostre nome, quantidade atual e mínimo quando disponível.
4. Se perguntarem sobre um produto específico não listado, diga que o estoque está OK (não consta nas listas de alerta).

RESUMO DO ESTOQUE:
- Total de produtos cadastrados: ${totalProd}
- Zerados (qtd = 0): ${zerados} produtos
- Críticos (qtd ≤ 50% do mínimo): ${criticos} produtos
- Atenção (qtd entre 50% e 100% do mínimo): ${atencao_count} produtos
- Valor total em estoque: R$ ${Number(valorTotal).toFixed(2)}
- Lançamentos hoje: ${lancHoje || 0}

=== PRODUTOS ZERADOS — qtd = 0 (${prodZerados.length} total) ===
${prodZerados.map(p => `• ${p.nome} | ${p.categoria}`).join('\n') || 'Nenhum produto zerado.'}

=== PRODUTOS CRÍTICOS — qtd ≤ 50% do mínimo (${prodCriticos.length} total) ===
${prodCriticos.map(p => `• ${p.nome} | qtd: ${p.qtd} | mínimo: ${p.minimo} ${p.unidade} | ${p.categoria}`).join('\n') || 'Nenhum produto crítico.'}

=== PRODUTOS EM ATENÇÃO — qtd entre 50% e 100% do mínimo (${prodAtencao.length} total) ===
${prodAtencao.map(p => `• ${p.nome} | qtd: ${p.qtd} | mínimo: ${p.minimo} ${p.unidade}`).join('\n') || 'Nenhum.'}

=== MAIS CONSUMIDOS (últimos 30 dias) ===
${maisConsumidos.map(([nome, d]) => `• ${nome}: ${d.total.toFixed(2)} ${d.unidade}`).join('\n') || 'Sem dados suficientes.'}

=== ÚLTIMAS MOVIMENTAÇÕES ===
${(ultimosMov || []).map(m => `• [${m.created_at}] ${m.tipo} — ${m.produto_nome} ${m.qtd} ${m.unidade||''} (${m.responsavel||''})`).join('\n')}

=== ESTOQUE POR CATEGORIA ===
${cats.map(([cat, d]) => `• ${cat}: ${d.n} produtos, R$ ${d.valor.toFixed(2)}`).join('\n')}`;

  try {
    const messages = [
      ...historico.map(h => ({ role: h.role, content: h.content })),
      { role: 'user', content: pergunta }
    ];
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1024, system: contexto, messages })
    });
    if (!response.ok) {
      const errText = await response.text();
      return res.status(502).json({ erro: 'Erro na API: ' + errText.slice(0, 200) });
    }
    const data = await response.json();
    const resposta = (data.content||[]).map(b => b.text||'').join('').trim();
    await audit('chat_ia', { pergunta: pergunta.slice(0,100) }, req.user, req.ip);
    res.json({ resposta });
  } catch(e) {
    res.status(500).json({ erro: 'Erro interno: ' + e.message });
  }
});

// ==================== GERENCIAR USUÁRIOS (admin) ====================
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

  const { error } = await supabase.from('users').insert({
    username, nome, role, password_hash: hashPassword(password), active: 1,
  });
  if (error) {
    if (error.code === '23505') return res.status(400).json({ erro: 'Usuário já existe.' });
    return res.status(500).json({ erro: 'Erro ao criar usuário.' });
  }
  await audit('criar_usuario', { novo: username, role }, req.user, req.ip);
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

  if (Object.keys(updates).length > 0) {
    await supabase.from('users').update(updates).eq('id', id);
  }
  await audit('editar_usuario', { id, active, role }, req.user, req.ip);
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

  const { error } = await supabase.from('sinonimos').upsert(
    { termo: normalizeSearch(termo), produto_nome: prod.nome },
    { onConflict: 'termo' }
  );
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

// Manutenção - normalizar
app.get('/api/manutencao/normalizar', auth, requireRole('admin'), async (req, res) => {
  const { data: todos } = await supabase.from('produtos').select('id, nome');
  for (const p of (todos || [])) {
    await supabase.from('produtos').update({ nome_search: normalizeSearch(p.nome) }).eq('id', p.id);
  }
  console.log(`✅ nome_search atualizado para ${(todos||[]).length} produtos`);
  res.json({ ok: true, total: (todos||[]).length, msg: `${(todos||[]).length} produtos normalizados!` });
});

// ==================== AUDITORIA DE DIVERGÊNCIAS ====================
app.get('/api/auditoria/divergencias', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const dataInicio = req.query?.data_inicio || new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10);
  const dataFim = req.query?.data_fim || nowSP().slice(0,10);
  const categoria = sanitizeText(req.query?.categoria || '', 80);

  let movQuery = supabase.from('movimentacoes').select('*')
    .gte('created_at', dataInicio).lte('created_at', dataFim + 'T23:59:59');
  if (categoria) movQuery = movQuery.eq('categoria', categoria);
  const { data: allMovs } = await movQuery;

  // Agrupa no JS (equivalente ao GROUP BY da versão SQLite)
  const groups = {};
  for (const m of (allMovs || [])) {
    const key = m.produto_nome;
    if (!groups[key]) groups[key] = { produto_nome: m.produto_nome, categoria: m.categoria, unidade: m.unidade,
      total_entrada: 0, total_saida: 0, total_perda: 0, valor_entrada: 0, valor_saida: 0, num_saidas: 0, num_entradas: 0 };
    const g = groups[key];
    if (m.tipo === 'Entrada') { g.total_entrada += Number(m.qtd); g.valor_entrada += Number(m.valor || 0); g.num_entradas++; }
    if (['Saída','Perda'].includes(m.tipo)) { g.total_saida += Number(m.qtd); g.valor_saida += Number(m.valor || 0); g.num_saidas++; }
    if (m.tipo === 'Perda') g.total_perda += Number(m.qtd);
  }

  const { data: produtos } = await supabase.from('produtos').select('nome, qtd, minimo');
  const estoqueMap = {};
  for (const p of (produtos || [])) estoqueMap[p.nome] = { qtd: Number(p.qtd), minimo: Number(p.minimo) };

  const resultado = Object.values(groups)
    .filter(g => g.total_entrada > 0 || g.total_saida > 0)
    .map(r => {
      const qtdAtual = estoqueMap[r.produto_nome]?.qtd ?? null;
      const saldo = Number((r.total_entrada - r.total_saida).toFixed(3));
      const alerta = r.total_saida > 0 && r.total_entrada > 0 && r.total_saida > r.total_entrada * 1.5;
      const semEntrada = r.total_saida > 0 && r.total_entrada === 0;
      return { ...r,
        total_entrada: Number(r.total_entrada.toFixed(3)), total_saida: Number(r.total_saida.toFixed(3)),
        total_perda: Number(r.total_perda.toFixed(3)),
        valor_entrada: Number(r.valor_entrada.toFixed(2)), valor_saida: Number(r.valor_saida.toFixed(2)),
        saldo, qtd_atual: qtdAtual, alerta, sem_entrada: semEntrada,
      };
    })
    .sort((a, b) => (a.categoria + a.produto_nome).localeCompare(b.categoria + b.produto_nome));

  const detalhesSaidas = (allMovs || [])
    .filter(m => ['Saída','Perda'].includes(m.tipo))
    .map(m => ({ produto_nome: m.produto_nome, tipo: m.tipo, qtd: m.qtd, unidade: m.unidade, motivo: m.motivo, responsavel: m.responsavel, obs: m.obs, created_at: m.created_at }))
    .sort((a, b) => (a.produto_nome + b.created_at).localeCompare(b.produto_nome + a.created_at));

  await audit('auditoria_divergencias', { dataInicio, dataFim, categoria }, req.user, req.ip);
  res.json({ resultado, detalhesSaidas, dataInicio, dataFim });
});

// ==================== BACKUP AUTOMÁTICO DIÁRIO ====================
// Snapshot do estoque salvo no Supabase todo dia às 18h (configurável)

async function criarBackupEstoque(motivo = 'automatico') {
  const { data: produtos } = await supabase.from('produtos').select('id, nome, categoria, unidade, qtd, minimo, custo, ativo');
  if (!produtos || !produtos.length) return null;

  const snapshot = {
    data_backup: nowSP(),
    motivo,
    total_produtos: produtos.length,
    valor_total: produtos.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0),
    zerados: produtos.filter(p => Number(p.qtd) === 0).length,
    criticos: produtos.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5).length,
    dados: JSON.stringify(produtos),
  };

  const { data, error } = await supabase.from('backups_estoque').insert(snapshot).select('id, data_backup').single();
  if (error) { console.error('❌ Erro no backup:', error.message); return null; }
  console.log(`✅ Backup #${data.id} criado em ${data.data_backup} (${motivo})`);
  return data;
}

// Cron simples: verifica a cada minuto se é 18:00
let ultimoBackupDia = '';
setInterval(async () => {
  const agora = nowSP();
  const hora = agora.slice(11, 16); // HH:MM
  const dia = agora.slice(0, 10);
  const HORA_BACKUP = process.env.HORA_BACKUP || '18:00';
  if (hora === HORA_BACKUP && dia !== ultimoBackupDia) {
    ultimoBackupDia = dia;
    await criarBackupEstoque('automatico_18h');
  }
}, 60 * 1000);

// API: criar backup manual
app.post('/api/backup', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const motivo = sanitizeText(req.body?.motivo || 'manual', 100);
  const backup = await criarBackupEstoque(motivo);
  if (!backup) return res.status(500).json({ erro: 'Erro ao criar backup.' });
  await audit('backup_manual', { backup_id: backup.id, motivo }, req.user, req.ip);
  res.json({ ok: true, backup });
});

// API: listar backups
app.get('/api/backups', auth, requireRole('admin', 'gerente'), async (req, res) => {
  const { data } = await supabase
    .from('backups_estoque')
    .select('id, data_backup, motivo, total_produtos, valor_total, zerados, criticos')
    .order('id', { ascending: false })
    .limit(30);
  res.json(data || []);
});

// API: restaurar backup
app.post('/api/backup/:id/restaurar', auth, requireRole('admin'), async (req, res) => {
  const senhaAdmin = String(req.body?.senha_admin || '');
  const { data: userDb } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!verifyPassword(senhaAdmin, userDb.password_hash)) return res.status(401).json({ erro: 'Senha incorreta.' });

  const { data: backup } = await supabase.from('backups_estoque').select('*').eq('id', req.params.id).single();
  if (!backup) return res.status(404).json({ erro: 'Backup não encontrado.' });

  // Salvar snapshot antes de restaurar (segurança)
  await criarBackupEstoque('pre_restauracao');

  const produtos = JSON.parse(backup.dados);
  let restaurados = 0;
  for (const p of produtos) {
    const { error } = await supabase.from('produtos')
      .update({ qtd: p.qtd, custo: p.custo, minimo: p.minimo, ativo: p.ativo })
      .eq('id', p.id);
    if (!error) restaurados++;
  }

  await audit('restaurar_backup', { backup_id: backup.id, data_backup: backup.data_backup, restaurados }, req.user, req.ip);
  res.json({ ok: true, restaurados, data_backup: backup.data_backup });
});

// ==================== WEBHOOK WHATSAPP (n8n / Evolution API) ====================
// Endpoint que o n8n chama para consultar/operar estoque via WhatsApp
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'toca-webhook-2026';

app.post('/api/webhook/whatsapp', async (req, res) => {
  // Validação por secret (configurar no n8n)
  const secret = req.headers['x-webhook-secret'] || req.body?.secret;
  if (secret !== WEBHOOK_SECRET) return res.status(403).json({ erro: 'Acesso negado.' });

  const acao = sanitizeText(req.body?.acao, 40);
  const produto_nome = sanitizeText(req.body?.produto, 120);
  const remetente = sanitizeText(req.body?.remetente, 40);

  // AÇÃO: consultar — "quanto tem de frango?"
  if (acao === 'consultar') {
    if (!produto_nome) return res.json({ resposta: 'Me diz o nome do produto que quer consultar.' });
    const qNorm = normalizeSearch(produto_nome);
    const { data: resultados } = await supabase
      .from('produtos').select('nome, categoria, qtd, unidade, minimo, custo')
      .ilike('nome_search', `%${qNorm}%`)
      .or('ativo.eq.1,ativo.is.null')
      .order('nome').limit(5);

    if (!resultados || resultados.length === 0) return res.json({ resposta: `Não encontrei "${produto_nome}" no estoque.` });

    const linhas = resultados.map(p => {
      const status = Number(p.qtd) === 0 ? '🔴 ZERADO' : Number(p.qtd) <= Number(p.minimo) * 0.5 ? '🟠 CRÍTICO' : Number(p.qtd) < Number(p.minimo) ? '🟡 ATENÇÃO' : '🟢 OK';
      return `📦 *${p.nome}*\n   ${p.qtd} ${p.unidade} (mín: ${p.minimo}) ${status}\n   Custo: R$${Number(p.custo).toFixed(2)}`;
    });
    return res.json({ resposta: linhas.join('\n\n') });
  }

  // AÇÃO: resumo — relatório rápido do estoque
  if (acao === 'resumo') {
    const { data: all } = await supabase.from('produtos').select('qtd, minimo, custo');
    const prods = all || [];
    const zerados = prods.filter(p => Number(p.qtd) === 0).length;
    const criticos = prods.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5).length;
    const atencao = prods.filter(p => Number(p.qtd) > Number(p.minimo) * 0.5 && Number(p.qtd) < Number(p.minimo)).length;
    const valor = prods.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0);

    const hojeSP = nowSP().slice(0, 10);
    const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true })
      .gte('created_at', hojeSP).lte('created_at', hojeSP + 'T23:59:59');

    return res.json({
      resposta: `📊 *RESUMO DO ESTOQUE*\n📅 ${hojeSP}\n\n` +
        `📦 Total: ${prods.length} produtos\n` +
        `🔴 Zerados: ${zerados}\n🟠 Críticos: ${criticos}\n🟡 Atenção: ${atencao}\n` +
        `💰 Valor total: R$ ${valor.toFixed(2)}\n📋 Lançamentos hoje: ${lancHoje || 0}`
    });
  }

  // AÇÃO: zerados — lista produtos zerados
  if (acao === 'zerados') {
    const { data } = await supabase.from('produtos').select('nome, categoria').eq('qtd', 0).or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    if (!data || data.length === 0) return res.json({ resposta: '✅ Nenhum produto zerado!' });
    const txt = (data || []).map(p => `• ${p.nome} (${p.categoria})`).join('\n');
    return res.json({ resposta: `🔴 *PRODUTOS ZERADOS (${data.length})*\n\n${txt}` });
  }

  // AÇÃO: criticos — lista produtos críticos
  if (acao === 'criticos') {
    const { data } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, unidade')
      .gt('qtd', 0).or('ativo.eq.1,ativo.is.null').order('nome');
    const crit = (data || []).filter(p => Number(p.qtd) <= Number(p.minimo) * 0.5);
    if (crit.length === 0) return res.json({ resposta: '✅ Nenhum produto em nível crítico!' });
    const txt = crit.map(p => `• ${p.nome}: ${p.qtd}/${p.minimo} ${p.unidade}`).join('\n');
    return res.json({ resposta: `🟠 *PRODUTOS CRÍTICOS (${crit.length})*\n\n${txt}` });
  }

  // AÇÃO: entrada — lançar entrada via WhatsApp
  if (acao === 'entrada' || acao === 'saida') {
    const tipo = acao === 'entrada' ? 'Entrada' : 'Saída';
    const qtd = parsePositiveNumber(req.body?.qtd);
    if (!produto_nome || !qtd) return res.json({ resposta: `Para lançar ${tipo.toLowerCase()}, envie:\nproduto, quantidade\nEx: "Filé de Frango, 5"` });

    const { data: prod } = await supabase.from('produtos').select('*').ilike('nome_search', `%${normalizeSearch(produto_nome)}%`).single();
    if (!prod) return res.json({ resposta: `Não encontrei "${produto_nome}" no estoque.` });

    let novaQtd = Number(prod.qtd);
    if (tipo === 'Entrada') { novaQtd = Number((novaQtd + qtd).toFixed(3)); }
    else {
      if (qtd > novaQtd) return res.json({ resposta: `❌ Estoque insuficiente de ${prod.nome}. Disponível: ${prod.qtd} ${prod.unidade}` });
      novaQtd = Number((novaQtd - qtd).toFixed(3));
    }

    await supabase.from('produtos').update({ qtd: novaQtd }).eq('id', prod.id);
    await supabase.from('movimentacoes').insert({
      produto_id: prod.id, produto_nome: prod.nome, categoria: prod.categoria,
      tipo, qtd, unidade: prod.unidade, custo: prod.custo,
      valor: Number((Number(prod.custo) * qtd).toFixed(2)),
      motivo: tipo === 'Entrada' ? 'Compra' : 'Produção',
      responsavel: remetente || 'WhatsApp', obs: 'via WhatsApp',
      created_at: nowSP(),
    });

    await audit('movimentacao_whatsapp', { produto: prod.nome, tipo, qtd, nova_qtd: novaQtd, remetente }, null, '');
    return res.json({
      resposta: `✅ *${tipo.toUpperCase()}* registrada!\n\n📦 ${prod.nome}\n📏 ${qtd} ${prod.unidade}\n📊 Estoque agora: ${novaQtd} ${prod.unidade}`
    });
  }

  // AÇÃO: compras — lista de compras sugerida
  if (acao === 'compras') {
    const { data } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, unidade')
      .or('ativo.eq.1,ativo.is.null').order('categoria').order('nome');
    const lista = (data || []).filter(p => Number(p.qtd) <= Number(p.minimo) * 0.5);
    if (lista.length === 0) return res.json({ resposta: '✅ Estoque OK! Nada para comprar urgente.' });
    const txt = lista.map(p => {
      const comprar = Math.max(0, Number(p.minimo) * 2 - Number(p.qtd)).toFixed(1);
      return `• ${p.nome}: tem ${p.qtd}, comprar ~${comprar} ${p.unidade}`;
    }).join('\n');
    return res.json({ resposta: `🛒 *LISTA DE COMPRAS (${lista.length} itens)*\n\n${txt}` });
  }

  // Ação não reconhecida — ajuda
  res.json({
    resposta: `🐰 *Toca do Coelho — Estoque*\n\nComandos disponíveis:\n` +
      `📦 *consultar* [produto] — ver estoque\n` +
      `📊 *resumo* — painel geral\n` +
      `🔴 *zerados* — produtos em falta\n` +
      `🟠 *criticos* — itens críticos\n` +
      `🛒 *compras* — lista de compras\n` +
      `➕ *entrada* [produto] [qtd] — registrar entrada\n` +
      `➖ *saida* [produto] [qtd] — registrar saída`
  });
});

// Endpoint para relatório diário (chamado pelo n8n via cron)
app.get('/api/webhook/relatorio-diario', async (req, res) => {
  const secret = req.headers['x-webhook-secret'] || req.query?.secret;
  if (secret !== WEBHOOK_SECRET) return res.status(403).json({ erro: 'Acesso negado.' });

  const { data: all } = await supabase.from('produtos').select('nome, categoria, qtd, minimo, custo, unidade');
  const prods = all || [];
  const zerados = prods.filter(p => Number(p.qtd) === 0);
  const criticos = prods.filter(p => Number(p.qtd) > 0 && Number(p.qtd) <= Number(p.minimo) * 0.5);
  const valor = prods.reduce((s, p) => s + Number(p.qtd) * Number(p.custo), 0);

  const hojeSP = nowSP().slice(0, 10);
  const { count: lancHoje } = await supabase.from('movimentacoes').select('id', { count: 'exact', head: true })
    .gte('created_at', hojeSP).lte('created_at', hojeSP + 'T23:59:59');

  let msg = `📊 *RELATÓRIO DIÁRIO — ${hojeSP}*\n🐰 Toca do Coelho\n\n`;
  msg += `📦 ${prods.length} produtos | 💰 R$ ${valor.toFixed(2)}\n`;
  msg += `📋 ${lancHoje || 0} lançamentos hoje\n\n`;

  if (zerados.length > 0) {
    msg += `🔴 *ZERADOS (${zerados.length})*\n`;
    msg += zerados.slice(0, 15).map(p => `• ${p.nome}`).join('\n');
    if (zerados.length > 15) msg += `\n... e mais ${zerados.length - 15}`;
    msg += '\n\n';
  }

  if (criticos.length > 0) {
    msg += `🟠 *CRÍTICOS (${criticos.length})*\n`;
    msg += criticos.slice(0, 10).map(p => `• ${p.nome}: ${p.qtd}/${p.minimo} ${p.unidade}`).join('\n');
    msg += '\n\n';
  }

  msg += `_Backup automático às 18h ✅_`;

  res.json({ mensagem: msg, zerados: zerados.length, criticos: criticos.length, valor_total: valor });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== START ====================
seed().then(() => {
  app.listen(PORT, () => {
    console.log(`🐰 Toca do Coelho — Estoque (Supabase) rodando em http://localhost:${PORT}`);
    console.log(`⏰ Backup automático configurado para ${process.env.HORA_BACKUP || '18:00'}`);
  });
}).catch(err => {
  console.error('❌ Erro ao inicializar:', err.message);
  process.exit(1);
});
