process.env.TZ = 'America/Sao_Paulo';

const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './estoque.db';
const db = new Database(DB_PATH);
const sessions = new Map();

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function nowIso() {
  return new Date().toISOString();
}
function nowSP() {
  const partes = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).formatToParts(new Date());

  const get = (type) => partes.find(p => p.type === type)?.value || '';

  return `${get('year')}-${get('month')}-${get('day')} ${get('hour')}:${get('minute')}:${get('second')}`;
}
function sha(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

function normalizeSearch(str) {
  return String(str || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim();
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

function createSession(user) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, {
    id: user.id,
    username: user.username,
    nome: user.nome,
    role: user.role,
    created_at: nowIso(),
  });
  return token;
}

function getToken(req) {
  const bearer = req.headers.authorization || '';
  if (bearer.startsWith('Bearer ')) return bearer.slice(7);
  return req.headers['x-auth-token'] || '';
}

function audit(action, details = {}, user = null) {
  db.prepare(`
    INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now','localtime'))
  `).run(
    user?.id || null,
    user?.nome || user?.username || '',
    user?.role || '',
    action,
    JSON.stringify(details),
    sanitizeText(reqIpFallback(details.ip), 80)
  );
}

function reqIpFallback(ip) {
  return ip || '';
}

function auth(req, res, next) {
  const token = getToken(req);
  const session = sessions.get(token);
  if (!session) return res.status(401).json({ erro: 'Sessão expirada. Faça login novamente.' });
  const user = db.prepare('SELECT id, username, nome, role, active FROM users WHERE id = ?').get(session.id);
  if (!user || !user.active) {
    sessions.delete(token);
    return res.status(401).json({ erro: 'Usuário inativo ou inválido.' });
  }
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

function calcStatusClause(status) {
  if (status === 'zerado') return ' AND qtd = 0';
  if (status === 'critico') return ' AND qtd > 0 AND qtd <= minimo * 0.5';
  if (status === 'atencao') return ' AND qtd > minimo * 0.5 AND qtd < minimo';
  if (status === 'ok') return ' AND qtd >= minimo';
  return '';
}

// ==================== SETUP BANCO ====================
db.exec(`
  CREATE TABLE IF NOT EXISTS produtos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL UNIQUE,
    categoria TEXT NOT NULL,
    unidade TEXT NOT NULL,
    qtd REAL DEFAULT 0,
    minimo REAL DEFAULT 1,
    custo REAL DEFAULT 0,
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS movimentacoes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    produto_id INTEGER,
    produto_nome TEXT NOT NULL,
    categoria TEXT,
    tipo TEXT NOT NULL,
    qtd REAL NOT NULL,
    unidade TEXT,
    custo REAL DEFAULT 0,
    valor REAL DEFAULT 0,
    motivo TEXT,
    responsavel TEXT,
    obs TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY(produto_id) REFERENCES produtos(id)
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    nome TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','gerente','operador')),
    password_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    usuario_nome TEXT,
    role TEXT,
    acao TEXT NOT NULL,
    detalhes TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS sinonimos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    termo TEXT NOT NULL UNIQUE,
    produto_nome TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
`);

// Migração: adiciona coluna nome_search se não existir
try { db.exec(`ALTER TABLE produtos ADD COLUMN nome_search TEXT`); } catch(e) {}
// Popula nome_search em todos os produtos que ainda não têm
const semNorm = db.prepare(`SELECT id, nome FROM produtos WHERE nome_search IS NULL OR nome_search = ''`).all();
if (semNorm.length > 0) {
  const updateNorm = db.prepare(`UPDATE produtos SET nome_search = ? WHERE id = ?`);
  const normTx = db.transaction(() => {
    for (const p of semNorm) updateNorm.run(normalizeSearch(p.nome), p.id);
  });
  normTx();
  console.log(`✅ nome_search populado para ${semNorm.length} produtos`);
}

const userCount = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
if (userCount === 0) {
  const adminUser = sanitizeText(process.env.ADMIN_USER || 'admin', 40) || 'admin';
  const adminName = sanitizeText(process.env.ADMIN_NAME || 'Administrador', 60) || 'Administrador';
  const adminPass = process.env.ADMIN_PASSWORD || 'Toca123!';
  db.prepare(`
    INSERT INTO users (username, nome, role, password_hash)
    VALUES (?, ?, 'admin', ?)
  `).run(adminUser, adminName, hashPassword(adminPass));
  console.log(`🔐 Usuário inicial criado: ${adminUser}`);
}
const seedUsers = [
  { username: 'nayara.admin', nome: 'Nayara', role: 'admin', password: 'Nayara@2026Tc' },
  { username: 'Simone.gerente', nome: 'Simone', role: 'gerente', password: 'Simone@2026Tc' },
  { username: 'estoque.operacao', nome: 'Estoque', role: 'operador', password: 'Estoque@2026Tc' },
];

const insertSeedUser = db.prepare(`
  INSERT OR IGNORE INTO users (username, nome, role, password_hash, active, created_at, updated_at)
  VALUES (?, ?, ?, ?, 1, datetime('now','localtime'), datetime('now','localtime'))
`);

for (const u of seedUsers) {
  insertSeedUser.run(
    u.username,
    u.nome,
    u.role,
    hashPassword(u.password)
  );
}
const count = db.prepare('SELECT COUNT(*) as n FROM produtos').get();
if (count.n === 0) {
  const seedPath = path.join(__dirname, 'produtos_seed.json');
  if (fs.existsSync(seedPath)) {
    const produtos = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
    const insert = db.prepare(`
      INSERT OR IGNORE INTO produtos (nome, categoria, unidade, qtd, minimo, custo)
      VALUES (@nome, @categoria, @unidade, @qtd, @minimo, @custo)
    `);
    const insertMany = db.transaction((prods) => {
      for (const p of prods) insert.run(p);
    });
    insertMany(produtos);
    console.log(`✅ ${produtos.length} produtos carregados no banco.`);
  }
}

// ==================== AUTH ====================
app.post('/api/login', (req, res) => {
  const username = sanitizeText(req.body?.username, 40).toLowerCase();
  const password = String(req.body?.password || '');
  if (!username || !password) {
    return res.status(400).json({ erro: 'Usuário e senha são obrigatórios.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE lower(username) = ? AND active = 1').get(username);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ erro: 'Usuário ou senha inválidos.' });
  }

  const token = createSession(user);
  db.prepare(`
    INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at)
    VALUES (?, ?, ?, 'login', ?, ?, datetime('now','localtime'))
  `).run(user.id, user.nome, user.role, JSON.stringify({ username: user.username }), sanitizeText(req.ip, 80));

  res.json({
    token,
    user: { id: user.id, username: user.username, nome: user.nome, role: user.role },
  });
});

app.post('/api/logout', auth, (req, res) => {
  sessions.delete(req.token);
  db.prepare(`
    INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at)
    VALUES (?, ?, ?, 'logout', ?, ?, datetime('now','localtime'))
  `).run(req.user.id, req.user.nome, req.user.role, '{}', sanitizeText(req.ip, 80));
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({
    user: { id: req.user.id, username: req.user.username, nome: req.user.nome, role: req.user.role },
    permissions: {
      pode_resetar: req.user.role === 'admin',
      pode_editar_produto: ['admin', 'gerente'].includes(req.user.role),
      pode_exportar: true,
      pode_lancar: true,
    },
  });
});

app.put('/api/me', auth, (req, res) => {
  const nome = sanitizeText(req.body?.nome, 60);
  if (!nome || nome.length < 2) return res.status(400).json({ erro: 'Nome inválido.' });
  db.prepare(`UPDATE users SET nome = ?, updated_at = datetime('now','localtime') WHERE id = ?`).run(nome, req.user.id);
  db.prepare(`INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at) VALUES (?,?,?,'editar_perfil',?,?,datetime('now','localtime'))`)
    .run(req.user.id, req.user.nome, req.user.role, JSON.stringify({ nome_anterior: req.user.nome, nome_novo: nome }), sanitizeText(req.ip, 80));
  res.json({ ok: true, nome });
});

app.post('/api/change-password', auth, (req, res) => {
  const current = String(req.body?.current_password || '');
  const next = String(req.body?.new_password || '');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!verifyPassword(current, user.password_hash)) {
    return res.status(400).json({ erro: 'Senha atual incorreta.' });
  }
  if (next.length < 6) {
    return res.status(400).json({ erro: 'A nova senha precisa ter pelo menos 6 caracteres.' });
  }
  db.prepare('UPDATE users SET password_hash = ?, updated_at = datetime(\'now\',\'localtime\') WHERE id = ?')
    .run(hashPassword(next), req.user.id);
  db.prepare(`
    INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at)
    VALUES (?, ?, ?, 'change_password', ?, ?, datetime('now','localtime'))
  `).run(req.user.id, req.user.nome, req.user.role, '{}', sanitizeText(req.ip, 80));
  res.json({ ok: true });
});

// ==================== ROTAS PRODUTOS ====================
app.get('/api/produtos', auth, (req, res) => {
  const { cat, status, q } = req.query;
  let sql = 'SELECT * FROM produtos WHERE 1=1';
  const params = [];
  if (q) { sql += ' AND nome LIKE ?'; params.push(`%${sanitizeText(q, 100)}%`); }
  if (cat) { sql += ' AND categoria = ?'; params.push(sanitizeText(cat, 80)); }
  sql += calcStatusClause(status);
  sql += ' ORDER BY categoria, nome';
  const rows = db.prepare(sql).all(...params);
  res.json(rows);
});

app.get('/api/produtos/buscar', auth, (req, res) => {
  const q = sanitizeText(req.query?.q, 100);
  if (!q || q.length < 2) return res.json([]);
  const qNorm = normalizeSearch(q);
  const rows = db.prepare(`
    SELECT id, nome, categoria, unidade, qtd, minimo, custo
    FROM produtos WHERE nome_search LIKE ? ORDER BY nome LIMIT 15
  `).all(`%${qNorm}%`);
  res.json(rows);
});

app.get('/api/categorias', auth, (req, res) => {
  const rows = db.prepare('SELECT DISTINCT categoria FROM produtos ORDER BY categoria').all();
  res.json(rows.map(r => r.categoria));
});

app.post('/api/produtos', auth, requireRole('admin', 'gerente'), (req, res) => {
  const nome = sanitizeText(req.body?.nome, 120);
  const categoria = sanitizeText(req.body?.categoria, 80);
  const unidade = sanitizeText(req.body?.unidade, 20);
  const minimo = parseNonNegativeNumber(req.body?.minimo ?? 1);
  const custo = parseNonNegativeNumber(req.body?.custo ?? 0);
  const qtd = parseNonNegativeNumber(req.body?.qtd ?? 0);
  if (!nome || !categoria || !unidade) return res.status(400).json({ erro: 'Nome, categoria e unidade são obrigatórios.' });
  try {
    const info = db.prepare(`
      INSERT INTO produtos (nome, nome_search, categoria, unidade, qtd, minimo, custo)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(nome, normalizeSearch(nome), categoria, unidade, qtd ?? 0, minimo ?? 1, custo ?? 0);
    db.prepare(`INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at) VALUES (?,?,?,'criar_produto',?,?,datetime('now','localtime'))`)
      .run(req.user.id, req.user.nome, req.user.role, JSON.stringify({ nome, categoria, unidade }), sanitizeText(req.ip, 80));
    const novo = db.prepare('SELECT * FROM produtos WHERE id = ?').get(info.lastInsertRowid);
    res.json({ ok: true, produto: novo });
  } catch(e) {
    if (e.message.includes('UNIQUE')) return res.status(400).json({ erro: 'Produto já cadastrado com este nome.' });
    res.status(500).json({ erro: 'Erro ao cadastrar produto.' });
  }
});

app.put('/api/produtos/:id', auth, requireRole('admin', 'gerente'), (req, res) => {
  const custo = parseNonNegativeNumber(req.body?.custo);
  const minimo = parseNonNegativeNumber(req.body?.minimo);
  if (custo === null || minimo === null) {
    return res.status(400).json({ erro: 'Custo e mínimo devem ser números maiores ou iguais a zero.' });
  }
  const produto = db.prepare('SELECT * FROM produtos WHERE id = ?').get(req.params.id);
  if (!produto) return res.status(404).json({ erro: 'Produto não encontrado.' });

  db.prepare(`
    UPDATE produtos
    SET custo = ?, minimo = ?, updated_at = datetime('now','localtime')
    WHERE id = ?
  `).run(custo, minimo, req.params.id);

  db.prepare(`
    INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at)
    VALUES (?, ?, ?, 'produto_update', ?, ?, datetime('now','localtime'))
  `).run(
    req.user.id,
    req.user.nome,
    req.user.role,
    JSON.stringify({ produto_id: produto.id, produto_nome: produto.nome, custo, minimo }),
    sanitizeText(req.ip, 80)
  );

  res.json({ ok: true });
});

// ==================== ROTAS MOVIMENTAÇÕES ====================
app.post('/api/movimentacoes', auth, (req, res) => {
  const produto_nome = sanitizeText(req.body?.produto_nome, 120);
  const tipo = sanitizeText(req.body?.tipo, 20);
  const motivo = sanitizeText(req.body?.motivo, 80);
  const obs = sanitizeText(req.body?.obs, 200);
  const qtdInput = req.body?.qtd;

  if (!produto_nome || !['Entrada', 'Saída', 'Perda', 'Ajuste'].includes(tipo)) {
    return res.status(400).json({ erro: 'Produto e tipo válidos são obrigatórios.' });
  }

  const prod = db.prepare('SELECT * FROM produtos WHERE nome = ? COLLATE NOCASE').get(produto_nome);
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });

  let qtd;
  if (tipo === 'Ajuste') qtd = parseNonNegativeNumber(qtdInput);
  else qtd = parsePositiveNumber(qtdInput);
  if (qtd === null) {
    return res.status(400).json({ erro: tipo === 'Ajuste' ? 'Ajuste deve ser zero ou maior.' : 'Quantidade deve ser maior que zero.' });
  }

  const custoBody = req.body?.custo === '' || req.body?.custo === null || req.body?.custo === undefined
    ? null
    : parseNonNegativeNumber(req.body?.custo);
  if (req.body?.custo !== '' && req.body?.custo !== null && req.body?.custo !== undefined && custoBody === null) {
    return res.status(400).json({ erro: 'Custo informado é inválido.' });
  }

  let novaQtd = prod.qtd;
  if (tipo === 'Entrada') {
    novaQtd = Number((prod.qtd + qtd).toFixed(3));
  } else if (tipo === 'Saída' || tipo === 'Perda') {
    if (qtd > prod.qtd) {
      return res.status(400).json({ erro: `Estoque insuficiente. Disponível: ${prod.qtd} ${prod.unidade}.` });
    }
    novaQtd = Number((prod.qtd - qtd).toFixed(3));
  } else if (tipo === 'Ajuste') {
    novaQtd = Number(qtd.toFixed(3));
  }

  const custoUnit = custoBody !== null ? custoBody : Number(prod.custo || 0);
  const valorBase = tipo === 'Ajuste' ? Math.abs(novaQtd - prod.qtd) : qtd;
  const valor = Number((custoUnit * valorBase).toFixed(2));

  const tx = db.transaction(() => {
    if (tipo === 'Entrada' && custoBody !== null) {
      db.prepare(`UPDATE produtos SET qtd = ?, custo = ?, updated_at = datetime('now','localtime') WHERE id = ?`)
        .run(novaQtd, custoUnit, prod.id);
    } else {
      db.prepare(`UPDATE produtos SET qtd = ?, updated_at = datetime('now','localtime') WHERE id = ?`)
        .run(novaQtd, prod.id);
    }

    db.prepare(`
  INSERT INTO movimentacoes (
    produto_id, produto_nome, categoria, tipo, qtd, unidade,
    custo, valor, motivo, responsavel, obs, created_at
  )
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`).run(
  prod.id,
  prod.nome,
  prod.categoria,
  tipo,
  tipo === 'Ajuste' ? novaQtd : qtd,
  prod.unidade,
  custoUnit,
  valor,
  motivo,
  req.user.nome,
  obs,
  nowSP()
);

    db.prepare(`
      INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at)
      VALUES (?, ?, ?, 'movimentacao', ?, ?, datetime('now','localtime'))
    `).run(
      req.user.id,
      req.user.nome,
      req.user.role,
      JSON.stringify({ produto_id: prod.id, produto_nome: prod.nome, tipo, qtd, nova_qtd: novaQtd, motivo }),
      sanitizeText(req.ip, 80)
    );
  });

  tx();

  const prodAtualizado = db.prepare('SELECT * FROM produtos WHERE id = ?').get(prod.id);
  res.json({ ok: true, produto: prodAtualizado });
});

app.delete('/api/movimentacoes/:id', auth, requireRole('admin', 'gerente'), (req, res) => {
  const mov = db.prepare('SELECT * FROM movimentacoes WHERE id = ?').get(req.params.id);
  if (!mov) return res.status(404).json({ erro: 'Movimentação não encontrada.' });
  const prod = db.prepare('SELECT * FROM produtos WHERE id = ?').get(mov.produto_id);
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado.' });
  let novaQtd = prod.qtd;
  if (mov.tipo === 'Entrada') {
    novaQtd = Number((prod.qtd - mov.qtd).toFixed(3));
    if (novaQtd < 0) return res.status(400).json({ erro: `Não é possível cancelar: estoque ficaria negativo (${prod.qtd} disponível).` });
  } else if (mov.tipo === 'Saída' || mov.tipo === 'Perda') {
    novaQtd = Number((prod.qtd + mov.qtd).toFixed(3));
  } else if (mov.tipo === 'Ajuste') {
    return res.status(400).json({ erro: 'Ajustes não podem ser cancelados. Use um novo Ajuste para corrigir.' });
  }
  const tx = db.transaction(() => {
    db.prepare(`UPDATE produtos SET qtd = ?, updated_at = datetime('now','localtime') WHERE id = ?`).run(novaQtd, prod.id);
    db.prepare(`DELETE FROM movimentacoes WHERE id = ?`).run(mov.id);
    db.prepare(`INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at) VALUES (?,?,?,'cancelar_movimentacao',?,?,datetime('now','localtime'))`)
      .run(req.user.id, req.user.nome, req.user.role, JSON.stringify({ mov_id: mov.id, produto: mov.produto_nome, tipo: mov.tipo, qtd: mov.qtd }), sanitizeText(req.ip, 80));
  });
  tx();
  res.json({ ok: true, novaQtd });
});

app.get('/api/movimentacoes', auth, (req, res) => {
  const tipo = sanitizeText(req.query?.tipo, 20);
  const q = sanitizeText(req.query?.q, 100);
  const limit = Math.min(Math.max(parseInt(req.query?.limit || '200', 10), 1), 500);
  let sql = 'SELECT * FROM movimentacoes WHERE 1=1';
  const params = [];
  if (tipo) { sql += ' AND tipo = ?'; params.push(tipo); }
  if (q) {
    sql += ' AND (produto_nome LIKE ? OR motivo LIKE ? OR obs LIKE ? OR responsavel LIKE ?)';
    params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
  }
  sql += ' ORDER BY id DESC LIMIT ?';
  params.push(limit);
  res.json(db.prepare(sql).all(...params));
});

// ==================== DASHBOARD ====================
app.get('/api/dashboard', auth, (req, res) => {
  const zerados = db.prepare('SELECT COUNT(*) as n FROM produtos WHERE qtd = 0').get().n;
  const criticos = db.prepare('SELECT COUNT(*) as n FROM produtos WHERE qtd > 0 AND qtd <= minimo * 0.5').get().n;
  const atencao = db.prepare('SELECT COUNT(*) as n FROM produtos WHERE qtd > minimo * 0.5 AND qtd < minimo').get().n;
  const valorTotal = db.prepare('SELECT SUM(qtd * custo) as v FROM produtos').get().v || 0;
  const hojeSP = nowSP().slice(0, 10);
  const lancHoje = db.prepare(`
    SELECT COUNT(*) as n
    FROM movimentacoes
    WHERE substr(created_at, 1, 10) = ?
  `).get(hojeSP).n;
  const ultimos = db.prepare('SELECT * FROM movimentacoes ORDER BY id DESC LIMIT 8').all();
  res.json({ zerados, criticos, atencao, valorTotal, lancHoje, ultimos });
});

// ==================== EXPORTAR ====================
app.get('/api/exportar/:tipo', auth, (req, res) => {
  const { tipo } = req.params;
  let rows, headers, filename;

  if (tipo === 'estoque') {
    rows = db.prepare('SELECT nome, categoria, unidade, qtd, minimo, custo FROM produtos ORDER BY categoria, nome').all();
    headers = ['Produto','Categoria','Unidade','Qtd Atual','Mínimo','Custo Unit.','Valor Total','Status'];
    rows = rows.map(r => {
      let st = r.qtd === 0 ? 'ZERADO' : r.qtd <= r.minimo * 0.5 ? 'CRITICO' : r.qtd < r.minimo ? 'ATENCAO' : 'OK';
      return [r.nome, r.categoria, r.unidade, r.qtd, r.minimo, r.custo, (r.qtd * r.custo).toFixed(2), st];
    });
    filename = 'estoque_toca_coelho.csv';
  } else if (tipo === 'movimentacoes') {
    rows = db.prepare('SELECT * FROM movimentacoes ORDER BY id DESC').all();
    headers = ['Data/Hora','Produto','Categoria','Tipo','Qtd','Unidade','Custo','Valor','Motivo','Responsável','Obs'];
    rows = rows.map(r => [r.created_at, r.produto_nome, r.categoria, r.tipo, r.qtd, r.unidade, r.custo, r.valor, r.motivo, r.responsavel, r.obs]);
    filename = 'movimentacoes_toca_coelho.csv';
  } else if (tipo === 'compras') {
    rows = db.prepare(`SELECT nome, categoria, unidade, qtd, minimo FROM produtos WHERE qtd <= minimo * 0.5 ORDER BY categoria, nome`).all();
    headers = ['Produto','Categoria','Unidade','Qtd Atual','Mínimo','Sugerido Comprar'];
    rows = rows.map(r => [r.nome, r.categoria, r.unidade, r.qtd, r.minimo, Math.max(0, r.minimo * 2 - r.qtd).toFixed(3)]);
    filename = 'lista_compras_toca_coelho.csv';
  } else {
    return res.status(400).json({ erro: 'Tipo inválido' });
  }

  db.prepare(`
    INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at)
    VALUES (?, ?, ?, 'exportar', ?, ?, datetime('now','localtime'))
  `).run(req.user.id, req.user.nome, req.user.role, JSON.stringify({ tipo }), sanitizeText(req.ip, 80));

  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send('\uFEFF' + csv);
});

app.post('/api/resetar', auth, requireRole('admin'), (req, res) => {
  const confirmacao = sanitizeText(req.body?.confirmacao, 20).toUpperCase();
  if (confirmacao !== 'RESTAURAR') {
    return res.status(400).json({ erro: 'Confirmação inválida. Digite RESTAURAR para continuar.' });
  }
  // Verifica senha do admin como segunda confirmação
  const senhaAdmin = String(req.body?.senha_admin || '');
  const userDb = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!verifyPassword(senhaAdmin, userDb.password_hash)) {
    return res.status(401).json({ erro: 'Senha de administrador incorreta.' });
  }
  const seedPath = path.join(__dirname, 'produtos_seed.json');
  if (!fs.existsSync(seedPath)) return res.status(404).json({ erro: 'Seed não encontrado.' });
  const produtos = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
  const update = db.prepare('UPDATE produtos SET qtd = ?, custo = ?, minimo = ?, updated_at = datetime(\'now\',\'localtime\') WHERE nome = ?');
  const tx = db.transaction(() => {
    for (const p of produtos) update.run(p.qtd, p.custo, p.minimo, p.nome);
    db.prepare(`
      INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at)
      VALUES (?, ?, ?, 'resetar_estoque', ?, ?, datetime('now','localtime'))
    `).run(req.user.id, req.user.nome, req.user.role, JSON.stringify({ total_produtos: produtos.length }), sanitizeText(req.ip, 80));
  });
  tx();
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
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: [
            {
              type: 'image',
              source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: imagem }
            },
            {
              type: 'text',
              text: `Você está lendo um cupom fiscal ou nota fiscal de um restaurante brasileiro.
Extraia TODOS os itens comprados com nome do produto e quantidade.
Responda SOMENTE com JSON válido, sem texto extra, sem markdown, no formato:
{"itens":[{"nome":"Nome do produto","qtd":1.0,"unidade":"KG"}]}
Use unidade KG para peso, UN para unidade, L para litro, CX para caixa.
Se não conseguir ler: {"itens":[],"erro":"descrição do problema"}`
            }
          ]
        }]
      })
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('Anthropic error:', err);
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

    const itens = (parsed.itens || []).map(item => {
      const qNorm = normalizeSearch(item.nome);
      // Primeiro tenta sinônimo exato
      const sinonimo = db.prepare(`SELECT produto_nome FROM sinonimos WHERE termo = ?`).get(qNorm);
      let candidatos = [];
      let produtoExato = null;
      if (sinonimo) {
        const p = db.prepare(`SELECT id, nome, categoria, unidade, qtd, minimo, custo FROM produtos WHERE nome = ? COLLATE NOCASE`).get(sinonimo.produto_nome);
        if (p) { produtoExato = p; candidatos = [p]; }
      }
      if (!produtoExato) {
        // Busca por palavras individuais — resolve nomes compostos fora de ordem
        // Ex: "PEITO FRANGO KG" → encontra "Frango Peito"
        const palavras = qNorm.split(/\s+/).filter(p => p.length > 2);
        if (palavras.length > 1) {
          const scoreMap = new Map();
          for (const palavra of palavras) {
            const matches = db.prepare(`SELECT id, nome, categoria, unidade, qtd, minimo, custo FROM produtos WHERE nome_search LIKE ? ORDER BY nome LIMIT 10`).all(`%${palavra}%`);
            for (const m of matches) {
              const entry = scoreMap.get(m.id) || { produto: m, score: 0 };
              entry.score++;
              scoreMap.set(m.id, entry);
            }
          }
          if (scoreMap.size > 0) {
            candidatos = Array.from(scoreMap.values())
              .sort((a, b) => b.score - a.score)
              .slice(0, 3)
              .map(r => r.produto);
          }
        }
        // Fallback: busca o string completo normalizado
        if (!candidatos.length) {
          candidatos = db.prepare(`SELECT id, nome, categoria, unidade, qtd, minimo, custo FROM produtos WHERE nome_search LIKE ? ORDER BY nome LIMIT 3`).all(`%${qNorm}%`);
        }
      }
      return {
        nome_cupom: item.nome,
        qtd: Number(item.qtd) || 1,
        unidade_cupom: item.unidade || 'UN',
        candidatos,
        produto: candidatos[0] || null,
        via_sinonimo: !!produtoExato
      };
    });

    db.prepare(`
      INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at)
      VALUES (?, ?, ?, 'ler_cupom', ?, ?, datetime('now','localtime'))
    `).run(req.user.id, req.user.nome, req.user.role,
      JSON.stringify({ total_itens: itens.length }), sanitizeText(req.ip, 80));

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

  const totalProd = db.prepare('SELECT COUNT(*) as n FROM produtos').get().n;
  const zerados = db.prepare('SELECT COUNT(*) as n FROM produtos WHERE qtd = 0').get().n;
  const criticos = db.prepare('SELECT COUNT(*) as n FROM produtos WHERE qtd > 0 AND qtd <= minimo * 0.5').get().n;
  const atencao = db.prepare('SELECT COUNT(*) as n FROM produtos WHERE qtd > minimo * 0.5 AND qtd < minimo').get().n;
  const valorTotal = db.prepare('SELECT SUM(qtd * custo) as v FROM produtos').get().v || 0;
  const hojeSP = nowSP().slice(0, 10);
  const lancHoje = db.prepare(`SELECT COUNT(*) as n FROM movimentacoes WHERE substr(created_at,1,10)=?`).get(hojeSP).n;
  const prodZerados = db.prepare(`SELECT nome, categoria FROM produtos WHERE qtd = 0 ORDER BY categoria, nome LIMIT 50`).all();
  const prodCriticos = db.prepare(`SELECT nome, categoria, qtd, minimo, unidade FROM produtos WHERE qtd > 0 AND qtd <= minimo * 0.5 ORDER BY categoria LIMIT 50`).all();
  const prodAtencao = db.prepare(`SELECT nome, categoria, qtd, minimo, unidade FROM produtos WHERE qtd > minimo * 0.5 AND qtd < minimo ORDER BY categoria LIMIT 30`).all();
  const ultimosMov = db.prepare(`SELECT produto_nome, tipo, qtd, unidade, motivo, responsavel, created_at FROM movimentacoes ORDER BY id DESC LIMIT 15`).all();
  const maisConsumidos = db.prepare(`SELECT produto_nome, SUM(qtd) as total, unidade FROM movimentacoes WHERE tipo IN ('Saída','Perda') AND substr(created_at,1,10) >= date(?) GROUP BY produto_nome ORDER BY total DESC LIMIT 10`).all(new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10));
  const cats = db.prepare(`SELECT categoria, COUNT(*) as n, SUM(qtd*custo) as valor FROM produtos GROUP BY categoria ORDER BY valor DESC`).all();

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
- Atenção (qtd entre 50% e 100% do mínimo): ${atencao} produtos
- Valor total em estoque: R$ ${Number(valorTotal).toFixed(2)}
- Lançamentos hoje: ${lancHoje}

=== PRODUTOS ZERADOS — qtd = 0 (${prodZerados.length} total) ===
${prodZerados.map(p => `• ${p.nome} | ${p.categoria}`).join('\n') || 'Nenhum produto zerado.'}

=== PRODUTOS CRÍTICOS — qtd ≤ 50% do mínimo (${prodCriticos.length} total) ===
${prodCriticos.map(p => `• ${p.nome} | qtd: ${p.qtd} | mínimo: ${p.minimo} ${p.unidade} | ${p.categoria}`).join('\n') || 'Nenhum produto crítico.'}

=== PRODUTOS EM ATENÇÃO — qtd entre 50% e 100% do mínimo (${prodAtencao.length} total) ===
${prodAtencao.map(p => `• ${p.nome} | qtd: ${p.qtd} | mínimo: ${p.minimo} ${p.unidade}`).join('\n') || 'Nenhum.'}

=== MAIS CONSUMIDOS (últimos 30 dias) ===
${maisConsumidos.map(p => `• ${p.produto_nome}: ${Number(p.total).toFixed(2)} ${p.unidade}`).join('\n') || 'Sem dados suficientes.'}

=== ÚLTIMAS MOVIMENTAÇÕES ===
${ultimosMov.map(m => `• [${m.created_at}] ${m.tipo} — ${m.produto_nome} ${m.qtd} ${m.unidade||''} (${m.responsavel||''})`).join('\n')}

=== ESTOQUE POR CATEGORIA ===
${cats.map(c => `• ${c.categoria}: ${c.n} produtos, R$ ${Number(c.valor||0).toFixed(2)}`).join('\n')}`;

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
      console.error('Chat API error:', errText);
      return res.status(502).json({ erro: 'Erro na API: ' + errText.slice(0, 200) });
    }
    const data = await response.json();
    const resposta = (data.content||[]).map(b => b.text||'').join('').trim();
    db.prepare(`INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at) VALUES (?,?,?,'chat_ia',?,?,datetime('now','localtime'))`).run(req.user.id, req.user.nome, req.user.role, JSON.stringify({ pergunta: pergunta.slice(0,100) }), sanitizeText(req.ip, 80));
    res.json({ resposta });
  } catch(e) {
    console.error('Erro chat:', e.message);
    res.status(500).json({ erro: 'Erro interno: ' + e.message });
  }
});

// ==================== GERENCIAR USUÁRIOS (admin) ====================
app.get('/api/users', auth, requireRole('admin'), (req, res) => {
  const users = db.prepare(`SELECT id, username, nome, role, active, created_at FROM users ORDER BY role, nome`).all();
  res.json(users);
});

app.post('/api/users', auth, requireRole('admin'), (req, res) => {
  const username = sanitizeText(req.body?.username, 40).toLowerCase();
  const nome = sanitizeText(req.body?.nome, 60);
  const role = sanitizeText(req.body?.role, 20);
  const password = String(req.body?.password || '');
  if (!username || !nome || !password) return res.status(400).json({ erro: 'Preencha todos os campos.' });
  if (!['admin','gerente','operador'].includes(role)) return res.status(400).json({ erro: 'Perfil inválido.' });
  if (password.length < 6) return res.status(400).json({ erro: 'Senha precisa ter pelo menos 6 caracteres.' });
  try {
    db.prepare(`INSERT INTO users (username, nome, role, password_hash, active) VALUES (?,?,?,?,1)`)
      .run(username, nome, role, hashPassword(password));
    db.prepare(`INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at) VALUES (?,?,?,'criar_usuario',?,?,datetime('now','localtime'))`)
      .run(req.user.id, req.user.nome, req.user.role, JSON.stringify({ novo: username, role }), sanitizeText(req.ip, 80));
    res.json({ ok: true });
  } catch(e) {
    if (e.message.includes('UNIQUE')) return res.status(400).json({ erro: 'Usuário já existe.' });
    res.status(500).json({ erro: 'Erro ao criar usuário.' });
  }
});

app.put('/api/users/:id', auth, requireRole('admin'), (req, res) => {
  const { id } = req.params;
  const active = req.body?.active !== undefined ? (req.body.active ? 1 : 0) : null;
  const nova_senha = String(req.body?.nova_senha || '');
  const role = sanitizeText(req.body?.role, 20);

  if (Number(id) === req.user.id && active === 0) return res.status(400).json({ erro: 'Você não pode desativar sua própria conta.' });

  if (active !== null) {
    db.prepare(`UPDATE users SET active=?, updated_at=datetime('now','localtime') WHERE id=?`).run(active, id);
  }
  if (role && ['admin','gerente','operador'].includes(role)) {
    db.prepare(`UPDATE users SET role=?, updated_at=datetime('now','localtime') WHERE id=?`).run(role, id);
  }
  if (nova_senha) {
    if (nova_senha.length < 6) return res.status(400).json({ erro: 'Senha precisa ter pelo menos 6 caracteres.' });
    db.prepare(`UPDATE users SET password_hash=?, updated_at=datetime('now','localtime') WHERE id=?`).run(hashPassword(nova_senha), id);
  }
  db.prepare(`INSERT INTO audit_logs (usuario_id, usuario_nome, role, acao, detalhes, ip, created_at) VALUES (?,?,?,'editar_usuario',?,?,datetime('now','localtime'))`)
    .run(req.user.id, req.user.nome, req.user.role, JSON.stringify({ id, active, role }), sanitizeText(req.ip, 80));
  res.json({ ok: true });
});

// ==================== SINÔNIMOS ====================
app.get('/api/sinonimos', auth, (req, res) => {
  res.json(db.prepare(`SELECT * FROM sinonimos ORDER BY termo`).all());
});

app.post('/api/sinonimos', auth, requireRole('admin', 'gerente'), (req, res) => {
  const termo = sanitizeText(req.body?.termo, 120);
  const produto_nome = sanitizeText(req.body?.produto_nome, 120);
  if (!termo || !produto_nome) return res.status(400).json({ erro: 'Termo e produto são obrigatórios.' });
  const prod = db.prepare(`SELECT nome FROM produtos WHERE nome = ? COLLATE NOCASE`).get(produto_nome);
  if (!prod) return res.status(404).json({ erro: 'Produto não encontrado no estoque.' });
  try {
    db.prepare(`INSERT INTO sinonimos (termo, produto_nome) VALUES (?,?) ON CONFLICT(termo) DO UPDATE SET produto_nome=excluded.produto_nome`)
      .run(normalizeSearch(termo), prod.nome);
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ erro: 'Erro ao salvar sinônimo.' });
  }
});

app.post('/api/sinonimos/importar', auth, requireRole('admin'), (req, res) => {
  const lista = req.body?.lista;
  if (!Array.isArray(lista) || !lista.length) return res.status(400).json({ erro: 'Lista inválida.' });
  let ok = 0, erros = [];
  const upsert = db.prepare(`INSERT OR REPLACE INTO sinonimos (termo, produto_nome) VALUES (?,?)`);
  const tx = db.transaction(() => {
    for (const s of lista) {
      try {
        const termo = normalizeSearch(String(s.termo || ''));
        const prod = db.prepare(`SELECT nome FROM produtos WHERE nome = ? COLLATE NOCASE`).get(s.produto_nome);
        if (!termo || !prod) { erros.push(s.termo); continue; }
        upsert.run(termo, prod.nome); ok++;
      } catch(e) { erros.push(s.termo); }
    }
  });
  tx();
  res.json({ ok, erros });
});

app.delete('/api/sinonimos/:id', auth, requireRole('admin', 'gerente'), (req, res) => {
  db.prepare(`DELETE FROM sinonimos WHERE id=?`).run(req.params.id);
  res.json({ ok: true });
});

// Rota de manutenção - forçar atualização do nome_search
app.get('/api/manutencao/normalizar', auth, requireRole('admin'), (req, res) => {
  const todos = db.prepare(`SELECT id, nome FROM produtos`).all();
  const update = db.prepare(`UPDATE produtos SET nome_search = ? WHERE id = ?`);
  const tx = db.transaction(() => {
    for (const p of todos) update.run(normalizeSearch(p.nome), p.id);
  });
  tx();
  console.log(`✅ nome_search atualizado para ${todos.length} produtos`);
  res.json({ ok: true, total: todos.length, msg: `${todos.length} produtos normalizados!` });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🐰 Toca do Coelho — Estoque rodando em http://localhost:${PORT}`);
});
