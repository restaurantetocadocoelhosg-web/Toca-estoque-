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
app.use(express.json());
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
    nome_search TEXT,
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
`);

// Migração: adiciona coluna nome_search se não existir
try { db.exec(`ALTER TABLE produtos ADD COLUMN nome_search TEXT`); } catch(e) {}
// Popula nome_search em registros existentes que ainda não têm
const semNorm = db.prepare(`SELECT id, nome FROM produtos WHERE nome_search IS NULL`).all();
const updateNorm = db.prepare(`UPDATE produtos SET nome_search = ? WHERE id = ?`);
for (const p of semNorm) updateNorm.run(normalizeSearch(p.nome), p.id);

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
      INSERT OR IGNORE INTO produtos (nome, nome_search, categoria, unidade, qtd, minimo, custo)
      VALUES (@nome, @nome_search, @categoria, @unidade, @qtd, @minimo, @custo)
    `);
    const insertMany = db.transaction((prods) => {
      for (const p of prods) insert.run({ ...p, nome_search: normalizeSearch(p.nome) });
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
  if (q) { sql += ' AND nome_search LIKE ?'; params.push(`%${normalizeSearch(sanitizeText(q, 100))}%`); }
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

app.get('/api/movimentacoes', auth, (req, res) => {
  const tipo = sanitizeText(req.query?.tipo, 20);
  const q = sanitizeText(req.query?.q, 100);
  const dataInicio = sanitizeText(req.query?.data_inicio, 10);
  const dataFim = sanitizeText(req.query?.data_fim, 10);
  const limit = Math.min(Math.max(parseInt(req.query?.limit || '200', 10), 1), 500);
  let sql = 'SELECT * FROM movimentacoes WHERE 1=1';
  const params = [];
  if (tipo) { sql += ' AND tipo = ?'; params.push(tipo); }
  if (q) {
    sql += ' AND (produto_nome LIKE ? OR motivo LIKE ? OR obs LIKE ? OR responsavel LIKE ?)';
    params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
  }
  if (dataInicio) { sql += ' AND substr(created_at, 1, 10) >= ?'; params.push(dataInicio); }
  if (dataFim) { sql += ' AND substr(created_at, 1, 10) <= ?'; params.push(dataFim); }
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

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🐰 Toca do Coelho — Estoque rodando em http://localhost:${PORT}`);
});
