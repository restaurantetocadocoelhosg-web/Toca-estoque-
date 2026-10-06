// F7 (auditoria Codex) — unidade e embalagem da nota × unidade do produto. A nota fala em g/ml/caixa; o estoque conta em
// kg/L/unidade. Converter UMA vez só, e na dúvida NÃO lançar no automático: vai para conferência com o motivo.
const test = require('node:test');
const assert = require('node:assert/strict');
const { converterItemNota } = require('../nota-unidades');

const LIM = { qtd: 1000, embalagem: 200, gramatura_kg: 50 };
const conv = (item, unidadeProduto) => converterItemNota({ item, unidadeProduto, limites: LIM });

// ── o que já funcionava continua igual ──
test('caixa com 24 para produto em unidade: 2 caixas = 48 unidades (uma conversão só)', () => {
  const r = conv({ qtd: 2, unidade: 'UN', valor_total: 95.76, embalagem: 24 }, 'un');
  assert.equal(r.qtd, 48);
  assert.equal(r.convertido.tipo, 'embalagem');
  assert.equal(r.problema, null);
});
test('pacote de 5 kg para produto em kg: 1 pacote = 5 kg', () => {
  const r = conv({ qtd: 1, unidade: 'UN', valor_total: 80, gramatura_kg: 5 }, 'kg');
  assert.equal(r.qtd, 5);
  assert.equal(r.convertido.tipo, 'gramatura');
});
test('quilo para produto em quilo: sem conversão', () => {
  const r = conv({ qtd: 18.5, unidade: 'KG', valor_total: 400 }, 'kg');
  assert.equal(r.qtd, 18.5);
  assert.equal(r.convertido, null);
  assert.equal(r.problema, null);
});
test('"1,5" na quantidade é lido como 1,5', () => {
  assert.equal(conv({ qtd: '1,5', unidade: 'KG', valor_total: 30 }, 'kg').qtd, 1.5);
});
test('quantidade negativa vai para conferência', () => {
  assert.match(conv({ qtd: -2, unidade: 'UN', valor_total: 10 }, 'un').problema, /inválida/);
});

// ── F7: o que estava errado ──
test('F7 — nota em GRAMAS para produto em kg: 500 g = 0,5 kg (antes entrava 500 kg)', () => {
  const r = conv({ qtd: 500, unidade: 'G', valor_total: 25 }, 'kg');
  assert.equal(r.qtd, 0.5);
  assert.equal(r.convertido.tipo, 'grama_para_kg');
  assert.equal(r.problema, null);
});
test('F7 — nota em ML para produto em litro: 900 ml = 0,9 L', () => {
  const r = conv({ qtd: 900, unidade: 'ML', valor_total: 12 }, 'L');
  assert.equal(r.qtd, 0.9);
  assert.equal(r.convertido.tipo, 'ml_para_litro');
});
test('F7 — CAIXA sem dizer quantas unidades, produto em unidade: conferência (antes 1 caixa virava 1 unidade a preço de caixa)', () => {
  const r = conv({ qtd: 2, unidade: 'CX', valor_total: 95.76, embalagem: 1 }, 'un');
  assert.match(r.problema, /quantas unidades/);
});
test('F7 — FARDO/PACOTE sem quantidade de unidades: conferência', () => {
  assert.match(conv({ qtd: 1, unidade: 'FD', valor_total: 30, embalagem: 1 }, 'un').problema, /quantas unidades/);
  assert.match(conv({ qtd: 1, unidade: 'PCT', valor_total: 9, embalagem: 1 }, 'un').problema, /quantas unidades/);
});
test('F7 — nota em quilo para produto contado em UNIDADE: conferência (não dá para saber quantas unidades)', () => {
  assert.match(conv({ qtd: 3, unidade: 'KG', valor_total: 30 }, 'un').problema, /quilo/);
});
test('F7 — nota em unidade para produto em QUILO, sem peso no nome: conferência (antes 2 un viravam 2 kg)', () => {
  assert.match(conv({ qtd: 2, unidade: 'UN', valor_total: 14, gramatura_kg: 0 }, 'kg').problema, /peso/);
});
test('F7 — linha SEM valor: conferência (não dá para saber o custo)', () => {
  assert.match(conv({ qtd: 10, unidade: 'UN', valor_total: null }, 'un').problema, /valor/);
});
test('F7 — gramas para produto em UNIDADE: conferência', () => {
  assert.match(conv({ qtd: 500, unidade: 'G', valor_total: 10 }, 'un').problema, /grama/);
});

// ── controles: o que é normal continua automático ──
test('controle — unidade para unidade, com valor: automático', () => {
  const r = conv({ qtd: 12, unidade: 'UN', valor_total: 42 }, 'un');
  assert.equal(r.problema, null);
  assert.equal(r.qtd, 12);
});
test('controle — produto sem unidade conhecida (ainda não identificado): não inventa problema de unidade', () => {
  assert.equal(conv({ qtd: 12, unidade: 'UN', valor_total: 42 }, '').problema, null);
});
test('controle — CX com peso no nome para produto em kg (caixa de 20 kg): converte pelo peso', () => {
  const r = conv({ qtd: 1, unidade: 'CX', valor_total: 458, gramatura_kg: 20 }, 'kg');
  assert.equal(r.qtd, 20);
  assert.equal(r.problema, null);
});
