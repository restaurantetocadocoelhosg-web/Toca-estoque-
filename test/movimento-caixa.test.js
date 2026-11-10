// Fechamento do dia (08/11/2026): leitor do texto do movimento, perdas em kg, linha BALANÇA,
// preço do quilo (dia útil × fim de semana/feriado) e a conta das bebidas. Módulo puro, sem banco.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const mc = require('../public/movimento-caixa.js');

const TEXTO = fs.readFileSync(path.join(__dirname, 'fixtures', 'movimento-08-11-2026.txt'), 'utf8');
const COM_BALANCA = TEXTO.replace('TOTAL VENDIDO: R$ 6.358,07', 'TOTAL VENDIDO: R$ 6.358,07\nBALANÇA: 70,402 KG');
const soma = (l) => Math.round(l.reduce((s, x) => s + x.valor, 0) * 100) / 100;

test('lê pratos, recebimentos, relatório e total do texto de 08/11', () => {
  const r = mc.lerMovimento(TEXTO);
  assert.equal(r.data, '2026-11-08');
  assert.equal(r.pratos, 150);
  assert.equal(r.pagamentos.length, 6);
  assert.equal(soma(r.pagamentos), 6468.07);
  assert.deepEqual(r.cortes.map((c) => c.valor), [90.17, 248.98, 359.24]);
  assert.deepEqual(r.cortes.map((c) => c.qtd), [2, 5, 6]);
  assert.equal(r.totalDeclarado, 6358.07);
});

test('despesas do dia: 6 itens, R$ 124,10, sem traço sobrando no nome', () => {
  const r = mc.lerMovimento(TEXTO);
  assert.equal(r.despesas.length, 6);
  assert.equal(soma(r.despesas), 124.1);
  assert.equal(r.despesas[0].descricao, 'PAO');
  assert.equal(r.despesas[1].descricao, 'PASSAGEM VILMA');
});

test('seção LIXO: 5 pesos em gramas, nunca dinheiro', () => {
  const r = mc.lerMovimento(TEXTO);
  assert.deepEqual(r.perdas, { lixo_buffet_g: 2890, lixo_salada_g: 6200, desperdicio_g: null, fritura_g: 1750, doacao_corte_g: 2750 });
  assert.ok(!r.despesas.some((d) => /fritura|doa|lixo|desperd/i.test(d.descricao)), 'peso virou despesa');
});

test('linha BALANÇA em vários jeitos de escrever', () => {
  assert.equal(mc.lerMovimento(COM_BALANCA).balancaKg, 70.402);
  assert.equal(mc.lerMovimento(TEXTO.replace('DINHEIRO', 'BALANCA 70.402KG\nDINHEIRO')).balancaKg, 70.402);
  assert.equal(mc.lerMovimento(TEXTO.replace('DINHEIRO', 'BALANÇA KG 70,402\nDINHEIRO')).balancaKg, 70.402);
  assert.equal(mc.lerMovimento(TEXTO).balancaKg, null);
  const r = mc.lerMovimento(COM_BALANCA);
  assert.equal(soma(r.pagamentos), 6468.07, 'balança não pode virar recebimento');
});

test('despesa com KG fora da seção LIXO continua despesa em dinheiro', () => {
  const t = TEXTO.replace('PAO - 8,00', 'PAO - 8,00\nFRANGO 2KG R$ 30,00');
  const r = mc.lerMovimento(t);
  assert.ok(r.despesas.some((d) => d.valor === 30 && /FRANGO/.test(d.descricao)));
});

test('FERIADO no texto é detectado', () => {
  assert.equal(mc.lerMovimento(TEXTO).feriadoNoTexto, false);
  assert.equal(mc.lerMovimento(TEXTO.replace('DOMINGO', 'DOMINGO FERIADO')).feriadoNoTexto, true);
});

test('feriados automáticos (nacionais + RJ)', () => {
  assert.equal(mc.feriadoAutomatico('2026-04-03'), 'Sexta-feira Santa');
  assert.equal(mc.feriadoAutomatico('2026-06-04'), 'Corpus Christi');
  assert.ok(mc.feriadoAutomatico('2026-11-20'));
  assert.ok(mc.feriadoAutomatico('2026-04-23'), 'São Jorge (RJ)');
  assert.equal(mc.feriadoAutomatico('2026-02-17'), null, 'Carnaval não é feriado');
  assert.equal(mc.feriadoAutomatico('2026-11-10'), null);
});

test('preço do quilo: 64,99 seg–sex, 89,99 sábado/domingo/feriado', () => {
  assert.equal(mc.precoKgDoDia('2026-11-08', { feriado: false }).preco, 89.99);
  assert.equal(mc.precoKgDoDia('2026-11-07', { feriado: false }).tipo, 'fim_semana');
  assert.equal(mc.precoKgDoDia('2026-11-10', { feriado: false }).preco, 64.99);
  assert.deepEqual(mc.precoKgDoDia('2026-11-20', { feriado: true }), { preco: 89.99, tipo: 'feriado' });
  const tabela = [{ inicio: '2026-12-01', util: 69.99, fimSemana: 94.99 }];
  assert.equal(mc.precoKgDoDia('2026-12-02', { feriado: false, tabela }).preco, 69.99);
  assert.equal(mc.precoKgDoDia('2026-11-10', { feriado: false, tabela }).preco, 64.99, 'preço novo não volta no tempo');
});

test('conta das bebidas de 08/11 = R$ 830,98', () => {
  const r = mc.lerMovimento(COM_BALANCA);
  const c = mc.contaBalanca({ balancaKg: r.balancaKg, precoKg: 89.99, cortes: r.cortes, totalVendido: soma(r.pagamentos) });
  assert.equal(c.comidaPesada, 6335.48);
  assert.equal(c.relatorio, 698.39);
  assert.equal(c.comidaVendida, 5637.09);
  assert.equal(c.bebidas, 830.98);
  assert.deepEqual(c.pesoCortesKg, [1.002, 2.767, 3.992]);
  assert.equal(mc.contaBalanca({ balancaKg: null, precoKg: 89.99, cortes: [], totalVendido: 100 }), null);
});

test('perdas em reais (só informação)', () => {
  const r = mc.lerMovimento(TEXTO);
  // 2,890 + 6,200 + 1,750 + 2,750 = 13,590 kg × 89,99
  assert.equal(mc.valorPerdas(r.perdas, 89.99), 1222.96);
});

test('avisos: total que não bate, bebidas negativa, balança faltando só a partir de 08/11', () => {
  const r = mc.lerMovimento(TEXTO);
  const avisosSem = mc.avisosMovimento({ totalDeclarado: r.totalDeclarado, totalVendido: 6468.07, conta: null, data: '2026-11-08', balancaKg: null, naoEntendidas: [] });
  assert.ok(avisosSem.some((a) => a.includes('110,00')));
  assert.ok(avisosSem.some((a) => /balan/i.test(a)));
  const antes = mc.avisosMovimento({ totalDeclarado: 100, totalVendido: 100, conta: null, data: '2026-11-07', balancaKg: null, naoEntendidas: [] });
  assert.deepEqual(antes, []);
  const neg = mc.avisosMovimento({ totalDeclarado: 100, totalVendido: 100, conta: { bebidas: -50 }, data: '2026-11-09', balancaKg: 10, naoEntendidas: [] });
  assert.ok(neg.some((a) => /negativ/i.test(a)));
  const fora = mc.avisosMovimento({ totalDeclarado: null, totalVendido: 100, conta: { bebidas: 2000 }, data: '2026-11-09', balancaKg: 10, mediaBebidas14d: 800, naoEntendidas: ['XPTO 12,00'] });
  assert.ok(fora.some((a) => /normal/i.test(a)));
  assert.ok(fora.some((a) => a.includes('XPTO 12,00')));
});

// Leitor antigo (cópia congelada do public/index.html da v126) só para comparar os recebimentos nos textos reais.
function leitorAntigo() {
  const html = fs.readFileSync(path.join(__dirname, 'fixtures', 'leitor-antigo-v126.js.txt'), 'utf8');
  const pegar = (nome) => {
    const ini = html.search(new RegExp(String.raw`(^|\n)[ \t]*(async[ \t]+)?function[ \t]+${nome}[ \t]*\(`));
    let i = html.indexOf('{', ini), n = 0;
    for (; i < html.length; i++) { if (html[i] === '{') n++; else if (html[i] === '}' && --n === 0) break; }
    return html.slice(ini, i + 1).replace(/^\s*async\s+/, '');
  };
  const corpo = pegar('lerRelatorioColado')
    .replace(/function lerRelatorioColado\(\) \{[\s\S]*?const linhas =/, 'function ler(texto) {\n  const linhas =')
    .replace(/\n\s*if \(pratos\) document[\s\S]*$/, '\n  return { pagamentos, despesas };\n}');
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(['moneyFromText', 'extrairValorLinha', 'normalizarLinhaRelatorio', 'extrairLixoBuffet', 'deveIgnorarLinhaFinanceira']
    .map(pegar).join('\n') + '\n' + corpo + '\nglobalThis.ler = ler;', ctx);
  return ctx.ler;
}

const PASTA = 'C:/Users/User/Desktop/fechamento';
test('textos reais de Desktop/fechamento: recebimentos iguais ao leitor antigo e nenhum peso como despesa', { skip: !fs.existsSync(PASTA) }, () => {
  const antigo = leitorAntigo();
  const arquivos = [];
  const andar = (d) => { for (const f of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, f.name); if (f.isDirectory()) andar(p); else if (/^\d{2}-\d{2}-\d{4}\.txt$/.test(f.name)) arquivos.push(p); } }; // só os fechamentos DD-MM-AAAA.txt
  andar(PASTA);
  assert.ok(arquivos.length > 50);
  const diferentes = [];
  for (const arq of arquivos) {
    const t = fs.readFileSync(arq, 'utf8');
    const novo = mc.lerMovimento(t);
    const velho = antigo(t);
    // Diferença só é aceita quando o leitor NOVO bate com o TOTAL escrito no texto e o antigo não
    // (10/11: "DINHEIRO: R$ 236,00 SOBROU 1,75" e "sobrou" na linha de baixo viravam recebimento).
    const novoBateTotal = novo.totalDeclarado != null && soma(novo.pagamentos) === novo.totalDeclarado;
    if (soma(novo.pagamentos) !== soma(velho.pagamentos) && !novoBateTotal) diferentes.push(`${path.basename(arq)}: novo ${soma(novo.pagamentos)} × antigo ${soma(velho.pagamentos)}`);
    for (const d of novo.despesas) {
      assert.ok(!/\b(lixo|fritura|doa[cç]|desperd)/i.test(d.descricao), `${path.basename(arq)}: peso como despesa "${d.descricao}"`);
    }
  }
  assert.deepEqual(diferentes, []);
});

test('balança escrita de outros jeitos, inclusive começando com TOTAL', () => {
  const com = (linha) => mc.lerMovimento(TEXTO.replace('TOTAL VENDIDO: R$ 6.358,07', `TOTAL VENDIDO: R$ 6.358,07\n${linha}`));
  for (const linha of ['TOTAL PESADO BALANÇA: 70,402KG', 'TOTAL PESADO BALANÇA 70,402 KG', 'PESO DA BALANÇA: 70,402 KG', 'BALANÇA TOTAL KG 70,402', 'KG BALANÇA 70,402']) {
    const r = com(linha);
    assert.equal(r.balancaKg, 70.402, linha);
    assert.equal(r.totalDeclarado, 6358.07, `${linha}: não pode virar o TOTAL`);
    assert.equal(Math.round(r.pagamentos.reduce((s, x) => s + x.valor, 0) * 100) / 100, 6468.07, `${linha}: não pode virar recebimento`);
  }
});

test('"01 BALANÇA 49,67" (valor em reais, 09/08) continua recebimento, não peso', () => {
  const r = mc.lerMovimento(TEXTO.replace('DINHEIRO: 918,79', 'DINHEIRO: 918,79\n01 BALANÇA 49,67'));
  assert.equal(r.balancaKg, null);
  assert.ok(r.pagamentos.some((p) => p.valor === 49.67));
  assert.equal(mc.lerMovimento(TEXTO.replace('DINHEIRO', 'BALANÇA: 70,402\nDINHEIRO')).balancaKg, 70.402, '3 casas sem KG = peso');
});

test('04/11: comentário depois do dinheiro não troca o valor nem vira pagamento', () => {
  const r = mc.lerMovimento(`MOVIMENTO
04/11/2026
VOUCHER STONE: R$ 427,52
CRED PAG BANK:R$ 976,99
DEB PAG BANK: R$ 1.087,59
PIX PAG BANK:R$ 750,63
DINHEIRO: R$ 236,00 SOBROU 1,75, SENDO QUE
1,00 CLIENTE DEIXOU DE CAIXINHA E 0,75 DA NAYARA
QUE TINHA PEGO PRA PODER DAR TROCO
TOTAL VENDIDO: R$ 3.478,73`, { anoPadrao: 2026 });
  const din = r.pagamentos.find((p) => /DINHEIRO/i.test(p.descricao));
  assert.equal(din.valor, 236);
  assert.equal(r.pagamentos.length, 5, 'a frase de baixo não é pagamento');
  assert.equal(Math.round(r.pagamentos.reduce((s, p) => s + p.valor, 0) * 100) / 100, 3478.73);
});
