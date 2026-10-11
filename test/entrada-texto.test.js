// "ENTRADA> 10 FEIJAO 10 ARROZ 15 FARINHA TRIGO" digitado no grupo do estoque: vira itens que vão
// TODOS para Pendentes (o Rubens confirma no app). Aqui só a leitura do texto e a sugestão de produto.
const test = require('node:test');
const assert = require('node:assert/strict');
const { ehEntradaTexto, lerListaEntrada, sugerirProdutos, ajustarAoProduto } = require('../entrada-texto');

test('reconhece o comando ENTRADA> em qualquer caixa, e nada mais', () => {
  assert.ok(ehEntradaTexto('ENTRADA> 10 feijao'));
  assert.ok(ehEntradaTexto('  entrada> 2 arroz'));
  assert.ok(ehEntradaTexto('Entrada >5 sal'));
  assert.ok(!ehEntradaTexto('entrada do salão está suja'));
  assert.ok(!ehEntradaTexto('resumo'));
  assert.ok(!ehEntradaTexto(''));
});

test('uma linha só: separa pelos números (exemplo do Rubens)', () => {
  const r = lerListaEntrada('ENTRADA> 10 FEIJAO 10 ARROZ 15 FARINHA TRIGO');
  assert.deepEqual(r.itens.map(i => [i.qtd, i.nome]), [[10, 'FEIJAO'], [10, 'ARROZ'], [15, 'FARINHA TRIGO']]);
  assert.deepEqual(r.ignorados, []);
});

test('uma por linha ou separado por vírgula: nome pode ter número (Farinha 5kg)', () => {
  const r = lerListaEntrada('entrada>\n10 feijao carioca\n2 farinha de trigo 5kg\n3,5 kg camarão');
  assert.deepEqual(r.itens.map(i => [i.qtd, i.nome, i.unidade]), [[10, 'feijao carioca', null], [2, 'farinha de trigo 5kg', null], [3.5, 'camarão', 'kg']]);
  const v = lerListaEntrada('ENTRADA> 10 feijao, 2 cx coca lata; 1 fd papel toalha');
  assert.deepEqual(v.itens.map(i => [i.qtd, i.nome, i.unidade]), [[10, 'feijao', null], [2, 'coca lata', 'cx'], [1, 'papel toalha', 'fd']]);
});

test('quantidade depois do nome também vale (feijao 10)', () => {
  const r = lerListaEntrada('entrada>\nfeijao 10\ncamarao 2,5kg');
  assert.deepEqual(r.itens.map(i => [i.qtd, i.nome, i.unidade]), [[10, 'feijao', null], [2.5, 'camarao', 'kg']]);
});

test('grama e dúzia viram kg e unidade', () => {
  const r = lerListaEntrada('entrada>\n500g alho\n2 dz ovos');
  assert.deepEqual(r.itens.map(i => [i.qtd, i.nome, i.unidade]), [[0.5, 'alho', 'kg'], [24, 'ovos', 'un']]);
});

test('linha sem quantidade, zero ou exagerada não entra: volta em ignorados', () => {
  const r = lerListaEntrada('entrada>\nfeijao\n0 arroz\n5000 sal\n2 oleo');
  assert.deepEqual(r.itens.map(i => i.nome), ['oleo']);
  assert.equal(r.ignorados.length, 3);
});

test('limite de itens e de tamanho (grupo é entrada de texto livre)', () => {
  const muitos = 'entrada>\n' + Array.from({ length: 50 }, (_, i) => `${i + 1} item${i}`).join('\n');
  const lido = lerListaEntrada(muitos);
  assert.equal(lido.itens.length, 30);
  assert.equal(lido.ignorados.length, 20, 'o que passou do limite tem que aparecer, não sumir');
  assert.match(lido.ignorados[0], /passou de 30 itens/);
  assert.deepEqual(lerListaEntrada('entrada> 600 arroz').itens, [], 'quantidade alta digitada sem nota não vira pendência');
  const enorme = lerListaEntrada('entrada> 2 ' + 'x'.repeat(5000));
  assert.ok(enorme.itens.every(i => i.nome.length <= 60));
  assert.deepEqual(lerListaEntrada('entrada>').itens, []);
});

const PRODS = [
  { id: 1, nome: 'Feijao Carioca', nome_search: 'feijao carioca', unidade: 'kg' },
  { id: 2, nome: 'Feijao Preto', nome_search: 'feijao preto', unidade: 'kg' },
  { id: 3, nome: 'Arroz', nome_search: 'arroz', unidade: 'kg' },
  { id: 4, nome: 'Arroz Integral', nome_search: 'arroz integral', unidade: 'un' },
  { id: 5, nome: 'Farinha de Trigo Venturelli 5kg', nome_search: 'farinha de trigo venturelli 5kg', unidade: 'kg' },
  { id: 6, nome: 'Farinha de Mandioca', nome_search: 'farinha de mandioca', unidade: 'kg' },
];

test('sugestão de produto: apelido > nome exato > palavras (com acento e plural)', () => {
  assert.equal(sugerirProdutos('ARROZ', PRODS, {})[0].id, 3);
  assert.equal(sugerirProdutos('FARINHA TRIGO', PRODS, {})[0].id, 5);
  const fei = sugerirProdutos('FEIJÃO', PRODS, {});
  assert.deepEqual(fei.map(p => p.id).sort(), [1, 2]); // empate: as duas opções, o Rubens escolhe
  assert.equal(sugerirProdutos('feijao', PRODS, { feijao: 'Feijao Preto' })[0].id, 2); // apelido memorizado
  assert.deepEqual(sugerirProdutos('picanha', PRODS, {}), []);
  assert.ok(sugerirProdutos('feijoes', PRODS, {}).length >= 1); // plural
});

test('revisão: "sal" não sugere Salsicha, "ovo" não sugere Novo Tempero', () => {
  const P = [
    { id: 10, nome: 'Salsicha', nome_search: 'salsicha', unidade: 'kg' },
    { id: 11, nome: 'Sal Refinado', nome_search: 'sal refinado', unidade: 'kg' },
    { id: 12, nome: 'Novo Tempero', nome_search: 'novo tempero', unidade: 'un' },
    { id: 13, nome: 'Ovos BRANCO Un', nome_search: 'ovos branco un', unidade: 'UN' },
  ];
  assert.deepEqual(sugerirProdutos('sal', P, {}).map(p => p.id), [11]);
  assert.deepEqual(sugerirProdutos('ovo', P, {}).map(p => p.id), [13]);
  assert.deepEqual(sugerirProdutos('ovos', P, {}).map(p => p.id), [13]);
});

test('revisão: só "ENTRADA>" dispara; "Entrada: o fornecedor atrasou" é conversa', () => {
  assert.ok(!ehEntradaTexto('Entrada: o fornecedor atrasou'));
  assert.ok(!ehEntradaTexto('entrada: 2 arroz'));
});

test('revisão: tamanho colado no nome não vira item; "5 kg" sozinho e "de" no começo', () => {
  assert.deepEqual(lerListaEntrada('ENTRADA> 2 farinha de trigo 5kg 3 arroz').itens.map(i => [i.qtd, i.nome]), [[2, 'farinha de trigo 5kg'], [3, 'arroz']]);
  assert.deepEqual(lerListaEntrada('ENTRADA>\n5 kg\n3 cx\n2 cx de coca').itens.map(i => [i.qtd, i.unidade, i.nome]), [[2, 'cx', 'coca']]);
});

test('revisão: unidade e embalagem acertadas com o produto, ou aviso para conferir', () => {
  assert.deepEqual(ajustarAoProduto({ qtd: 2, unidade: null, nome: 'farinha de trigo 5kg' }, 'kg'), { qtd: 10, unidade: 'kg', conversao: '2 × 5kg = 10 kg', aviso: null });
  assert.equal(ajustarAoProduto({ qtd: 4, unidade: null, nome: 'creme de leite 200g' }, 'kg').qtd, 0.8);
  assert.equal(ajustarAoProduto({ qtd: 2, unidade: null, nome: 'arroz 5kg' }, 'un').qtd, 2, 'produto em un: 2 pacotes são 2');
  assert.equal(ajustarAoProduto({ qtd: 10, unidade: null, nome: 'feijao' }, 'kg').aviso, null);
  assert.equal(ajustarAoProduto({ qtd: 3.5, unidade: 'kg', nome: 'camarao' }, 'kg').aviso, null);
  assert.match(ajustarAoProduto({ qtd: 2, unidade: 'cx', nome: 'coca' }, 'un').aviso, /quantos un vêm em cada cx/);
  assert.equal(ajustarAoProduto({ qtd: 2, unidade: 'cx', nome: 'tampa' }, 'CX').aviso, null);
  assert.match(ajustarAoProduto({ qtd: 0.5, unidade: 'kg', nome: 'alho' }, 'un').aviso, /contado em un/);
  assert.match(ajustarAoProduto({ qtd: 24, unidade: 'un', nome: 'ovos' }, 'kg').aviso, /contado em kg/);
});

// ---- app REAL contra Postgres local: a lista vira pendência, nada entra no estoque ----
const { subirApp } = require('./ambiente/app-teste');
let ctx;
test.before(async () => { ctx = await subirApp(); });
test.after(async () => { if (ctx) await ctx.parar(); });
const zap = (texto) => ctx.apiToken(null, 'POST', '/api/webhook/whatsapp', { secret: 'segredo-de-teste-local', acao: 'entrada_lista', texto, remetente: 'Rubens' });

test('ENTRADA> no grupo: tudo vira pendência, estoque não muda, Pendentes confirma e lança', async () => {
  const feijao = await ctx.criarProduto({ nome: 'Feijao Carioca', unidade: 'kg', qtd: 3, custo: 7.5 });
  const arroz = await ctx.criarProduto({ nome: 'Arroz Agulhinha', unidade: 'kg', qtd: 1, custo: 5 });
  const r = await zap('ENTRADA> 10 FEIJAO CARIOCA 10 ARROZ 2 picanha marciana');
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.pendencias, 3);
  assert.match(r.json.resposta, /nada foi lançado/);
  assert.match(r.json.resposta, /Feijao Carioca/);
  assert.match(r.json.resposta, /não achei no estoque/);
  assert.equal(await ctx.saldo(feijao), 3, 'estoque NÃO pode mudar antes de confirmar');
  assert.equal(await ctx.saldo(arroz), 1);

  const pend = (await ctx.db.query(`select * from nota_pendencias where remetente='Rubens' and status='pendente' order by id`)).rows;
  assert.equal(pend.length, 3);
  assert.equal(Number(pend[0].qtd), 10);
  assert.equal(String(pend[0].candidatos[0].id), String(feijao));
  const comp = (await ctx.db.query('select * from compras where id=$1', [pend[0].compra_id])).rows[0];
  assert.equal(comp.sem_nota, true);
  assert.equal(comp.origem, 'grupo');

  // a mesma lista de novo, no mesmo dia, não duplica
  const de2 = await zap('ENTRADA> 10 FEIJAO CARIOCA 10 ARROZ 2 picanha marciana');
  assert.equal(de2.json.repetida, true);
  assert.equal((await ctx.db.query(`select count(*)::int n from nota_pendencias where remetente='Rubens'`)).rows[0].n, 3);

  // aparece em Pendentes e, confirmando, entra no estoque
  const lista = await ctx.api('admin', 'GET', '/api/pendencias');
  assert.ok(lista.json.some(p => String(p.id) === String(pend[0].id)));
  const ok = await ctx.api('admin', 'POST', `/api/pendencias/${pend[0].id}/resolver`, { produto_id: feijao });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(await ctx.saldo(feijao), 13);
});

test('ENTRADA> sem lista entendível: explica o formato e não grava nada', async () => {
  const antes = (await ctx.db.query('select count(*)::int n from nota_pendencias')).rows[0].n;
  const r = await zap('ENTRADA> feijao arroz');
  assert.match(r.json.resposta, /Não entendi a lista/);
  assert.equal((await ctx.db.query('select count(*)::int n from nota_pendencias')).rows[0].n, antes);
});

test('ENTRADA> sem o segredo do webhook é recusada', async () => {
  const r = await ctx.apiToken(null, 'POST', '/api/webhook/whatsapp', { acao: 'entrada_lista', texto: 'ENTRADA> 10 feijao' });
  assert.equal(r.status, 403);
});

test('ENTRADA> com embalagem: "2 farinha 5kg" vira 10 kg; caixa de produto em un pede conferência', async () => {
  const farinha = await ctx.criarProduto({ nome: 'Farinha de Trigo Teste', unidade: 'kg', qtd: 0, custo: 4 });
  await ctx.criarProduto({ nome: 'Coca Lata Teste', unidade: 'un', qtd: 0, custo: 3 });
  const r = await zap('ENTRADA>\n2 farinha de trigo teste 5kg\n2 cx coca lata teste');
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.match(r.json.resposta, /2 × 5kg = 10 kg/);
  assert.match(r.json.resposta, /confira: 2 cx — quantos un vêm em cada cx/);
  const p = (await ctx.db.query(`select produto_cupom, qtd, unidade_cupom from nota_pendencias where produto_cupom in ('farinha de trigo teste 5kg','coca lata teste') order by id`)).rows;
  assert.deepEqual(p.map(x => [x.produto_cupom, Number(x.qtd), x.unidade_cupom]), [['farinha de trigo teste 5kg', 10, 'kg'], ['coca lata teste', 2, 'cx']]);
  assert.equal(await ctx.saldo(farinha), 0);
});
