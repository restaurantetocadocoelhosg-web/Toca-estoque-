// Onda S — XSS na tela (public/index.html). Sem navegador: reproduz o que o navegador faz com
// onclick="...": desfaz as entidades HTML do atributo e roda o JS resultante.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { extrairFuncao } = require('./helpers/extrair-funcao');

const HTML = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
const escapeHtml = extrairFuncao('public/index.html', 'escapeHtml');
const jsArg = extrairFuncao('public/index.html', 'jsArg', { escapeHtml });

// O que o navegador faz com o valor do atributo antes de executar o handler.
const desfazEntidades = (s) => s.replace(/&(quot|#39|lt|gt|amp);/g, (_, e) => ({ quot: '"', '#39': "'", lt: '<', gt: '>', amp: '&' }[e]));

const MALICIOSOS = [
  "Ana'); globalThis.invadiu = 1; ('",
  'Bia"); globalThis.invadiu = 1; ("',
  "x\\'); globalThis.invadiu = 1; //",
  '"><img src=x onerror="globalThis.invadiu=1">',
  '</script><script>globalThis.invadiu=1</script>',
  'Café & Cia <b>',
  "D'Ávila",
];

test('jsArg: texto malicioso chega ao handler INTACTO e nada executa', () => {
  for (const nome of MALICIOSOS) {
    const atributo = `renomearUser(7, ${jsArg(nome)})`; // como fica dentro de onclick="..."
    assert.ok(!atributo.includes('"'), 'aspas duplas cruas quebrariam o atributo');
    const recebidos = [];
    const sandbox = { renomearUser: (id, n) => recebidos.push(n) };
    vm.createContext(sandbox);
    vm.runInContext(desfazEntidades(atributo), sandbox);
    assert.equal(sandbox.invadiu, undefined, `executou código com: ${nome}`);
    assert.deepEqual(recebidos, [nome]);
  }
});

test('nenhum handler inline interpola texto entre aspas simples com escapeHtml (padrão vulnerável)', () => {
  const vulneraveis = HTML.split('\n')
    .map((l, i) => [i + 1, l])
    .filter(([, l]) => /on[a-z]+="[^"]*'\$\{escapeHtml\(/.test(l));
  assert.deepEqual(vulneraveis.map(([n]) => n), [], 'use ${jsArg(x)} sem aspas em volta');
});

test('listas de estoque parado e "fantasmas" escapam nome, categoria, unidade e responsável', () => {
  // avisar(msg) escapa a mensagem inteira: texto passado para ele é seguro.
  const linhasHtml = HTML.split('\n').filter((l) => !/\bavisar\(/.test(l));
  for (const campo of ['a.nome', 'a.categoria', 'a.unidade', 'f.nome', 'f.categoria', 'f.unidade', 'f.explica']) {
    assert.ok(!linhasHtml.some((l) => l.includes('${' + campo + '}')), `${campo} sem escape`);
  }
});
