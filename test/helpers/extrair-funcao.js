// Extrai uma função PELO NOME (não por número de linha) de server.js ou public/index.html e a executa num
// contexto isolado. Serve para testar funções puras sem carregar o app inteiro.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function extrairFuncao(arquivoRelativo, nome, contexto = {}) {
  const fonte = fs.readFileSync(path.join(__dirname, '..', '..', arquivoRelativo), 'utf8');
  const inicio = fonte.search(new RegExp(String.raw`(^|\n)[ \t]*(async[ \t]+)?function[ \t]+${nome}[ \t]*\(`));
  if (inicio < 0) throw new Error(`função ${nome} não encontrada em ${arquivoRelativo}`);
  const abre = fonte.indexOf('{', inicio);
  let nivel = 0, fim = -1;
  for (let i = abre; i < fonte.length; i++) {
    if (fonte[i] === '{') nivel++;
    else if (fonte[i] === '}' && --nivel === 0) { fim = i; break; }
  }
  const codigo = fonte.slice(inicio, fim + 1);
  const sandbox = { ...contexto };
  vm.createContext(sandbox);
  vm.runInContext(`${codigo}\n;globalThis.__f = ${nome};`, sandbox);
  return sandbox.__f;
}

module.exports = { extrairFuncao };
