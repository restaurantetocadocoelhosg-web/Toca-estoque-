// ENTRADA DIGITADA NO GRUPO DO ESTOQUE — "ENTRADA> 10 FEIJAO 10 ARROZ 15 FARINHA TRIGO".
// Pedido do Rubens (11/10): o bot lê a lista e deixa TUDO em Histórico → Pendentes para ele
// só confirmar, como já acontece com a nota quando o bot tem dúvida. Nada é lançado direto:
// texto digitado não tem nota nem preço, e um "100" no lugar de "10" iria direto pro estoque.
// Aqui fica só a parte pura (ler o texto e sugerir o produto), testada em test/entrada-texto.test.js.

const MAX_ITENS = 30;
const MAX_NOME = 60;
// Abaixo do teto de uma linha de nota (LIMITES_NOTA.qtd = 1000): digitado sem nota é mais fácil
// errar um zero; acima disso nem vira pendência, volta como "não entendi".
const MAX_QTD = 500;
// Só "ENTRADA>": com ":" pegava conversa normal do grupo ("Entrada: o fornecedor atrasou").
const PREFIXO = /^\s*entrada\s*>\s*/i;

const UNIDADES = {
  kg: 'kg', kilo: 'kg', kilos: 'kg', quilo: 'kg', quilos: 'kg',
  g: 'g', gr: 'g', grama: 'g', gramas: 'g',
  l: 'l', lt: 'l', litro: 'l', litros: 'l', ml: 'ml',
  un: 'un', und: 'un', unid: 'un', unidade: 'un', unidades: 'un',
  cx: 'cx', caixa: 'cx', caixas: 'cx', pct: 'pct', pacote: 'pct', pacotes: 'pct',
  fd: 'fd', fardo: 'fd', fardos: 'fd', sc: 'sc', saco: 'sc', sacos: 'sc', dz: 'dz', duzia: 'dz', duzias: 'dz',
};
const RE_UNIDADE = Object.keys(UNIDADES).sort((a, b) => b.length - a.length).join('|');
const NUM = '(\\d+(?:[.,]\\d+)?)';
// "10 feijao", "3,5 kg camarão", "2cx coca"
const RE_QTD_ANTES = new RegExp(`^${NUM}\\s*(?:(${RE_UNIDADE})\\.?\\s+|(${RE_UNIDADE})\\.?(?=\\s|$)|\\s+)(.+)$`, 'i');
// "feijao 10", "camarao 2,5kg"
const RE_QTD_DEPOIS = new RegExp(`^(.+?)\\s+${NUM}\\s*(${RE_UNIDADE})?\\.?$`, 'i');

const semAcento = (s) => String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').trim();

function ehEntradaTexto(texto) {
  return PREFIXO.test(String(texto || ''));
}

function montarItem(qtdTxt, unidadeTxt, nomeTxt) {
  let qtd = Number(String(qtdTxt).replace(',', '.'));
  let unidade = unidadeTxt ? UNIDADES[unidadeTxt.toLowerCase()] : null;
  // "2 cx de coca" → "coca"; "5 kg" sozinho não é item (o nome seria só a unidade).
  const nome = String(nomeTxt || '').replace(/\s+/g, ' ').trim().replace(/^(de|do|da|dos|das)\s+/i, '').slice(0, MAX_NOME);
  if (UNIDADES[semAcento(nome).replace(/\.$/, '')]) return null;
  if (unidade === 'g') { qtd = qtd / 1000; unidade = 'kg'; }
  if (unidade === 'ml') { qtd = qtd / 1000; unidade = 'l'; }
  if (unidade === 'dz') { qtd = qtd * 12; unidade = 'un'; }
  qtd = Math.round(qtd * 1000) / 1000;
  if (!nome || nome.length < 2 || !/[a-zà-ú]/i.test(nome)) return null;
  if (!Number.isFinite(qtd) || qtd <= 0 || qtd > MAX_QTD) return null;
  return { qtd, unidade, nome };
}

function lerLinha(linha) {
  const a = linha.match(RE_QTD_ANTES);
  if (a) return montarItem(a[1], a[2] || a[3], a[4]);
  const d = linha.match(RE_QTD_DEPOIS);
  if (d) return montarItem(d[2], d[3], d[1]);
  return null;
}

/**
 * Lê "ENTRADA> 10 FEIJAO 10 ARROZ" (uma linha, separa pelos números) ou uma lista com um
 * item por linha / vírgula / ponto e vírgula (aí o nome pode ter número: "2 farinha 5kg").
 * Devolve { itens: [{qtd, unidade, nome}], ignorados: [linhas que não deu para ler] }.
 */
function lerListaEntrada(texto) {
  const corpo = String(texto || '').slice(0, 3000).replace(PREFIXO, '').trim();
  if (!corpo) return { itens: [], ignorados: [] };
  // Vírgula seguida de número é decimal ("3,5 kg"); as outras separam itens.
  let partes = corpo.split(/\n|;|,(?!\d)/).map(s => s.trim()).filter(Boolean);
  // Uma linha só com vários números ("10 FEIJAO 10 ARROZ"): quebra antes de cada número que começa item.
  if (partes.length === 1) {
    // Número colado na unidade e seguido de outro número ("trigo 5kg 3 arroz") é tamanho, não item novo.
    partes = corpo.split(new RegExp(`\\s+(?=\\d+(?:[.,]\\d+)?(?:\\s*(?:${RE_UNIDADE})\\.?\\s+|\\s+)[a-zà-ú])`, 'i'))
      .map(s => s.trim()).filter(Boolean);
  }
  const itens = [], ignorados = [];
  for (const p of partes) {
    const item = lerLinha(p);
    if (!item) ignorados.push(p.slice(0, MAX_NOME));
    else if (itens.length < MAX_ITENS) itens.push(item);
    else ignorados.push(`${p.slice(0, MAX_NOME)} (passou de ${MAX_ITENS} itens — mande o resto em outra mensagem)`);
  }
  return { itens, ignorados };
}

function singular(palavra) {
  if (palavra.length <= 3) return palavra;
  if (/oes$|aes$/.test(palavra)) return palavra.replace(/(oes|aes)$/, 'ao');
  if (/ns$/.test(palavra)) return palavra.replace(/ns$/, 'm');
  if (/s$/.test(palavra)) return palavra.replace(/s$/, '');
  return palavra;
}

/**
 * Sugere até 3 produtos para o nome digitado: apelido memorizado → nome exato → palavras.
 * Empate fica com as opções (o Rubens escolhe na tela) — nunca adivinha.
 * `apelidos` = { termo_sem_acento: nome_do_produto }.
 */
function sugerirProdutos(nome, produtos, apelidos = {}) {
  const q = semAcento(nome);
  if (!q) return [];
  const doNome = (n) => produtos.find(p => semAcento(p.nome) === semAcento(n));
  if (apelidos[q]) { const p = doNome(apelidos[q]); if (p) return [p]; }
  const exato = produtos.filter(p => (p.nome_search || semAcento(p.nome)) === q);
  if (exato.length) return exato.slice(0, 3);
  const palavras = palavrasDe(q).filter(w => w.length > 2);
  if (!palavras.length) return [];
  const ranking = [];
  for (const p of produtos) {
    const doProduto = palavrasDe(p.nome_search || p.nome);
    let pontos = 0;
    for (const w of palavras) {
      // Palavra INTEIRA: "sal" não é "Salsicha", "ovo" não é "Novo". Começo de palavra só com 4+ letras ("farin" → farinha).
      if (doProduto.includes(w)) pontos += 1;
      else if (w.length >= 4 && doProduto.some(pw => pw.startsWith(w))) pontos += 0.5;
    }
    if (pontos && doProduto[0] === palavras[0]) pontos += 0.25; // "arroz" → "Arroz" antes de "Arroz Integral"
    if (pontos) ranking.push({ p, pontos });
  }
  ranking.sort((a, b) => b.pontos - a.pontos || a.p.nome.length - b.p.nome.length);
  return ranking.slice(0, 3).map(r => r.p);
}

const palavrasDe = (texto) => semAcento(texto).split(/[^a-z0-9]+/).filter(Boolean).map(singular);

// Família da unidade do PRODUTO no estoque: peso, volume ou contagem.
function familia(unidade) {
  const u = semAcento(unidade).replace(/\.$/, '');
  if (/^(kg|kilo|quilo)/.test(u)) return 'kg';
  if (/^(l|lt|litro)s?$/.test(u)) return 'l';
  return 'un';
}

/**
 * Põe a quantidade digitada na unidade do produto, quando dá para ter CERTEZA:
 *  - "2 farinha de trigo 5kg" num produto em kg → 10 kg (o tamanho está no nome);
 *  - mesma família (kg com kg, l com l, un com un) → como veio.
 * Quando não dá (caixa/fardo de produto contado em un, kg de produto em un…), mantém o que
 * foi digitado e devolve `aviso` — a pendência mostra a unidade digitada e a resposta pede conferência.
 */
function ajustarAoProduto(item, unidadeProduto) {
  const fam = familia(unidadeProduto);
  const u = item.unidade;
  const pacote = String(item.nome).match(/(\d+(?:[.,]\d+)?)\s*(kg|g|l|lt|ml)\b/i);
  if ((!u || u === 'un') && pacote && fam !== 'un') {
    let tam = Number(pacote[1].replace(',', '.'));
    const up = pacote[2].toLowerCase();
    if (up === 'g' || up === 'ml') tam /= 1000;
    const famPacote = up === 'kg' || up === 'g' ? 'kg' : 'l';
    if (famPacote === fam && tam > 0) {
      const qtd = Math.round(item.qtd * tam * 1000) / 1000;
      return { qtd, unidade: unidadeProduto, conversao: `${item.qtd} × ${pacote[0].replace(/\s+/g, '')} = ${qtd} ${unidadeProduto}`, aviso: null };
    }
  }
  if (!u) return { qtd: item.qtd, unidade: unidadeProduto || null, conversao: null, aviso: null };
  const famItem = u === 'kg' ? 'kg' : u === 'l' ? 'l' : u === 'un' ? 'un' : 'pacote';
  if (famItem === fam) return { qtd: item.qtd, unidade: unidadeProduto || u, conversao: null, aviso: null };
  // produto contado na própria embalagem (cadastrado como CX, FD, PCT…): caixa é caixa
  if (famItem === 'pacote' && semAcento(unidadeProduto).replace(/\.$/, '').startsWith(u)) return { qtd: item.qtd, unidade: unidadeProduto, conversao: null, aviso: null };
  const aviso = famItem === 'pacote'
    ? `${item.qtd} ${u} — quantos ${unidadeProduto} vêm em cada ${u}?`
    : `${item.qtd} ${u}, mas o produto é contado em ${unidadeProduto}`;
  return { qtd: item.qtd, unidade: u, conversao: null, aviso };
}

module.exports = { ehEntradaTexto, lerListaEntrada, sugerirProdutos, ajustarAoProduto, MAX_ITENS };
