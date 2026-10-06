// Leitura da QUANTIDADE de uma linha de nota (F7 da auditoria Codex, 05/10/2026).
// A nota fala em g, ml, caixa, fardo; o estoque conta em kg, L ou unidade. Aqui a conversão acontece UMA vez só,
// e quando a nota não deixa claro quanto entrou, o item NÃO é lançado no automático: volta `problema` com o motivo
// e vai para conferência. A IA só informa o que leu (qtd, unidade, embalagem, gramatura_kg); quem decide é aqui.

// Número que veio da IA (às vezes "1,5", "2 un"). null se não der para ler.
// QUANTIDADE, não dinheiro: vírgula ou ponto é sempre decimal ("0.750" kg = 0,75, nunca 750).
// Com os dois sinais ("1.234,5") o ponto é milhar. Ambíguo/ilegível → null (vai para conferência).
function lerNumeroNota(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  let s = String(value ?? '').replace(/[^\d.,-]/g, '');
  if (!s) return null;
  if (s.includes(',') && s.includes('.')) s = s.replace(/\./g, '').replace(',', '.');
  else s = s.replace(',', '.');
  if (!/^-?\d+(\.\d+)?$/.test(s)) return null;
  return Number(s);
}

const NOTA_GRAMA = /^(G|GR|GRS|GRAMAS?)$/;
const NOTA_ML = /^(ML|MLS)$/;
const NOTA_KG = /^(KG|KGS|QUILOS?)$/;
const NOTA_EMBALAGEM = /^(CX|CXS|CAIXAS?|FD|FDS|FARDOS?|PCT|PCTS|PACOTES?|PACK|SC|SCS|SACOS?)$/;
const PRODUTO_UN = /^(un|und|unid)/i;
const PRODUTO_KG = /^(kg|quilo)/i;
const PRODUTO_L = /^(l|lt|lts|litros?)$/i;
const tres = (n) => Number(n.toFixed(3));

/**
 * @param {{ item: object, unidadeProduto: string, limites: { qtd: number, embalagem: number, gramatura_kg: number } }} p
 * @returns {{ qtd: number, embalagem: number, convertido: object|null, problema: string|null }}
 */
function converterItemNota({ item, unidadeProduto, limites }) {
  const unNota = String(item.unidade || '').trim().toUpperCase();
  const unProd = String(unidadeProduto || '').trim();
  const prodUn = PRODUTO_UN.test(unProd);
  const prodKg = PRODUTO_KG.test(unProd);
  const prodL = PRODUTO_L.test(unProd);

  const qtdLida = lerNumeroNota(item.qtd);
  let problema = null;
  if (qtdLida === null || qtdLida <= 0) problema = `quantidade "${item.qtd}" inválida`;
  // Inválida/negativa fica 1; exagerada guarda o número lido (quem confere vê o que veio).
  let qtd = qtdLida && qtdLida > 0 ? qtdLida : 1;
  let convertido = null;

  // GRAMA → QUILO e ML → LITRO: "500 G" para produto em kg entrava como 500 kg.
  if (!problema && NOTA_GRAMA.test(unNota) && prodKg) {
    convertido = { tipo: 'grama_para_kg', de: qtd, para: tres(qtd / 1000) };
    qtd = convertido.para;
  } else if (!problema && NOTA_ML.test(unNota) && prodL) {
    convertido = { tipo: 'ml_para_litro', de: qtd, para: tres(qtd / 1000) };
    qtd = convertido.para;
  }
  if (!problema && qtd > limites.qtd) problema = `quantidade ${qtd} acima do limite (${limites.qtd})`;

  // EMBALAGEM FECHADA: a nota vende por CAIXA/FARDO, o estoque conta UNIDADE. "2 caixas de 24 a R$47,88" entrava
  // como 2 latas a R$47,88 (R$3.262 inflados entre 14/07 e 03/08). A IA só INFORMA quantas vêm; multiplica aqui.
  const embLida = lerNumeroNota(item.embalagem);
  const emb = embLida && embLida > 0 ? embLida : 1;
  if (!problema && emb > limites.embalagem) problema = `embalagem de ${emb} unidades acima do limite (${limites.embalagem})`;
  if (!problema && Number(item.gramatura_kg) > limites.gramatura_kg) problema = `pacote de ${item.gramatura_kg} kg acima do limite (${limites.gramatura_kg})`;
  if (!convertido && emb > 1 && prodUn) {
    convertido = { tipo: 'embalagem', de: qtd, embalagem: emb, para: tres(qtd * emb) };
    qtd = convertido.para;
  }
  // GRAMATURA: pacote com PESO no nome e produto por QUILO ("LING FINA PCT 5KG R$80" virava R$80 o quilo).
  const gram = Number(item.gramatura_kg) || 0;
  if (!convertido && gram > 1 && prodKg) {
    convertido = { tipo: 'gramatura', de: qtd, gramatura: gram, para: tres(qtd * gram) };
    qtd = convertido.para;
  }

  // F7: o que a nota não deixa claro NÃO entra sozinho. Só quando o produto (e a unidade dele) já é conhecido.
  if (!problema && unProd) {
    if (NOTA_GRAMA.test(unNota) && !prodKg) problema = 'nota em gramas e o produto não é contado em quilo';
    else if (NOTA_ML.test(unNota) && !prodL) problema = 'nota em ml e o produto não é contado em litro';
    else if (prodUn && NOTA_KG.test(unNota)) problema = 'nota em quilo e o produto é contado em unidade';
    else if (prodUn && NOTA_EMBALAGEM.test(unNota) && emb <= 1) problema = `a nota vende por ${unNota} e não diz quantas unidades vêm`;
    else if (prodKg && !NOTA_KG.test(unNota) && !NOTA_GRAMA.test(unNota) && !convertido) problema = `nota em ${unNota || 'unidade'} e o produto é contado em quilo (sem peso no nome)`;
  }
  const vt = Number(item.valor_total);
  if (!problema && !(item.valor_total !== null && item.valor_total !== undefined && Number.isFinite(vt) && vt > 0)) {
    problema = 'a linha da nota veio sem valor';
  }
  return { qtd, embalagem: emb, convertido, problema };
}

module.exports = { lerNumeroNota, converterItemNota };
