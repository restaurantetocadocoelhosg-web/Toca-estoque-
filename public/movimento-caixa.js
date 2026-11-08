// MOVIMENTO DO CAIXA (08/11/2026). Lê o texto que o Rubens escreve no fim do dia e faz a conta da balança.
// Usado pela tela Dia (navegador: window.MovimentoCaixa) e pelo servidor/testes (require).
//   - Seção __LIXO FINAL BUFFET__: tudo é PESO (gramas). Peso nunca vira dinheiro.
//   - Linha BALANÇA: total pesado do dia (kg).
//   - Bebidas e derivados = total vendido − (balança × preço do quilo − Relatório).
(function (raiz) {
  const PRECOS_PADRAO = { util: 64.99, fimSemana: 89.99 };
  const DATA_INICIO_BALANCA = '2026-11-08';
  const PERDAS_VAZIAS = () => ({ lixo_buffet_g: null, lixo_salada_g: null, desperdicio_g: null, fritura_g: null, doacao_corte_g: null });
  const ROTULOS_PERDAS = {
    lixo_buffet_g: 'Lixo final buffet', lixo_salada_g: 'Lixo salada', desperdicio_g: 'Desperdício',
    fritura_g: 'Fritura', doacao_corte_g: 'Doação/corte',
  };

  const centavos = (n) => Math.round((Number(n) || 0) * 100) / 100;
  const brl = (n) => 'R$ ' + centavos(n).toFixed(2).replace('.', ',').replace(/\B(?=(\d{3})+(?!\d))/g, '.');

  function dinheiro(value) {
    let s = String(value ?? '').trim().replace(/[R$\s]/g, '');
    if (!s) return 0;
    if (/^-?\d{1,3}(\.\d{3})+$/.test(s)) s = s.replace(/\./g, '');
    else if (s.includes(',') && s.includes('.')) s = s.replace(/\./g, '').replace(',', '.');
    else if (s.includes(',')) s = s.replace(',', '.');
    const n = Number(s);
    return Number.isFinite(n) ? n : 0;
  }

  function valorDaLinha(linha) {
    const m = String(linha || '').match(/(?:R\$?\s*)?\d{1,3}(?:\.\d{3})*,\d{2}|(?:R\$?\s*)?\d+[,.]\d{2}/g);
    if (!m || !m.length) return null;
    const raw = m[m.length - 1];
    return { raw, valor: dinheiro(raw) };
  }

  function normal(linha) {
    return String(linha || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .replace(/^[._\-\s]+/, '').replace(/[._\-\s]+$/, '').toLowerCase().trim();
  }

  // Peso em kg com unidade antes ou depois: "KG 2,890", "2,890 KG", "KGB 6,200", "2.785g", "1,7kg".
  // Retorna gramas; "----" ou sem número = null.
  function gramas(linha) {
    const s = String(linha || '');
    let m = s.match(/(\d+(?:[.,]\d+)?)\s*(kgb?|g)\b/i) || s.match(/\b(kgb?|g)\s*(\d+(?:[.,]\d+)?)/i);
    let numero, unidade;
    if (m && /^\d/.test(m[1])) { numero = m[1]; unidade = m[2]; } else if (m) { numero = m[2]; unidade = m[1]; }
    else { const n = s.match(/(\d+[.,]\d+|\d+)\s*$/); if (!n) return null; numero = n[1]; unidade = 'kg'; }
    unidade = unidade.toLowerCase();
    if (unidade === 'g') { const v = Number(numero.replace(/[.,]/g, '')); return Number.isFinite(v) ? v : null; }
    const v = Number(numero.replace(',', '.'));
    return Number.isFinite(v) ? Math.round(v * 1000) : null;
  }

  function chavePerda(n) {
    if (/salada/.test(n)) return 'lixo_salada_g';
    if (/desperd/.test(n)) return 'desperdicio_g';
    if (/fritura/.test(n)) return 'fritura_g';
    if (/doac|corte/.test(n)) return 'doacao_corte_g';
    if (/lixo/.test(n)) return 'lixo_buffet_g';
    return null;
  }

  function dataDoTexto(texto, anoPadrao) {
    for (const m of String(texto || '').matchAll(/\b(\d{1,2})[\/.-](\d{1,2})(?:[\/.-](\d{2,4}))?\b/g)) {
      const dia = Number(m[1]), mes = Number(m[2]);
      let ano = m[3] ? Number(m[3]) : anoPadrao;
      if (ano < 100) ano += 2000;
      if (dia < 1 || dia > 31 || mes < 1 || mes > 12 || ano < 2000) continue;
      const dt = new Date(Date.UTC(ano, mes - 1, dia));
      if (dt.getUTCMonth() !== mes - 1 || dt.getUTCDate() !== dia) continue;
      return `${ano}-${String(mes).padStart(2, '0')}-${String(dia).padStart(2, '0')}`;
    }
    return '';
  }

  const limparDescricao = (linha, raw) => linha.replace(raw, '').replace(/\bR\$/i, '')
    .replace(/^[.\-\s]+/, '').replace(/\s+/g, ' ').trim();

  function lerMovimento(texto, opts = {}) {
    const anoPadrao = opts.anoPadrao || new Date().getFullYear();
    const linhas = String(texto || '').split(/\n+/).map((l) => l.trim()).filter(Boolean);
    const r = {
      data: dataDoTexto(texto, anoPadrao), pratos: 0, pagamentos: [], cortes: [], despesas: [],
      perdas: PERDAS_VAZIAS(), balancaKg: null, feriadoNoTexto: false, totalDeclarado: null, naoEntendidas: [],
    };
    let secao = 'topo';
    let passouTotal = false;

    for (const linha of linhas) {
      const n = normal(linha);
      if (!n) continue;
      const temDigito = /\d/.test(linha);
      if (/\bferiado\b/.test(n)) r.feriadoNoTexto = true;

      // Títulos de seção (sem número).
      if (!temDigito && /^relatorio\b/.test(n)) { secao = 'relatorio'; continue; }
      if (!temDigito && /^despesa/.test(n)) { secao = 'despesas'; continue; }
      if (!temDigito && /^lixo\b/.test(n)) { secao = 'lixo'; continue; }
      if (/^despesa/.test(n)) secao = 'despesas';

      // Balança em qualquer lugar da linha ("TOTAL PESADO BALANÇA 70,402KG", "PESO DA BALANÇA ...").
      // Vem antes do TOTAL: senão "TOTAL PESADO BALANÇA" virava o total vendido e o peso se perdia.
      // Só é PESO com "KG" ou 3 casas (70,402); "01 BALANÇA 49,67" (09/08) é recebimento em reais.
      const ehPesoBalanca = /\bbalanca\b/.test(n) && (/kg/i.test(linha) || (/\d[.,]\d{3}(?!\d)/.test(linha) && !/R\$/i.test(linha)));
      if (ehPesoBalanca) { const g = gramas(linha); if (g != null) r.balancaKg = g / 1000; continue; }

      // Peso: dentro da seção LIXO, ou qualquer linha com "lixo" (jeito antigo).
      if (secao === 'lixo' || /\blixo\b/.test(n)) {
        const chave = chavePerda(n);
        if (chave) { r.perdas[chave] = /-{2,}/.test(linha) && !/\d/.test(linha.replace(/^\D*/, '')) ? null : gramas(linha); }
        else if (temDigito) r.naoEntendidas.push(linha);
        continue;
      }

      if (/^(obs|observacao)\b/.test(n) || /^resta\s+pagar\b/.test(n) || /\btroco\b/.test(n)) continue;
      const pratos = linha.match(/(\d+)\s+pratos?\s+vendidos?/i);
      if (pratos) { r.pratos = Number(pratos[1]) || r.pratos; continue; }
      if (/^total\b/.test(n)) {
        passouTotal = true;
        const v = valorDaLinha(linha);
        if (v && r.totalDeclarado === null) r.totalDeclarado = v.valor;
        continue;
      }
      const achado = valorDaLinha(linha);
      if (!achado) continue;

      if (secao === 'despesas') {
        r.despesas.push({ descricao: limparDescricao(linha, achado.raw).replace(/[\s:\-]+$/, ''), valor: achado.valor });
        continue;
      }
      const m = linha.match(/^(\d+)\s+(.+)$/);
      const qtd = m ? Number(m[1]) : null;
      const descricao = limparDescricao(m ? m[2] : linha, achado.raw);
      const ehCorte = secao === 'relatorio' || passouTotal || /erro|tara|canc|patr|funcion/i.test(normal(descricao));
      (ehCorte ? r.cortes : r.pagamentos).push({ qtd, descricao, valor: achado.valor });
    }
    return r;
  }

  // Páscoa (algoritmo de Meeus/Butcher), em UTC.
  function pascoa(ano) {
    const a = ano % 19, b = Math.floor(ano / 100), c = ano % 100, d = Math.floor(b / 4), e = b % 4;
    const f = Math.floor((b + 8) / 25), g = Math.floor((b - f + 1) / 3), h = (19 * a + b - d - g + 15) % 30;
    const i = Math.floor(c / 4), k = c % 4, l = (32 + 2 * e + 2 * i - h - k) % 7, m = Math.floor((a + 11 * h + 22 * l) / 451);
    const mes = Math.floor((h + l - 7 * m + 114) / 31), dia = ((h + l - 7 * m + 114) % 31) + 1;
    return Date.UTC(ano, mes - 1, dia);
  }
  const FIXOS = {
    '01-01': 'Confraternização Universal', '04-21': 'Tiradentes', '04-23': 'São Jorge', '05-01': 'Dia do Trabalho',
    '09-07': 'Independência', '10-12': 'Nossa Senhora Aparecida', '11-02': 'Finados', '11-15': 'Proclamação da República',
    '11-20': 'Consciência Negra', '12-25': 'Natal',
  };
  function feriadoAutomatico(dataISO) {
    const [ano, mes, dia] = String(dataISO || '').split('-').map(Number);
    if (!ano || !mes || !dia) return null;
    const fixo = FIXOS[`${String(mes).padStart(2, '0')}-${String(dia).padStart(2, '0')}`];
    if (fixo) return fixo;
    const dias = Math.round((Date.UTC(ano, mes - 1, dia) - pascoa(ano)) / 864e5);
    if (dias === -2) return 'Sexta-feira Santa';
    if (dias === 60) return 'Corpus Christi';
    return null;
  }

  function precoKgDoDia(dataISO, { feriado = false, tabela = [] } = {}) {
    const vigente = (tabela || []).filter((t) => t.inicio <= dataISO).sort((a, b) => (a.inicio < b.inicio ? 1 : -1))[0];
    const precos = vigente ? { util: Number(vigente.util), fimSemana: Number(vigente.fimSemana) } : PRECOS_PADRAO;
    if (feriado) return { preco: precos.fimSemana, tipo: 'feriado' };
    const [a, m, d] = String(dataISO).split('-').map(Number);
    const semana = new Date(Date.UTC(a, m - 1, d)).getUTCDay();
    return semana === 0 || semana === 6 ? { preco: precos.fimSemana, tipo: 'fim_semana' } : { preco: precos.util, tipo: 'util' };
  }

  function contaBalanca({ balancaKg, precoKg, cortes = [], totalVendido = 0 }) {
    if (balancaKg == null || !(Number(balancaKg) > 0) || !(Number(precoKg) > 0)) return null;
    const comidaPesada = centavos(Number(balancaKg) * Number(precoKg));
    const relatorio = centavos(cortes.reduce((s, c) => s + (Number(c.valor) || 0), 0));
    const comidaVendida = centavos(comidaPesada - relatorio);
    const bebidas = centavos(Number(totalVendido) - comidaVendida);
    const pesoCortesKg = cortes.map((c) => Math.round(((Number(c.valor) || 0) / Number(precoKg)) * 1000) / 1000);
    return { comidaPesada, relatorio, comidaVendida, bebidas, pesoCortesKg };
  }

  function valorPerdas(perdas, precoKg) {
    const g = Object.values(perdas || {}).reduce((s, v) => s + (Number(v) || 0), 0);
    return centavos((g / 1000) * Number(precoKg || 0));
  }

  function avisosMovimento({ totalDeclarado, totalVendido, conta, data, balancaKg, mediaBebidas14d, naoEntendidas = [] }) {
    const avisos = [];
    if (totalDeclarado != null && Math.abs(centavos(totalVendido - totalDeclarado)) >= 0.01) {
      const dif = centavos(totalVendido - totalDeclarado);
      avisos.push(`TOTAL escrito ${brl(totalDeclarado)}, mas as formas de pagamento somam ${brl(totalVendido)}: diferença de ${brl(Math.abs(dif))} ${dif > 0 ? 'a mais' : 'a menos'}.`);
    }
    if (data && data >= DATA_INICIO_BALANCA && balancaKg == null) avisos.push('Falta a linha BALANÇA (kg pesados no dia).');
    if (conta && conta.bebidas < 0) avisos.push(`Bebidas e derivados deu negativo (${brl(conta.bebidas)}): confira o peso da balança, o preço do quilo e o Relatório.`);
    else if (conta && mediaBebidas14d > 0 && (conta.bebidas < mediaBebidas14d / 2 || conta.bebidas > mediaBebidas14d * 2)) {
      avisos.push(`Bebidas e derivados (${brl(conta.bebidas)}) fora do normal: a média dos últimos dias é ${brl(mediaBebidas14d)}.`);
    }
    for (const l of naoEntendidas) avisos.push(`Linha não entendida (não foi lançada): "${l}".`);
    return avisos;
  }

  const api = {
    lerMovimento, feriadoAutomatico, precoKgDoDia, contaBalanca, valorPerdas, avisosMovimento,
    gramas, PRECOS_PADRAO, DATA_INICIO_BALANCA, ROTULOS_PERDAS, PERDAS_VAZIAS,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else raiz.MovimentoCaixa = api;
})(typeof window !== 'undefined' ? window : globalThis);
