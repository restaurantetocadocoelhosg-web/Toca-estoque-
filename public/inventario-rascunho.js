// RASCUNHO DA CONTAGEM DO INVENTÁRIO (11/11/2026). Em 03/08/2026 uma contagem de 292 itens se perdeu
// porque só existia na tela até clicar em Salvar e a sessão caiu antes.
// Aqui cada número digitado é guardado NO APARELHO (localStorage) na hora. Ele só sai do rascunho
// depois que o servidor confirma que gravou. Se a conexão ou a sessão cair, o número continua aqui
// e sobe sozinho quando a tela voltar.
// O rascunho guarda SÓ o que ainda não foi confirmado: nunca reenvia a tela inteira (uma tela
// desatualizada apagava a contagem feita em outro aparelho).
(function (raiz) {
  const PREFIXO = 'toca_inv_rascunho_';

  /**
   * @param {{getItem:Function,setItem:Function,removeItem:Function,length:number,key:Function}} armazem
   */
  function criarRascunho(armazem) {
    const chave = (invId) => PREFIXO + invId;

    /** @returns {Object<string,string>} pid -> texto digitado ('' = campo apagado) */
    function ler(invId) {
      try {
        const v = JSON.parse(armazem.getItem(chave(invId)) || '{}');
        return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
      } catch (e) { return {}; } // rascunho estragado nunca pode travar a contagem
    }
    function gravar(invId, mapa) {
      try {
        if (Object.keys(mapa).length) armazem.setItem(chave(invId), JSON.stringify(mapa));
        else armazem.removeItem(chave(invId));
        return true;
      } catch (e) { return false; } // aparelho sem espaço ou navegação privada
    }
    function guardar(invId, pid, texto) {
      return gravar(invId, { ...ler(invId), [String(pid)]: String(texto) });
    }
    /** Tira do rascunho só se o texto ainda é o que foi enviado (a pessoa pode ter digitado de novo). */
    function confirmar(invId, enviados) {
      const mapa = { ...ler(invId) };
      for (const [pid, texto] of Object.entries(enviados)) if (mapa[pid] === texto) delete mapa[pid];
      return gravar(invId, mapa);
    }
    function limpar(invId) { try { armazem.removeItem(chave(invId)); } catch (e) { /* sem armazenamento */ } }
    /** Apaga rascunhos de inventários que não são o aberto agora (já fechados em outro aparelho). */
    function limparOutros(invIdAtual) {
      try {
        const velhas = [];
        for (let i = 0; i < armazem.length; i++) {
          const k = armazem.key(i);
          if (k && k.startsWith(PREFIXO) && k !== chave(invIdAtual)) velhas.push(k);
        }
        velhas.forEach((k) => armazem.removeItem(k));
      } catch (e) { /* sem armazenamento */ }
    }
    return { ler, guardar, confirmar, limpar, limparOutros };
  }

  /**
   * Separa o rascunho em itens prontos para o servidor e textos que não são número.
   * @param {Object<string,string>} mapa
   * @param {(v:string)=>number} numQtd
   */
  function prepararEnvio(mapa, numQtd) {
    const itens = [], enviados = {}, invalidos = [];
    for (const [pid, texto] of Object.entries(mapa)) {
      const t = String(texto).trim();
      if (t === '') { itens.push({ produto_id: Number(pid), qtd_contada: null }); enviados[pid] = texto; continue; }
      const n = numQtd(t);
      if (!Number.isFinite(n) || n < 0) { invalidos.push(pid); continue; }
      itens.push({ produto_id: Number(pid), qtd_contada: n });
      enviados[pid] = texto;
    }
    return { itens, enviados, invalidos };
  }

  const api = { PREFIXO, criarRascunho, prepararEnvio };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else raiz.InvRascunho = api;
})(typeof window !== 'undefined' ? window : globalThis);
