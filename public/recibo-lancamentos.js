// RECIBO DOS LANÇAMENTOS (11/10/2026). Cada aparelho guarda a sua própria lista do que lançou no dia,
// com o código do lançamento. Serve para três coisas:
//   1. Mostrar um recibo que não some: "último lançamento: ✓ salvo às 15:44".
//   2. Avisar antes de lançar de novo a MESMA compra em poucos minutos (06/10: frita 7 + 7 em 16 s).
//   3. "Conferir meu dia": perguntar ao servidor se cada lançamento da lista está mesmo no banco.
// Fica no próprio aparelho (localStorage). Se o navegador apagar, o app continua funcionando sem a lista.
(function (raiz) {
  const PREFIXO = 'toca-recibo:';
  const DIAS_GUARDADOS = 3;
  const JANELA_REPETIDO_MS = 3 * 60 * 1000;

  function diaBrasilia(d) {
    return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Sao_Paulo', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
  }
  function horaBrasilia(d) {
    return new Intl.DateTimeFormat('pt-BR', { timeZone: 'America/Sao_Paulo', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(d);
  }

  function criarDiario(armazem, agora = () => new Date()) {
    const chave = (deslocDias = 0) => PREFIXO + diaBrasilia(new Date(agora().getTime() - deslocDias * 864e5));
    function ler(deslocDias = 0) {
      try {
        const v = JSON.parse(armazem.getItem(chave(deslocDias)) || '[]');
        return Array.isArray(v) ? v : []; // lista estragada nunca pode travar um lançamento
      } catch (e) { return []; }
    }
    function gravar(lista, deslocDias = 0) {
      try { armazem.setItem(chave(deslocDias), JSON.stringify(lista)); } catch (e) { /* sem espaço/bloqueado: segue sem lista */ }
    }
    function limparAntigos() {
      try {
        const limite = diaBrasilia(new Date(agora().getTime() - DIAS_GUARDADOS * 864e5));
        const velhas = [];
        for (let i = 0; i < armazem.length; i++) {
          const k = armazem.key(i);
          if (k && k.startsWith(PREFIXO) && k.slice(PREFIXO.length) < limite) velhas.push(k);
        }
        velhas.forEach((k) => armazem.removeItem(k));
      } catch (e) { /* ignora */ }
    }
    /** Cria ou atualiza o item do lançamento (pelo código). Devolve a lista nova. */
    function registrar(item) {
      // Resposta de um envio das 23:59 que chega 00:00: o item está na lista de ONTEM.
      if (!item.produto) {
        const ontem = ler(1);
        const j = ontem.findIndex((x) => x.evento === item.evento);
        if (j >= 0 && !ler().some((x) => x.evento === item.evento)) {
          gravar(ontem.map((x, k) => (k === j ? { ...x, ...item } : x)), 1);
          return ler();
        }
      }
      const lista = ler();
      const i = lista.findIndex((x) => x.evento === item.evento);
      const novo = i >= 0 ? { ...lista[i], ...item } : { quando: agora().getTime(), hora: horaBrasilia(agora()), ...item };
      const saida = i >= 0 ? lista.map((x, j) => (j === i ? novo : x)) : [...lista, novo];
      gravar(saida);
      return saida;
    }
    /** O mesmo produto/tipo/quantidade já foi SALVO por este aparelho há pouco (com outro código)? */
    function repetidoRecente({ produto_id, tipo, qtd, evento, data = '' }) {
      const limite = agora().getTime() - JANELA_REPETIDO_MS;
      return ler().filter((x) => x.status === 'salvo' && x.evento !== evento && x.quando >= limite
        && String(x.produto_id) === String(produto_id) && x.tipo === tipo && Number(x.qtd) === Number(qtd)
        && (x.data || '') === (data || '')).pop() || null;
    }
    const semConfirmacao = () => ler().filter((x) => x.status === 'enviando' || x.status === 'sem_confirmacao');
    const ultimo = () => ler().filter((x) => x.status !== 'nao_enviado').pop() || null;
    /** Junta o que o servidor respondeu em /api/conferir-lancamentos com a lista. */
    function aplicarConferencia(resultado) {
      const porEvento = new Map((resultado || []).map((r) => [r.evento, r]));
      let lista = ler();
      lista = lista.map((x) => {
        const r = porEvento.get(x.evento);
        if (!r) return x;
        const conferido = r.status === 'nao_encontrado' ? 'nao_chegou' : r.status; // salvo | cancelado | nao_chegou
        return { ...x, conferido, ...(r.mov_id ? { mov_id: r.mov_id } : {}) };
      });
      gravar(lista);
      return lista;
    }
    return { ler, registrar, repetidoRecente, semConfirmacao, ultimo, aplicarConferencia, limparAntigos };
  }

  const api = { criarDiario, diaBrasilia, horaBrasilia, JANELA_REPETIDO_MS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else raiz.ReciboLancamentos = api;
})(typeof window !== 'undefined' ? window : globalThis);
