// LIVRO DE COMPRAS — Fase 1 dos 3 livros (11/10/2026, aprovado pelo Rubens).
// A NOTA vira documento: uma linha em `compras` (fornecedor, data, total) e cada entrada no estoque
// aponta para ela. Compra na mão sem nota também vira linha (sem_nota) e o gerente aprova.
// As Contas NÃO mudam nesta fase. Banco sem a migração 2026-10-11: tudo aqui devolve null e o app
// segue como antes (nunca derruba um lançamento).
const TOLERANCIA_REAIS = 1.0;        // diferença até R$ 1 entre soma das linhas e total é arredondamento
const TOLERANCIA_PCT = 0.01;         // ou 1% do total, o que for maior
const MAX_TOTAL = 200000;

const tabelaAusente = (e) => e && (e.code === '42P01' || e.code === 'PGRST205' || e.code === '42703' || /does not exist|could not find the table|schema cache/i.test(e.message || ''));

/** Cabeçalho lido da nota, validado. Nunca inventa: o que não fizer sentido vira null. */
function cabecalhoDaNota(bruto = {}, hojeISO) {
  const fornecedor = String(bruto.fornecedor || '').replace(/\s+/g, ' ').trim().slice(0, 120) || null;
  let data_nota = null;
  const d = String(bruto.data_emissao || bruto.data || '').slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(d) && !Number.isNaN(Date.parse(d + 'T12:00:00Z'))) {
    const dias = (Date.parse(hojeISO + 'T12:00:00Z') - Date.parse(d + 'T12:00:00Z')) / 864e5;
    if (dias >= -1 && dias <= 90) data_nota = d; // nota do futuro ou de meses atrás = leitura errada
  }
  const t = Number(bruto.total_nota);
  const total_nota = Number.isFinite(t) && t > 0 && t < MAX_TOTAL ? Math.round(t * 100) / 100 : null;
  return { fornecedor, data_nota, total_nota };
}

/**
 * Situação da nota: soma do que entrou (valor das entradas ligadas) + pendências abertas × total impresso.
 * 'pendente' tem prioridade: enquanto houver linha sem produto, a soma não fecha mesmo.
 */
function situacaoDaCompra({ total_nota, soma_lancada, pendencias_abertas, sem_nota, aprovado_por }) {
  if (sem_nota) return aprovado_por ? 'sem_nota_aprovada' : 'aguardando_aprovacao';
  if (pendencias_abertas > 0) return 'pendente';
  if (!(total_nota > 0)) return 'sem_total';
  const dif = Math.round((Number(soma_lancada || 0) - total_nota) * 100) / 100;
  return Math.abs(dif) <= Math.max(TOLERANCIA_REAIS, total_nota * TOLERANCIA_PCT) ? 'bate' : 'diferenca';
}

/** Cria a compra (ou devolve a que já existe para a mesma foto). Devolve o id ou null. */
const JANELA_AGRUPAR_SEM_NOTA_MS = 30 * 60 * 1000;

async function registrarCompra(supabase, dados) {
  try {
    // Lançou 15 itens "sem nota" seguidos? É UMA compra (mesma pessoa, mesmo motivo, em 30 min) — o gerente
    // aprova uma vez só, não 15.
    if (dados.sem_nota && !dados.nota_hash) {
      let q = supabase.from('compras').select('id').eq('sem_nota', true).eq('origem', dados.origem)
        .eq('remetente', String(dados.remetente || '').slice(0, 80) || '')
        .eq('motivo_sem_nota', String(dados.motivo_sem_nota || 'não informado').slice(0, 200))
        .gte('criado_em', new Date(Date.now() - JANELA_AGRUPAR_SEM_NOTA_MS).toISOString());
      q = dados.aprovado_por ? q.not('aprovado_por', 'is', null) : q.is('aprovado_por', null);
      const { data: igual, error: eG } = await q.order('criado_em', { ascending: false }).limit(1);
      if (eG) throw eG;
      if (igual && igual.length) return Number(igual[0].id);
    }
    if (dados.nota_hash) {
      const { data: ja, error: e1 } = await supabase.from('compras').select('id').eq('nota_hash', dados.nota_hash).limit(1);
      if (e1) throw e1;
      if (ja && ja.length) return Number(ja[0].id);
    }
    const linha = {
      origem: dados.origem, nota_hash: dados.nota_hash || null,
      fornecedor: dados.fornecedor || null, data_nota: dados.data_nota || null, total_nota: dados.total_nota ?? null,
      remetente: String(dados.remetente || '').slice(0, 80) || null,
      sem_nota: !!dados.sem_nota, motivo_sem_nota: dados.sem_nota ? String(dados.motivo_sem_nota || 'não informado').slice(0, 200) : null,
      aprovado_por: dados.aprovado_por || null, aprovado_em: dados.aprovado_por ? new Date().toISOString() : null,
    };
    const { data, error } = await supabase.from('compras').insert(linha).select('id').single();
    if (error) {
      // Corrida: duas leituras da mesma foto ao mesmo tempo. A segunda pega a da primeira.
      if (error.code === '23505' && dados.nota_hash) {
        const { data: ja } = await supabase.from('compras').select('id').eq('nota_hash', dados.nota_hash).limit(1);
        if (ja && ja.length) return Number(ja[0].id);
      }
      throw error;
    }
    return Number(data.id);
  } catch (e) {
    if (!tabelaAusente(e)) console.error('[compras] registrar:', e.message);
    return null;
  }
}

/** Liga uma entrada do estoque à compra. Falha não desfaz a entrada (só fica sem vínculo). */
async function ligarMovimento(supabase, movId, compraId) {
  if (!movId || !compraId) return false;
  const { error } = await supabase.from('movimentacoes').update({ compra_id: compraId }).eq('id', movId);
  if (error && !tabelaAusente(error)) console.error('[compras] ligar movimento:', error.message);
  return !error;
}

/** É uma NOTA de verdade deste restaurante? Compra "sem nota" não serve: ligar a ela pularia a aprovação. */
async function compraExiste(supabase, compraId) {
  const id = Number(compraId);
  if (!Number.isInteger(id) || id <= 0) return false;
  const { data, error } = await supabase.from('compras').select('id').eq('id', id).eq('sem_nota', false).limit(1);
  if (error) return tabelaAusente(error) ? false : 'erro';
  return !!(data && data.length);
}

// PostgREST devolve no máximo 1.000 linhas por pedido: sem paginar, a soma da nota sairia menor e a
// tela diria "NÃO bate" sem motivo (mesma armadilha do Histórico em agosto).
async function todasAsLinhas(pagina, tamanho = 1000) {
  const todas = [];
  for (let de = 0; ; de += tamanho) {
    const { data, error } = await pagina(de, de + tamanho - 1);
    if (error) throw error;
    todas.push(...(data || []));
    if (!data || data.length < tamanho) return todas;
  }
}

/** Lista as compras recentes com a conferência de cada uma. */
async function listarCompras(supabase, { desdeISO, limite = 200 }) {
  const { data: compras, error } = await supabase.from('compras').select('*').gte('criado_em', desdeISO)
    .order('criado_em', { ascending: false }).limit(limite);
  if (error) { if (tabelaAusente(error)) return { indisponivel: true, compras: [] }; throw error; }
  const ids = (compras || []).map((c) => c.id);
  const somas = new Map(), itens = new Map(), pend = new Map(), pendValor = new Map();
  if (ids.length) {
    const movs = await todasAsLinhas((de, ate) => supabase.from('movimentacoes').select('id, compra_id, valor').in('compra_id', ids).order('id').range(de, ate));
    for (const m of movs) {
      somas.set(m.compra_id, (somas.get(m.compra_id) || 0) + Number(m.valor || 0));
      itens.set(m.compra_id, (itens.get(m.compra_id) || 0) + 1);
    }
    const pends = await todasAsLinhas((de, ate) => supabase.from('nota_pendencias').select('id, compra_id, valor_total').in('compra_id', ids).eq('status', 'pendente').order('id').range(de, ate));
    for (const p of pends) {
      pend.set(p.compra_id, (pend.get(p.compra_id) || 0) + 1);
      pendValor.set(p.compra_id, (pendValor.get(p.compra_id) || 0) + Number(p.valor_total || 0));
    }
  }
  return {
    compras: (compras || []).map((c) => {
      const soma_lancada = Math.round((somas.get(c.id) || 0) * 100) / 100;
      const pendencias_abertas = pend.get(c.id) || 0;
      const total = c.total_nota === null ? null : Number(c.total_nota);
      return {
        id: Number(c.id), origem: c.origem, fornecedor: c.fornecedor, data_nota: c.data_nota, total_nota: total,
        remetente: c.remetente, sem_nota: c.sem_nota, motivo_sem_nota: c.motivo_sem_nota, aprovado_por: c.aprovado_por,
        criado_em: c.criado_em, itens: itens.get(c.id) || 0, soma_lancada, pendencias_abertas,
        valor_pendente: Math.round((pendValor.get(c.id) || 0) * 100) / 100,
        diferenca: total ? Math.round((soma_lancada - total) * 100) / 100 : null,
        situacao: situacaoDaCompra({ total_nota: total, soma_lancada, pendencias_abertas, sem_nota: c.sem_nota, aprovado_por: c.aprovado_por }),
      };
    }),
  };
}

module.exports = { cabecalhoDaNota, situacaoDaCompra, registrarCompra, ligarMovimento, compraExiste, listarCompras, tabelaAusente, todasAsLinhas };
