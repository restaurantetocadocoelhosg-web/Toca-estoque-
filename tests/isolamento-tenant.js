// Prova de isolamento entre restaurantes, contra o schema mt (dev).
// Nenhuma linha da produção (schema public) é tocada.
const fs = require('fs');
const { createClient } = require('C:/Users/User/.local/bin/toca-estoque-fix/node_modules/@supabase/supabase-js');
const { criarAcesso, TenantError } = require('C:/Users/User/.local/bin/toca-estoque-fix/tenant.js');

const env = Object.fromEntries(
  fs.readFileSync('C:/Users/User/.local/bin/toca-estoque-fix/.env', 'utf8')
    .split(/\r?\n/).filter(Boolean).map(l => { const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1)]; })
);
const sb = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_KEY, { db: { schema: 'mt' } });

const TOCA = 3, CANTINA = 4;
let falhas = 0;
const ok = (nome, cond, extra = '') => { if (!cond) falhas++; console.log((cond ? 'ok     ' : 'FALHOU ') + nome + (extra ? '  → ' + extra : '')); };

(async () => {
  const toca = criarAcesso(sb, TOCA);
  const cantina = criarAcesso(sb, CANTINA);

  console.log('=== 1. Cada um enxerga só o que é seu ===');
  const { count: pToca } = await toca.from('produtos').select('id', { count: 'exact', head: true });
  const { count: pCantina } = await cantina.from('produtos').select('id', { count: 'exact', head: true });
  ok('Toca enxerga os produtos dele', pToca === 341, `viu ${pToca}`);
  ok('Cantina nasce sem produto nenhum', pCantina === 0, `viu ${pCantina}`);

  const { count: mToca } = await toca.from('movimentacoes').select('id', { count: 'exact', head: true });
  const { count: mCantina } = await cantina.from('movimentacoes').select('id', { count: 'exact', head: true });
  ok('Toca enxerga as movimentações dele', mToca === 7748, `viu ${mToca}`);
  ok('Cantina não enxerga movimentação alguma', mCantina === 0, `viu ${mCantina}`);

  console.log('\n=== 2. Não dá pra alcançar o dado do outro nem sabendo o id ===');
  const { data: alvo } = await toca.from('produtos').select('id, nome').limit(1);
  const idDoToca = alvo[0].id;
  const { data: espiado } = await cantina.from('produtos').select('*').eq('id', idDoToca);
  ok('Cantina buscando o id de um produto do Toca não recebe nada', (espiado || []).length === 0);

  const { data: alterado } = await cantina.from('produtos').update({ nome: 'INVADIDO' }).eq('id', idDoToca).select('id');
  ok('Cantina não consegue alterar produto do Toca', (alterado || []).length === 0);
  const { data: conf } = await toca.from('produtos').select('nome').eq('id', idDoToca);
  ok('nome do produto do Toca continua intacto', conf[0].nome !== 'INVADIDO', conf[0].nome);

  const { data: apagado } = await cantina.from('produtos').delete().eq('id', idDoToca).select('id');
  ok('Cantina não consegue apagar produto do Toca', (apagado || []).length === 0);

  console.log('\n=== 3. Escrita nasce com o dono certo ===');
  const { data: novo } = await cantina.from('produtos')
    .insert({ nome: 'PRODUTO DA CANTINA', categoria: 'Hortifruti', unidade: 'kg', qtd: 5, custo: 10, ativo: 1 })
    .select('id, tenant_id').single();
  ok('insert grava tenant_id sozinho, sem a rota informar', novo.tenant_id === CANTINA, `gravou ${novo.tenant_id}`);
  const { count: tocaVe } = await toca.from('produtos').select('id', { count: 'exact', head: true }).eq('nome', 'PRODUTO DA CANTINA');
  ok('Toca NÃO enxerga o produto criado pela Cantina', tocaVe === 0, `viu ${tocaVe}`);

  console.log('\n=== 4. Tentativa de forjar o dono no payload ===');
  const { data: forjado } = await cantina.from('produtos')
    .insert({ nome: 'TENTATIVA DE FORJAR', categoria: 'Hortifruti', unidade: 'kg', qtd: 1, custo: 1, ativo: 1, tenant_id: TOCA })
    .select('id, tenant_id').single();
  ok('tenant_id mandado pela rota é sobrescrito, não obedecido', forjado.tenant_id === CANTINA, `gravou ${forjado.tenant_id}`);

  console.log('\n=== 5. O código recusa o que é perigoso ===');
  try { criarAcesso(sb, null); ok('acesso sem tenant é recusado', false); }
  catch (e) { ok('acesso sem tenant é recusado', e instanceof TenantError); }
  try { cantina.from('tenants'); ok('tabela global barrada no tdb()', false); }
  catch (e) { ok('tabela global barrada no tdb()', e instanceof TenantError); }
  try { cantina.from('tabela_inventada'); ok('tabela não declarada é barrada', false); }
  catch (e) { ok('tabela não declarada é barrada', e instanceof TenantError); }

  console.log('\n=== 6. Agregados não vazam ===');
  const { data: vendasToca } = await toca.from('fechamentos_diarios').select('vendas');
  const { data: vendasCantina } = await cantina.from('fechamentos_diarios').select('vendas');
  const somaToca = (vendasToca || []).reduce((s, r) => s + Number(r.vendas || 0), 0);
  const somaCantina = (vendasCantina || []).reduce((s, r) => s + Number(r.vendas || 0), 0);
  ok('faturamento do Toca aparece só para o Toca', somaToca > 100000, `R$ ${somaToca.toFixed(2)}`);
  ok('faturamento da Cantina é zero', somaCantina === 0, `R$ ${somaCantina.toFixed(2)}`);

  // limpeza do que o teste criou
  await cantina.from('produtos').delete().in('nome', ['PRODUTO DA CANTINA', 'TENTATIVA DE FORJAR']);

  console.log(falhas ? `\n${falhas} FALHA(S) — isolamento NÃO está garantido` : '\nIsolamento provado: 16/16.');
  process.exit(falhas ? 1 : 0);
})().catch(e => { console.error('ERRO:', e.message); process.exit(1); });
