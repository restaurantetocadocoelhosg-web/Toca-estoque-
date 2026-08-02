// Abre um restaurante novo pela API e entra nele como o dono, para ver o que ele
// encontra no primeiro dia. Depois confere que o dado dele não encosta no do Toca.
const API = 'http://localhost:3002';
const post = async (t, url, body) => {
  const r = await fetch(API + url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(t ? { Authorization: 'Bearer ' + t } : {}) },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
};
const get = async (t, url) => {
  const r = await fetch(API + url, { headers: { Authorization: 'Bearer ' + t } });
  return { status: r.status, body: await r.json().catch(() => null) };
};
let falhas = 0;
const ok = (n, c, extra = '') => { if (!c) falhas++; console.log((c ? 'ok     ' : 'FALHOU ') + n + (extra ? '  → ' + extra : '')); };

(async () => {
  const slug = 'pizzaria-teste-' + Date.now().toString(36);

  console.log('=== 1. Abrir o restaurante (como plataforma) ===');
  const sup = (await post(null, '/api/login', { username: 'plataforma', password: 'super123' })).body;
  ok('superadmin entra', !!sup.token);

  const criado = await post(sup.token, '/api/plataforma/restaurantes', {
    nome: 'Pizzaria do Teste', slug, cnpj: '11.222.333/0001-44', plano: 'completo',
    admin_usuario: 'dono.' + slug, admin_senha: 'pizza123', admin_nome: 'Dono da Pizzaria',
  });
  ok('restaurante criado', criado.status === 200, criado.body?.erro || '');
  if (criado.status !== 200) process.exit(1);
  const { restaurante, preparado, admin } = criado.body;
  console.log(`       ${restaurante.nome} · plano ${restaurante.plano}`);
  console.log(`       veio com ${preparado.categorias} categorias e ${preparado.produtos} produtos`);
  ok('categorias já vieram', preparado.categorias >= 15, `${preparado.categorias}`);
  ok('catálogo já veio', preparado.produtos >= 280, `${preparado.produtos}`);
  ok('usuário do dono criado', admin?.role === 'admin');

  console.log('\n=== 2. O dono entra e vê o que tem ===');
  const dono = (await post(null, '/api/login', { username: 'dono.' + slug, password: 'pizza123' })).body;
  ok('dono entra com a senha dele', !!dono.token);

  const est = await get(dono.token, '/api/produtos');
  const prods = Array.isArray(est.body) ? est.body : (est.body?.produtos || []);
  ok('estoque já tem a lista pronta', prods.length >= 280, `${prods.length} produtos`);
  console.log('       ex: ' + prods.slice(0, 4).map(p => `${p.nome} (${p.categoria})`).join(' · '));
  ok('produtos vêm ZERADOS (é sugestão, não estoque de mentira)', prods.every(p => Number(p.qtd) === 0));
  ok('produtos vêm SEM preço', prods.every(p => Number(p.custo) === 0));

  const dash = await get(dono.token, '/api/dashboard');
  ok('dashboard abre sem erro', dash.status === 200);
  console.log(`       ${dash.body.lancHoje} lançamentos hoje · ${dash.body.zerados} zerados (esperado: tudo zerado no 1º dia)`);

  const idx = await get(dono.token, '/api/indices?mes=2026-07');
  ok('índices abrem zerados', idx.status === 200 && Number(idx.body.vendas_mes) === 0, `venda ${idx.body?.vendas_mes}`);

  console.log('\n=== 3. O dado dele não encosta no do Toca ===');
  const toca = (await post(null, '/api/login', { username: 'rubens', password: 'teste123' })).body;
  const idxToca = await get(toca.token, '/api/indices?mes=2026-07');
  ok('Toca continua vendo o faturamento dele', Number(idxToca.body.vendas_mes) > 100000,
    `R$ ${Number(idxToca.body.vendas_mes).toLocaleString('pt-BR')}`);
  ok('Pizzaria não vê faturamento nenhum', Number(idx.body.vendas_mes) === 0);

  // o dono mexe no catálogo dele — não pode respingar no Toca
  const alvo = prods[0];
  await post(dono.token, '/api/movimentacoes', { produto_id: alvo.id, tipo: 'Entrada', qtd: 10, motivo: 'Compra' });
  const depoisPizza = await get(dono.token, '/api/produtos');
  const listaP = Array.isArray(depoisPizza.body) ? depoisPizza.body : [];
  const naPizza = listaP.find(p => p.id === alvo.id);
  ok('entrada do dono altera o estoque DELE', Number(naPizza?.qtd) === 10, `qtd ${naPizza?.qtd}`);

  const noToca = await get(toca.token, '/api/produtos');
  const listaT = Array.isArray(noToca.body) ? noToca.body : [];
  const mesmoNoToca = listaT.find(p => p.nome === alvo.nome);
  ok('o produto de mesmo nome no Toca NÃO foi afetado',
    !mesmoNoToca || Number(mesmoNoToca.qtd) !== 10, `qtd no Toca: ${mesmoNoToca?.qtd ?? 'não existe'}`);

  console.log(falhas ? `\n${falhas} FALHA(S)` : '\nOnboarding funcionando: 13/13.');
  console.log(`\n(restaurante de teste criado: slug "${slug}" — dá pra entrar com dono." + slug + " / pizza123)`);
  process.exit(falhas ? 1 : 0);
})().catch(e => { console.error('ERRO:', e.message); process.exit(1); });
