// REVISÃO COMPLETA do ambiente multi-restaurante, antes de pensar em subir.
// Roda contra o servidor local (3002) no schema isolado. Produção não é tocada.
const API = 'http://localhost:3002';
const req = async (m, url, t, body) => {
  const r = await fetch(API + url, {
    method: m,
    headers: { 'Content-Type': 'application/json', ...(t ? { Authorization: 'Bearer ' + t } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
};
const login = async (u, p) => (await req('POST', '/api/login', null, { username: u, password: p })).body;

let f = 0, n = 0;
const ok = (nome, cond, extra = '') => { n++; if (!cond) f++; console.log((cond ? '  ok     ' : '  FALHOU ') + nome + (extra ? '  → ' + extra : '')); };
const secao = t => console.log(`\n── ${t} ──`);

(async () => {
  const slug = 'rev-' + Date.now().toString(36);
  const userDono = 'dono.' + slug;

  secao('1. Papéis: cada um enxerga a sua área');
  const sup = await login('plataforma', 'super123');
  ok('superadmin entra', !!sup.token);
  ok('superadmin tem papel próprio', sup.user.role === 'superadmin');
  const meSup = await req('GET', '/api/me', sup.token);
  ok('superadmin NÃO recebe permissões do app do cliente',
    meSup.body?.permissoes && Object.values(meSup.body.permissoes).every(v => v === false),
    JSON.stringify(meSup.body?.permissoes?.planilha));

  const toca = await login('rubens', 'teste123');
  const meToca = await req('GET', '/api/me', toca.token);
  ok('dono de restaurante recebe as permissões do app', meToca.body?.permissoes?.planilha === true);
  ok('dono de restaurante NÃO é superadmin', meToca.body?.user?.role === 'admin');

  secao('2. Cliente não alcança a área da plataforma');
  const tentaListar = await req('GET', '/api/plataforma/restaurantes', toca.token);
  ok('cliente é barrado ao listar restaurantes', tentaListar.status === 403, `HTTP ${tentaListar.status}`);
  const tentaCriar = await req('POST', '/api/plataforma/restaurantes', toca.token,
    { nome: 'Invasao', slug: 'invasao', admin_usuario: 'x', admin_senha: '123456' });
  ok('cliente é barrado ao criar restaurante', tentaCriar.status === 403, `HTTP ${tentaCriar.status}`);
  const tentaSuspender = await req('POST', '/api/plataforma/restaurantes/3/status', toca.token, { ativo: false });
  ok('cliente é barrado ao suspender restaurante', tentaSuspender.status === 403);

  secao('3. Abrir restaurante já pronto pra usar');
  const criado = await req('POST', '/api/plataforma/restaurantes', sup.token, {
    nome: 'Restaurante Revisao', slug, plano: 'completo',
    admin_usuario: userDono, admin_senha: 'rev12345', admin_nome: 'Dono Revisao',
  });
  ok('restaurante criado', criado.status === 200, criado.body?.erro || '');
  ok('veio com categorias', criado.body?.preparado?.categorias >= 15, `${criado.body?.preparado?.categorias}`);
  ok('veio com catálogo', criado.body?.preparado?.produtos >= 280, `${criado.body?.preparado?.produtos}`);

  const dupe = await req('POST', '/api/plataforma/restaurantes', sup.token, {
    nome: 'Outro', slug: slug + '-2', admin_usuario: userDono, admin_senha: 'rev12345',
  });
  ok('usuário repetido é recusado com mensagem clara', dupe.status === 400 && /já existe/i.test(dupe.body?.erro || ''),
    dupe.body?.erro || '');
  const lista = await req('GET', '/api/plataforma/restaurantes', sup.token);
  ok('restaurante órfão NÃO ficou no banco após a recusa',
    !(lista.body.restaurantes || []).some(r => r.slug === slug + '-2'));

  secao('4. Painel de saúde');
  const painel = lista.body.restaurantes || [];
  ok('painel lista os restaurantes', painel.length >= 3, `${painel.length}`);
  const oToca = painel.find(r => r.slug === 'toca-do-coelho');
  ok('mostra aderência de lançamento', typeof oToca?.aderencia === 'number', `${oToca?.aderencia}%`);
  ok('classifica a saúde', ['ok', 'atencao', 'risco'].includes(oToca?.saude), oToca?.saude);

  secao('5. O novo dono usa o app dele');
  const dono = await login(userDono, 'rev12345');
  ok('dono entra', !!dono.token);
  const prod = await req('GET', '/api/produtos', dono.token);
  const lst = Array.isArray(prod.body) ? prod.body : [];
  ok('estoque já vem preenchido', lst.length >= 280, `${lst.length} produtos`);
  ok('tudo zerado no primeiro dia', lst.every(p => Number(p.qtd) === 0));

  const mov = await req('POST', '/api/movimentacoes', dono.token,
    { produto_id: lst[0].id, tipo: 'Entrada', qtd: 7, motivo: 'Compra' });
  ok('dono consegue lançar no estoque dele', mov.status === 200, `HTTP ${mov.status}`);

  const cmp = await req('GET', '/api/comparar?inicio=2026-07-01&fim=2026-07-15', dono.token);
  ok('comparador abre para o cliente novo', cmp.status === 200);
  ok('comparador do cliente novo vem zerado', Number(cmp.body?.linhas?.find(l => l.chave === 'vendas')?.atual || 0) === 0);

  secao('6. Isolamento sob as telas novas');
  const idxDono = await req('GET', '/api/indices?mes=2026-07', dono.token);
  const idxToca = await req('GET', '/api/indices?mes=2026-07', toca.token);
  ok('índices do cliente novo: zerado', Number(idxDono.body.vendas_mes) === 0);
  ok('índices do Toca: intactos', Number(idxToca.body.vendas_mes) > 100000,
    `R$ ${Number(idxToca.body.vendas_mes).toLocaleString('pt-BR')}`);
  const cmpToca = await req('GET', '/api/comparar?inicio=2026-07-16&fim=2026-07-29', toca.token);
  ok('comparador do Toca traz os dados dele', Number(cmpToca.body?.linhas?.find(l => l.chave === 'vendas')?.atual) > 0);

  secao('7. Suspender corta o acesso? (regra de negócio)');
  const idNovo = criado.body.restaurante.id;
  await req('POST', `/api/plataforma/restaurantes/${idNovo}/status`, sup.token, { ativo: false });
  const listaDepois = await req('GET', '/api/plataforma/restaurantes', sup.token);
  const suspenso = (listaDepois.body.restaurantes || []).find(r => r.id === idNovo);
  ok('restaurante fica marcado como suspenso', suspenso && suspenso.ativo === false);
  const tentaEntrar = await req('POST', '/api/login', null, { username: userDono, password: 'rev12345' });
  ok('suspenso NÃO consegue entrar', tentaEntrar.status === 403, `HTTP ${tentaEntrar.status}`);
  ok('mensagem explica o motivo real', /suspens/i.test(tentaEntrar.body?.erro || ''), tentaEntrar.body?.erro || '');
  await req('POST', `/api/plataforma/restaurantes/${idNovo}/status`, sup.token, { ativo: true });
  const voltou = await login(userDono, 'rev12345');
  ok('reativar devolve o acesso', !!voltou.token);

  console.log(`\n${n - f}/${n} verificações passaram.`);
  console.log(`(restaurante de revisão: ${slug} · usuário ${userDono} / rev12345)`);
  process.exit(f ? 1 : 0);
})().catch(e => { console.error('ERRO:', e.message); process.exit(1); });
