// Tenta quebrar o cadastro de restaurante de todas as formas que eu consegui imaginar.
// Objetivo: nenhum cadastro torto entra e estraga o fluxo do cliente depois.
const API = 'http://localhost:3002';
const req = async (m, url, t, body) => {
  const r = await fetch(API + url, {
    method: m, headers: { 'Content-Type': 'application/json', ...(t ? { Authorization: 'Bearer ' + t } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
};
let f = 0, n = 0;
const ok = (nome, c, e = '') => { n++; if (!c) f++; console.log((c ? '  ok     ' : '  FALHOU ') + nome + (e ? '  → ' + e : '')); };

(async () => {
  const sup = (await req('POST', '/api/login', null, { username: 'plataforma', password: 'super123' })).body;
  const base = { nome: 'Restaurante Bom', slug: 'valido-' + Date.now().toString(36), admin_usuario: 'user' + Date.now().toString(36), admin_senha: 'senhaBoa123', plano: 'completo' };
  const tentar = (patch) => req('POST', '/api/plataforma/restaurantes', sup.token, { ...base, ...patch });
  const criados = [];

  console.log('\n── Cadastro torto é barrado ──');
  const casos = [
    ['nome com 2 letras', { nome: 'AB' }],
    ['identificador com espaço', { slug: 'meu restaurante' }],
    ['identificador com acento', { slug: 'café-central' }],
    ['identificador curto demais', { slug: 'ab' }],
    ['identificador reservado (admin)', { slug: 'admin' }],
    ['usuário reservado (suporte)', { admin_usuario: 'suporte' }],
    ['usuário com espaço', { admin_usuario: 'dono da casa' }],
    ['senha curta', { admin_senha: 'abc123' }],
    ['senha só de letras', { admin_senha: 'senhasenha' }],
    ['senha só de números', { admin_senha: '123456789' }],
    ['senha óbvia', { admin_senha: 'senha123456' }],
    ['CNPJ com dígito errado', { cnpj: '11.222.333/0001-44' }],
    ['CNPJ todo zero', { cnpj: '00.000.000/0000-00' }],
    ['plano inexistente', { plano: 'ouro' }],
  ];
  for (const [desc, patch] of casos) {
    const r = await tentar(patch);
    ok(desc, r.status === 400, r.status === 200 ? 'PASSOU (não devia)' : (r.body?.erro || '').slice(0, 60));
    if (r.status === 200) criados.push(r.body.restaurante.id);
  }

  console.log('\n── Normalização (não é erro — é gentileza com quem digita) ──');
  const suf = Date.now().toString(36);
  const maiusc = await tentar({ slug: 'Cantina-' + suf, admin_usuario: 'mai' + suf });
  ok('MAIÚSCULA no identificador é normalizada, não recusada', maiusc.status === 200, maiusc.body?.erro || '');
  ok('e é gravada em minúscula', /^cantina-/.test(maiusc.body?.restaurante?.slug || ''), maiusc.body?.restaurante?.slug || '');
  if (maiusc.status === 200) criados.push(maiusc.body.restaurante.id);

  console.log('\n── Cadastro correto entra ──');
  const bom = await tentar({ cnpj: '11.222.333/0001-81' });   // CNPJ fictício válido no mod-11
  ok('cadastro válido é aceito', bom.status === 200, bom.body?.erro || '');
  if (bom.status === 200) criados.push(bom.body.restaurante.id);
  ok('CNPJ válido é aceito', bom.status === 200);

  console.log('\n── Nada fica pela metade ──');
  const dup = await tentar({ slug: base.slug + '-x' });  // mesmo usuário do anterior
  ok('usuário repetido é barrado', dup.status === 400, (dup.body?.erro || '').slice(0, 70));
  const lista = await req('GET', '/api/plataforma/restaurantes', sup.token);
  ok('nenhum restaurante órfão ficou no banco',
    !(lista.body.restaurantes || []).some(r => r.slug === base.slug + '-x'));

  console.log('\n── Checagem de disponibilidade ──');
  const d1 = await req('GET', `/api/plataforma/disponivel?slug=${base.slug}`, sup.token);
  ok('slug já usado aparece como ocupado', d1.body?.slug?.livre === false);
  const d2 = await req('GET', '/api/plataforma/disponivel?slug=totalmente-livre-xyz', sup.token);
  ok('slug novo aparece como livre', d2.body?.slug?.livre === true);
  const d3 = await req('GET', '/api/plataforma/disponivel?slug=admin', sup.token);
  ok('slug reservado aparece como ocupado', d3.body?.slug?.livre === false);

  console.log('\n── O restaurante criado funciona de verdade ──');
  const dono = (await req('POST', '/api/login', null, { username: base.admin_usuario, password: base.admin_senha })).body;
  ok('dono entra', !!dono.token);
  for (const [rot, url] of [['estoque', '/api/produtos'], ['dashboard', '/api/dashboard'],
                            ['planilha', '/api/planilha-mensal?mes=2026-08'], ['índices', '/api/indices?mes=2026-08'],
                            ['contas', '/api/pagamentos?mes=2026-08'], ['comparar', '/api/comparar?inicio=2026-08-01&fim=2026-08-02'],
                            ['dia', '/api/realidade-dia?data=2026-08-02']]) {
    const r = await req('GET', url, dono.token);
    ok(`${rot} abre sem erro`, r.status === 200, `HTTP ${r.status}`);
  }

  // limpeza
  for (const id of criados) await req('POST', `/api/plataforma/restaurantes/${id}/status`, sup.token, { ativo: false });
  console.log(`\n${n - f}/${n} verificações passaram.`);
  process.exit(f ? 1 : 0);
})().catch(e => { console.error('ERRO:', e.message); process.exit(1); });
