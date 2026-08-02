// O que o dono do restaurante PODE e NÃO PODE mexer.
const API = 'http://localhost:3002';
const req = async (m, url, t, body) => {
  const r = await fetch(API + url, {
    method: m, headers: { 'Content-Type': 'application/json', ...(t ? { Authorization: 'Bearer ' + t } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
};
const login = async (u, p) => (await req('POST', '/api/login', null, { username: u, password: p })).body;
let f = 0, n = 0;
const ok = (nome, c, e = '') => { n++; if (!c) f++; console.log((c ? '  ok     ' : '  FALHOU ') + nome + (e ? '  → ' + e : '')); };

(async () => {
  const dono = await login('rubens', 'teste123');
  const sup = await login('plataforma', 'super123');

  console.log('\n── O dono NÃO mexe no que muda o relatório ──');
  const criarCat = await req('POST', '/api/categorias', dono.token, { nome: 'Categoria Inventada' });
  ok('não cria categoria', criarCat.status === 403, `HTTP ${criarCat.status}`);
  ok('erro explica o porquê', /estrutura do relat/i.test(criarCat.body?.erro || ''), criarCat.body?.erro || '');
  const renomear = await req('PUT', '/api/categorias/renomear', dono.token, { de: 'Hortifruti', para: 'Verduras' });
  ok('não renomeia categoria', renomear.status === 403);
  const apagar = await req('DELETE', '/api/categorias/Pescados', dono.token);
  ok('não apaga categoria', apagar.status === 403);

  console.log('\n── O dono MEXE no que é dele ──');
  const meu = await req('GET', '/api/restaurante', dono.token);
  ok('vê os dados do restaurante dele', meu.status === 200 && !!meu.body?.restaurante);
  ok('é marcado como quem pode editar', meu.body?.pode_editar === true);

  const salvar = await req('PUT', '/api/restaurante', dono.token, {
    telefone: '21 99999-0000', taxas: { credito: '3,10', debito: '1,80' },
  });
  ok('salva telefone e taxas dele', salvar.status === 200, salvar.body?.erro || '');
  ok('taxa aceita vírgula e vira número', salvar.body?.config?.taxas?.credito === 3.1, `${salvar.body?.config?.taxas?.credito}`);
  ok('taxa não informada é preservada', salvar.body?.config?.taxas?.voucher === 3.99, `${salvar.body?.config?.taxas?.voucher}`);

  const absurda = await req('PUT', '/api/restaurante', dono.token, { taxas: { credito: '150' } });
  ok('taxa absurda é recusada antes de virar custo errado', absurda.status === 400, absurda.body?.erro || '');
  const conf = await req('GET', '/api/restaurante', dono.token);
  ok('a taxa boa continua salva depois da recusa', conf.body?.restaurante?.config?.taxas?.credito === 3.1);

  console.log('\n── Um restaurante não configura o outro ──');
  const outro = await req('GET', '/api/restaurante', sup.token);
  ok('superadmin sem restaurante escolhido não pega config de ninguém', outro.status === 404 || outro.status === 400,
    `HTTP ${outro.status}`);

  console.log('\n── A taxa configurada é a que vale no fechamento ──');
  const fech = await req('POST', '/api/realidade-dia', dono.token, {
    data: '2026-01-07', pratos_vendidos: 5,
    pagamentos: [{ descricao: 'CRED PAG BANK:', valor: 1000 }],
    despesas: [],
  });
  ok('fechamento de teste salvo', fech.status === 200, fech.body?.erro || '');
  const pag = await req('GET', '/api/pagamentos?mes=2026-01', dono.token);
  const taxa = (pag.body?.pagamentos || []).find(p => p.forma === 'taxa_operadora');
  ok('taxa lançada usa os 3,10% DELE, não os 2,71% padrão', Number(taxa?.valor_bruto) === 31,
    `R$ ${taxa?.valor_bruto} — ${taxa?.descricao || ''}`);
  await req('DELETE', '/api/realidade-dia?data=2026-01-07', dono.token);

  // devolve a taxa original pra não sujar o ambiente
  await req('PUT', '/api/restaurante', dono.token, { taxas: { credito: '2,71', debito: '1,75' } });

  console.log(`\n${n - f}/${n} verificações passaram.`);
  process.exit(f ? 1 : 0);
})().catch(e => { console.error('ERRO:', e.message); process.exit(1); });
