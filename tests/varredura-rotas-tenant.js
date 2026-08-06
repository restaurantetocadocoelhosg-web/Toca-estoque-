// Varre TODAS as rotas GET do app no ambiente multi-restaurante para descobrir
// o que ainda não funciona. Só leitura — não altera nada.
const fs = require('fs');
const API = 'http://localhost:3002';
const src = fs.readFileSync('C:/Users/User/.local/bin/toca-estoque-fix/server.js', 'utf8');

// extrai as rotas GET declaradas no servidor
const rotas = [...src.matchAll(/app\.get\('(\/api\/[^']+)'/g)].map(m => m[1])
  .filter(r => !r.includes(':'))            // rotas com parâmetro precisam de id real
  .filter((r, i, a) => a.indexOf(r) === i);

const params = {
  '/api/planilha-mensal': '?mes=2026-07', '/api/indices': '?mes=2026-07',
  '/api/pagamentos': '?mes=2026-07', '/api/comparar': '?inicio=2026-07-01&fim=2026-07-15',
  '/api/relatorios/periodo': '?inicio=2026-07-01&fim=2026-07-15',
  '/api/realidade-dia': '?data=2026-07-15', '/api/movimentacoes': '?limit=5',
  '/api/produtos/buscar': '?q=arroz', '/api/exportar/fechamentos': '?mes=2026-07',
  '/api/relatorio/fechamento': '?mes=2026-07',
};

(async () => {
  const login = async (u, p) => (await (await fetch(API + '/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p }),
  })).json());
  const toca = await login('rubens', 'teste123');

  const okList = [], quebradas = [], protegidas = [];
  for (const rota of rotas) {
    const url = API + rota + (params[rota] || '');
    try {
      const r = await fetch(url, { headers: { Authorization: 'Bearer ' + toca.token } });
      const txt = await r.text();
      let corpo = null; try { corpo = JSON.parse(txt); } catch (_) {}
      if (r.status === 200) okList.push(rota);
      else if (r.status === 403) protegidas.push(`${rota} (${corpo?.erro || 403})`);
      else quebradas.push(`${rota} → HTTP ${r.status} ${corpo?.erro || txt.slice(0, 80)}`);
    } catch (e) { quebradas.push(`${rota} → ${e.message}`); }
  }

  console.log(`\n✅ FUNCIONANDO no multi-restaurante (${okList.length})`);
  okList.forEach(r => console.log('   ' + r));
  if (protegidas.length) {
    console.log(`\n🔒 BLOQUEADAS DE PROPÓSITO (${protegidas.length})`);
    protegidas.forEach(r => console.log('   ' + r));
  }
  if (quebradas.length) {
    console.log(`\n❌ PRECISAM DE ATENÇÃO (${quebradas.length})`);
    quebradas.forEach(r => console.log('   ' + r));
  } else console.log('\n(nenhuma rota GET quebrada)');
})().catch(e => console.error('ERRO:', e.message));
