# Testes do Toca Estoque

## O que tem aqui

| Arquivo | O que testa |
|---|---|
| `estoque-integridade.test.js` | Cancelamento duplo (F1), saldo × histórico com falha (F2), reenvio do mesmo evento (F3) e dois controles que nunca podem quebrar |
| `relatorios-conferencias.test.js` | Falso aviso do delivery (F4), "sumiço" de inventário (F8), auditoria com mais de 1.000 linhas (F9), data da compra retroativa (R2), "1.500" virando 1,50 |
| `ambiente/ambiente.js` | Sobe um **banco descartável**: Postgres 17 local + PostgREST 16 (o motor REST do Supabase) |
| `ambiente/app-teste.js` | Carrega o **app real** (`server.js`) contra esse banco, com um restaurante e três usuários logados |
| `ambiente/schema-producao.sql` | Estrutura (sem dados) das 25 tabelas que o app usa, lida da produção em 03/10/2026 |
| `helpers/extrair-funcao.js` | Testa uma função pura pelo **nome**, sem carregar o app |

Os testes exigem o **resultado correto**. Enquanto um defeito não for corrigido, o teste dele falha de propósito. Os testes marcados "CONTROLE" devem passar sempre.

## Segurança

- Nada aqui conecta à produção. O banco nasce vazio, a partir da estrutura, e é apagado no fim.
- O app sobe com `NODE_ENV=test`: os temporizadores (backup das 18h, limpeza de sessões) e o servidor HTTP não são ligados.
- Sem chamadas de IA: nenhuma chave de API é usada.
- `npm run test:e2e` (Playwright) **não aponta mais para produção**: exige `E2E_BASE_URL`, e recusa a produção sem `E2E_PERMITIR_PRODUCAO=1`.

## Preparar (uma vez por máquina)

1. `npm install` (instala `embedded-postgres` e `pg`, só para desenvolvimento).
2. Baixe o PostgREST oficial para `test/.ambiente/bin/` (pasta ignorada pelo git):
   - Windows: `postgrest-v16.4-windows-x86-64.zip` em https://github.com/PostgREST/postgrest/releases/tag/v16.4 e extraia `postgrest.exe`.
   - SHA-256 do `postgrest.exe` usado em 03/10/2026: `c4155000dfb0befb59215b65d61a621bbaea1515f36a6e758fc504c7ca0dcbee`.

## Rodar

```
npm test
```

Cada arquivo sobe o próprio banco (alguns segundos). No Windows o PostgREST às vezes aborta ao iniciar (código 3); o ambiente descarta a instância e sobe outra sozinho, até 3 vezes.

## Observações

- O banco local é criado em UTF-8, como a produção (o padrão do Windows recusa o emoji que o app grava em lançamentos retroativos).
- O PostgREST local corta cada consulta em 1.000 linhas, como o Supabase.
- Ficaram de fora da estrutura, de propósito, os triggers da produção `trg_produtos_updated` e `trg_brain_captura` (o Brain lê movimentações).
