<!-- Generated: 2026-07-11 | Files scanned: package.json, server.js (integrações), playwright.config.js | Token estimate: ~350 -->

# Dependências e Integrações Externas

## NPM (produção)
- `express` ^4.21.2 — servidor HTTP + rotas
- `@supabase/supabase-js` ^2.49.4 — cliente do banco (Postgres gerenciado)
- `cors` — CORS aberto (`origin: ALLOWED_ORIGIN || true` — sem env var, aceita qualquer origem;
  risco baixo pq auth é Bearer token, não cookie, mas configurável via Railway env)
- `express-rate-limit` — 3 limiters: login (20/15min/IP), chat (10/min/user), webhook (30/min)

## NPM (dev)
- `@playwright/test` ^1.61.1 — suíte E2E (`tests/app.spec.js`, 21 testes contra produção)

## Serviços externos
| Serviço | Uso | Onde |
|---|---|---|
| **Supabase** (Postgres) | Banco principal, compartilhado com outros apps do restaurante | todo o server.js |
| **Anthropic (Claude)** | Chat IA (`/api/chat`), leitura de nota fiscal/comprovante por foto | `/api/chat`, `/api/ler-cupom`, `/api/webhook/ler-nota` |
| **n8n** (Railway) | Cron do relatório diário automático + bot WhatsApp aciona `/api/webhook/whatsapp` | `WEBHOOK_SECRET` header |
| **WhatsApp** (via n8n/Evolution) | Comandos de consulta/lançamento por mensagem | `POST /api/webhook/whatsapp` |
| **Railway** | Hosting (nixpacks, `npm start`) | `railway.toml` |

## Segredos (env vars, Railway)
- `WEBHOOK_SECRET` — valida `x-webhook-secret` nos webhooks (sem fallback hardcoded, já corrigido
  em sessão anterior — antes tinha um valor fixo exposto no histórico do git)
- `SUPABASE_URL` / chave de serviço — acesso ao banco
- `ALLOWED_ORIGIN` — opcional, restringe CORS

## Robô de testes (QA)
- Conta dedicada `robo.teste` (gerente) + `robo.teste.operador` — nunca usam contas reais
- Produtos fictícios isolados: `ROBO TESTE`, `ROBO TESTE ANOMALIA`, `ROBO TESTE 2` (categoria
  `QA Robo (teste)`) — nunca tocam no estoque real
- Login com cache de sessão (token salvo, reaproveitado via `localStorage`) — evita bater no
  rate limiter de login rodando a suíte inteira

Ver também: [[architecture]] [[backend]]
