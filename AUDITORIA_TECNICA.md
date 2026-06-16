# AUDITORIA TÉCNICA — Toca do Coelho (Sistema de Estoque)

Data: 2026-06-16
Versão analisada: 2.1.0
Branch: `claude/code-review-improvements-8bkv3l`

## Mapa do projeto

| Camada | Arquivo | Observações |
|---|---|---|
| Backend | `server.js` (~2.680 linhas) | Express + Supabase (PostgreSQL). Arquivo único. |
| Frontend | `public/index.html` (~3.280 linhas) | HTML/CSS/JS puro, PWA com `manifest.json` e `public/sw.js`. |
| Dados | Supabase (PostgreSQL) | **Não é SQLite** como descrito no pedido — a base é Supabase. |
| Seed | `produtos_seed.json` | 259 produtos iniciais. |
| Deploy | `railway.toml` | Railway + nixpacks. |

### Tabelas Supabase usadas
`users`, `sessions`, `produtos`, `categorias`, `movimentacoes`, `audit_logs`,
`backups_estoque`, `inventarios` / itens, `sinonimos`, `ia_agenda`, `snapshots_diarios`.

### Módulos / rotas principais
- **Auth**: login, logout, me, change-password (scrypt + sessão por token, idle 60 min).
- **Produtos**: CRUD, busca acento-insensível, histórico, resumo, arquivar.
- **Movimentações**: Entrada / Saída / Perda / Ajuste com trava otimista de concorrência.
- **Inventário**: abrir, contar, fechar, histórico, ajuste com auditoria.
- **Categorias / Grupos de troca / Sinônimos (apelidos)**.
- **Backup**: manual, automático, restauração (admin).
- **Auditoria**: trilha (`audit_logs`) + detecção de divergências.
- **IA**: leitura de cupom/nota fiscal, chat com ferramentas.
- **Integrações**: webhook WhatsApp (consulta + lançamentos), relatório diário.

---

## Pontos fortes já existentes (preservados)

O sistema já está bem acima da média para o porte. Não foram tocados:
- **Trava otimista de concorrência** nas movimentações (`update ... eq('qtd', valorAntigo)` com retry) — evita que duas baixas simultâneas se sobrescrevam.
- **Detecção de anomalia** (saída muito acima da média) exigindo confirmação do gerente.
- **Trava de ajuste com movimento recente** — evita que uma contagem antiga apague lançamentos da noite.
- **Senhas com scrypt + salt aleatório + `timingSafeEqual`**.
- **Saldo recalculado no backend** (não confia no frontend); registro de `qtd_antes`/`qtd_depois`.
- **Rate limit no login** (20/15 min) e sessão com expiração por inatividade.

---

## Achados e correções

Legenda de status: ✅ corrigido nesta auditoria · 🟡 documentado / decisão humana · ⛔ não alterado (risco/escopo).

### CRÍTICA

| # | Problema | Arquivo | Risco para a empresa | Correção | Status |
|---|---|---|---|---|---|
| C1 | Endpoint `POST /api/movimentacoes` não verificava a permissão `lancar` no backend (só o frontend escondia o botão). Um usuário com `lancar=false` podia mover estoque chamando a API direto. | `server.js` | Lançamentos por quem teve a permissão revogada. | Adicionado `requirePerm('lancar')`. | ✅ |

### ALTA

| # | Problema | Arquivo | Risco | Correção | Status |
|---|---|---|---|---|---|
| A1 | Erros assíncronos não tratados (Supabase fora do ar, JSON malformado) deixavam a requisição pendurada ou vazavam stack trace HTML para o usuário. | `server.js` | Travamentos, vazamento técnico, instabilidade. | Tratador central de erros + `unhandledRejection`/`uncaughtException` + respostas genéricas. | ✅ |
| A2 | `WEBHOOK_SECRET` com valor padrão público (`toca-webhook-2026`) quando a variável de ambiente não está definida. | `server.js` | Qualquer um que saiba o padrão pode mover estoque via webhook. | Mantido o padrão (para não quebrar a integração ativa) + **aviso forte na inicialização**. **Definir `WEBHOOK_SECRET` no Railway.** | 🟡 |
| A3 | Exclusão de movimentação (`DELETE /api/movimentacoes/:id`) apaga fisicamente o registro do histórico. | `server.js` | Perda de trilha de auditoria; conflito com a regra "não apagar movimentação concluída / gerar estorno". | Requer mudança de modelo (soft-delete/estorno). Documentado. | 🟡 |

### MÉDIA

| # | Problema | Arquivo | Risco | Correção | Status |
|---|---|---|---|---|---|
| M1 | Movimentações via WhatsApp não gravavam `qtd_antes`/`qtd_depois` (a tela grava). A reconstrução cronológica da auditoria ficava com lacunas para lançamentos do WhatsApp. | `server.js` | Divergências/falsos positivos na auditoria de integrações. | Passou a gravar `qtd_antes`/`qtd_depois`. | ✅ |
| M2 | `verifyPassword` usava `timingSafeEqual` sem checar tamanho dos buffers — hash corrompido lançava exceção não tratada no login. | `server.js` | Login podia quebrar com 500 em vez de "senha inválida". | Guard de tamanho antes do compare. | ✅ |
| M3 | Sem cabeçalhos de segurança (clickjacking, MIME sniffing). | `server.js` | Exposição a clickjacking/sniffing. | Middleware com `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` (sem dependência nova). | ✅ |
| M4 | Sem endpoint de verificação de saúde / conexão com o banco. | `server.js` | Sem monitoramento de uptime/deploy. | Adicionado `GET /api/health`. | ✅ |
| M5 | Sem idempotência server-side: clique-duplo é barrado no frontend (botão desabilitado), mas reenvio de rede / dois dispositivos podem duplicar. | `server.js` / `index.html` | Movimentação duplicada em caso de retry de rede. | Mitigado parcialmente pela trava otimista. Idempotência por chave de operação fica como melhoria. | 🟡 |

### BAIXA

| # | Problema | Arquivo | Risco | Correção | Status |
|---|---|---|---|---|---|
| B1 | `CORS origin: true` reflete qualquer origem. Autenticação é por header `Authorization` (não cookie), então o risco de CSRF é baixo, mas é permissivo. | `server.js` | Baixo (sem cookies de sessão). | Restringir via `ALLOWED_ORIGIN` em produção. | 🟡 |
| B2 | `<meta viewport ... maximum-scale=1.0>` bloqueia o zoom no celular (acessibilidade). | `index.html` | Acessibilidade. | Remover `maximum-scale` (não alterado para não mexer no layout sem teste visual). | 🟡 |
| B3 | Valores monetários trafegam como `float` com `toFixed(2)`. Depende do tipo da coluna no Postgres (idealmente `numeric`). | `server.js` / DB | Arredondamento em somas grandes. | Verificar tipos das colunas no Supabase (decisão de schema). | 🟡 |

---

## Itens que exigem decisão humana

1. **Definir `WEBHOOK_SECRET`** (e idealmente `ADMIN_PASSWORD`, `ALLOWED_ORIGIN`) como variáveis de ambiente no Railway. (A2/B1)
2. **Política de exclusão de movimentação** (A3): manter exclusão física ou migrar para estorno/soft-delete? Afeta relatórios e auditoria.
3. **Tipos de coluna monetária** no Supabase (B3) — requer acesso ao schema do banco.
4. **Trocar senhas iniciais de seed** que ainda usam fallback no código (`seed()`), via variáveis de ambiente.

## Verificação

- `node --check server.js` → OK.
- Teste de fumaça (servidor com Supabase stub): boot OK, `/api/health` → 200,
  cabeçalhos de segurança presentes, JSON malformado → 400 limpo (sem stack trace),
  rota protegida sem token → 401. Detalhes em `ALTERACOES_REALIZADAS.md`.
