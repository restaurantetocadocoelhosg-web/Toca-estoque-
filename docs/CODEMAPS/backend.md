<!-- Generated: 2026-07-11 | Files scanned: server.js (4.615 linhas) | Token estimate: ~950 -->

# Backend — server.js

Express monolítico. Sem pastas `routes/`/`controllers/` — tudo num arquivo só, organizado por
blocos `// ==================== SEÇÃO ====================`.

## Middlewares principais
- `auth` — valida token Bearer, popula `req.user` (id, nome, role, permissoes)
- `requireRole(...roles)` — bloqueia por papel (admin/gerente/operador)
- `requirePerm(chave)` — bloqueia por permissão fina (`dia`, `planilha`, `contas`, `ia`, `lancar`,
  `pendencias`, `exportar`) — ver `permsPorRole()`/`permsEfetivas()`
- `loginLimiter` (20/15min por IP), `chatLimiter` (10/min por user), `webhookLimiter` (30/min)

## Rotas por área

### Auth (349-407)
`POST /login` `POST /logout` `GET/PUT /me` `POST /change-password`

### Produtos (408-659)
`GET /produtos` (lista + filtro cat/status/q — **q consulta sinônimos primeiro, depois nome/código**)
`GET /produtos/buscar` (autocomplete do Lançar — mesmo padrão apelido-primeiro)
`GET/POST/PUT /categorias` `GET/POST/DELETE /grupos` (grupo de troca/substituto)
`POST/PUT /produtos` `PUT /produtos/:id/arquivar` `GET /produtos/:id/historico|resumo`

### Movimentações (660-860) — núcleo do sistema
`POST /movimentacoes` — valida produto, checa **Ajuste recente** (409 se >6h) e **anomalia**
(saída/perda 3x média 30d → 409 bloqueia operador SEM bypass, gerente/admin só anota obs) →
**trava otimista** (update com `.eq('qtd', qtdEsperada)`, retry 4x) → grava produto+movimentação
`DELETE /movimentacoes/:id` (cancela, estorna estoque, mesma trava otimista)
`GET /movimentacoes` (histórico, busca por produto_nome/motivo/obs/responsavel)
`GET /dashboard` (cards zerados/críticos/valor — filtra `ativo` corretamente)

### Realidade do Dia / Planilha Mensal (2256-2399)
`GET/POST/DELETE /realidade-dia` `POST /realidade-dia/mover`
`GET /planilha-mensal` (agrega dias do mês — `montarPlanilhaMensal()`)
`GET /relatorios/periodo`

### Pagamentos/Contas (2400-2490)
CRUD `/pagamentos` + `POST /pagamentos/ler-comprovante` (IA lê foto do comprovante)

### Exportação/Relatórios (2491-2894)
`GET /exportar/:tipo` (CSV: estoque|movimentacoes|compras|fechamentos)
`GET /relatorio/:tipo` (HTML formatado: estoque|compras)
`POST /resetar` (admin, restaura seed — usa TODOS produtos incl. arquivados, intencional)

### Nota Fiscal / Pendências (2895-3120)
`POST /ler-cupom` (app) `POST /webhook/ler-nota` (WhatsApp) — IA lê foto, cria movimentação
automática se match confiável, senão vai pra `nota_pendencias`
`GET /pendencias` `POST /pendencias/:id/resolver|criar-produto|ignorar`

### Chat IA (3528-3649)
`POST /chat` — ferramentas: buscar_produto, registrar_movimentacao, ver_historico, ver_dashboard,
ver_inventarios. Usa `buscarProdutos()` (matcher código→apelido→nome_exato→parcial).

### Alertas (3650-3821)
`GET /alertas/estoque-parado` (produto sem movimento > threshold por categoria, considera
grupo_troca) `GET/POST /alertas/fantasmas` (zerados suspeitos de dessincronia)

### Inventário (3822-4026)
`POST /inventario/abrir|contar|fechar` `GET /inventario/aberto|historico|:id`
`PUT /inventario/item/:id` — fechar aplica contagem como Ajuste rastreável (obs='inventario')

### Admin: Users/Sinônimos/Manutenção/Auditoria/Backup (4027-4265)
`GET/POST/PUT /users` `GET/POST/DELETE /sinonimos` (+ `/importar`)
`GET /manutencao/normalizar` `GET /auditoria/divergencias` (reconstrução cronológica de saldo)
`POST /backup` `GET /backups` `POST /backup/:id/restaurar`

### Webhooks externos (4266-4604)
`POST /webhook/whatsapp` (secret via header) — ações: consultar/resumo/zerados/criticos/
entrada/saida/compras/fechamento/realidade
`GET /webhook/relatorio-diario` (cron n8n — relatório automático diário)

### Catch-all (4605)
`GET *` → serve `public/index.html` (SPA)

## Helpers de negócio principais
- `buscarProdutos(termo)` / `acharProdutoUnico(termo)` — matcher determinístico (código → apelido
  → nome exato → parcial), usado por IA/WhatsApp/lançamento
- `montarRealidadeDia()` / `montarPlanilhaMensal()` / `resumoMovimentosDia()` — cálculos financeiros
  do dia/mês (compras/consumo/perdas/percentuais sobre vendas)
- `resumoFormasPagamento()` / `somarResumoFormas()` — agregação por forma de pagamento
- `THRESHOLDS_ALERTA` / `THRESHOLD_PADRAO=30` — dias por categoria pra alerta de "parado"
- `nowSP()` / `dateSP()` / `dateAgoDias()` — datas SEMPRE em America/Sao_Paulo (sem bug de UTC)
- `hashPassword()` / `verifyPassword()` — scrypt, formato `salt:hash`

Ver também: [[architecture]] [[data]] [[frontend]]
