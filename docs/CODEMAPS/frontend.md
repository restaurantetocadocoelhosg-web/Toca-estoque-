<!-- Generated: 2026-07-11 | Files scanned: public/index.html (5.037 linhas) | Token estimate: ~500 -->

# Frontend — public/index.html

SPA de arquivo único: HTML + CSS + JS tudo inline (sem build, sem framework, sem bundler).
Estado global em variáveis `let` no topo do `<script>` (não há Redux/Zustand/Context).

## Estrutura de página (SPA, troca de aba só alterna classe `.active`)

`goPage(id)` controla qual `<div id="p-...">` fica visível — **não navega de verdade**, então
estado de formulário/seleção de produto PERSISTE entre trocas de aba (relevante pra automação/QA).

| Aba (`id`) | Carrega via | Conteúdo |
|---|---|---|
| `lancar` (padrão) | — | Dashboard (cards zerados/críticos) + form de lançamento + últimos |
| `estoque` | `loadEstoque()` | Lista filtrável por nome/apelido/código, categoria, status |
| `hist` | `loadHist()` | Histórico de movimentações, busca livre, cancelar lançamento |
| `realidade` | `loadRealidade()` | Fechamento do dia (vendas, formas pgto, consumo/perdas) |
| `planilha` | `loadPlanilhaMensal()` | Agregação mensal, tabela dia-a-dia, % sobre vendas |
| `relatorios` | `loadRelatorios()` | Comparativo por período |
| `pagamentos` | `loadPagamentos()` | Contas pagas (CRUD), ler comprovante por IA |
| `export` | — | Botões de exportação CSV/HTML |
| `chat` | `iniciarChatBoot()` | Chat com IA (ferramentas de consulta/lançamento) |
| `audit` | `initAuditoria()` | Divergências de estoque (reconstrução de saldo) |
| `inventario` | `loadInventario()` | Abrir/contar/fechar inventário físico |
| `admin` | `loadUsers/Sinonimos/ProdAdmin/CatsAdmin/Grupos()` | Gestão (só admin) |

## Componentes/telas modais principais
- `NotaSheet`/leitor de cupom — foto → IA lê → confirma lançamento
- Modais de confirmação in-app: `askConfirm()`, `askPrompt()`, `avisar()` (substituem
  window.confirm/alert/prompt nativos — não funcionam em PWA instalado)
- `erroModal()` — erro bloqueante (ex.: "Estoque Insuficiente")

## Fluxo de lançamento manual (tela mais usada)
```
#f-busca (oninput) → buscaProd() → GET /api/produtos/buscar → .ac-item lista
  → selProd() seta prodAtual, esconde busca, mostra #prod-sel
  → #f-qtd + tipo (Entrada/Saída/Perda/Ajuste) → lancar()
  → POST /api/movimentacoes → trata 409 (alerta) ou sucesso (toast + atualiza listas)
```

## Busca de produto — 6 pontos de entrada, mesmo backend
`#f-busca` (Lançar), `#est-search` (Estoque), `#prod-admin-search` (Admin produtos),
busca de Pendências, Admin>Sinônimos, Admin>Grupos de troca, modal de cupom — todos batem em
`/api/produtos/buscar` ou `/api/produtos?q=`, ambos com matcher de apelido (corrigido 11/07).

## Convenções
- `escapeHtml()` sempre antes de interpolar dado do usuário em `innerHTML`
- `fmtBRLMoney()`/`fmtSheetMoney()`/`fmtPct()` — formatação consistente de dinheiro/percentual
- `api()` — wrapper fetch com token + tratamento de erro padrão

Ver também: [[architecture]] [[backend]]
