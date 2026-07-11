<!-- Generated: 2026-07-11 | Files scanned: server.js (queries), migrations SQL soltas na raiz | Token estimate: ~450 -->

# Dados — Supabase (Postgres)

Projeto compartilhado com outros apps do restaurante (ref `zuwdgyvbuaocbzckhhlm`). Sem ORM —
acesso via `@supabase/supabase-js` direto nas rotas.

## Tabelas principais

| Tabela | Papel | Colunas-chave |
|---|---|---|
| `produtos` | Estoque atual (fonte da verdade de `qtd`) | id, nome, nome_search, categoria, unidade, qtd, minimo, custo, ativo, codigo, grupo_troca |
| `movimentacoes` | Ledger histórico (nunca recalculado, só inserido/cancelado) | produto_id, produto_nome, categoria, tipo(Entrada/Saída/Perda/Ajuste), qtd, qtd_antes, qtd_depois, valor, motivo, responsavel, obs, created_at |
| `categorias` | Categorias cadastradas (admin) — união com as derivadas de produtos | id, nome |
| `sinonimos` | Apelidos → nome do produto (matcher determinístico) | id, termo (normalizado), produto_nome |
| `users` | Contas de acesso (auth própria, não Supabase Auth) | id, username, nome, role, password_hash (`salt:hash`), active, permissoes (jsonb) |
| `sessions` | Sessões persistidas (fallback: memória se tabela não existir) | token, user_id, ... |
| `inventarios` / `inventario_itens` | Inventário físico (contagem periódica) | status(aberto/fechado), categoria, valor_sumico, valor_sobra / produto_id, qtd_sistema, qtd_contada, causa |
| `fechamentos_diarios` | Caixa do dia (vendas, formas de pgto, despesas) | data, vendas, pratos_vendidos, pagamentos(jsonb), cortes(jsonb), despesas(jsonb), relatorio_texto |
| `pagamentos` | Contas pagas (fora do caixa diário) | categoria, valor, data, ... |
| `backups_estoque` | Snapshot completo (dados=json de TODOS os produtos, incl. arquivados) | data_backup, motivo, total_produtos, valor_total, zerados, criticos, dados |
| `snapshots_diarios` | 1 snapshot/dia por produto (auditoria histórica de qtd) | produto_id, data, qtd |
| `ia_agenda` | Log de observações/erros/alertas da IA | tipo(observacao/melhoria/erro/alerta), ... |
| `nota_pendencias` | Itens de nota fiscal que a IA não conseguiu casar com produto | nome_cupom, qtd, status |

## Convenções importantes
- **`ativo`**: `1` ou `NULL` = ativo; `0` = arquivado. Quase toda query de CONTAGEM/LISTAGEM
  precisa filtrar `.or('ativo.eq.1,ativo.is.null')` — exceção: auditoria (precisa histórico
  completo) e backup/reset (precisa todos os dados).
- **Reconstrução de saldo**: Entrada soma, Saída/Perda subtrai, **Ajuste DEFINE o saldo absoluto**
  (não é delta) — usado em auditoria e no fechamento de inventário.
- **`obs` como marcador de origem**: `'sincronização automática'` (reset/restore) e `'inventario'`
  (fechamento de inventário) são EXCLUÍDOS do cálculo de "sumiço" nas conferências.
- **`grupo_troca`**: produtos substitutos entre si (ex.: Alcatra/Coxão Mole) — se um tem estoque,
  o outro não dispara alerta de "parado".

Ver também: [[architecture]] [[backend]]
