-- Onda 1 / F8 — instante da contagem de cada item do inventário.
-- ADITIVA: só acrescenta colunas que aceitam vazio. Não altera nem apaga dado existente.
-- Sem ela, o fechamento comparava a contagem com o saldo da ABERTURA: uma saída normal feita
-- durante a contagem virava "sumiço" e o ajuste apagava saídas feitas depois da contagem.
-- Itens contados antes desta migração ficam com contado_em vazio e seguem a regra antiga.
alter table inventario_itens add column if not exists contado_em timestamptz;
-- Saldo do sistema no instante em que o item foi contado (abertura + o que se mexeu até ali).
alter table inventario_itens add column if not exists qtd_sistema_contagem numeric;
