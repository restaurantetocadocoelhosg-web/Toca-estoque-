-- FECHAMENTO DO DIA COM BALANÇA (08/11/2026, aprovado pelo Rubens).
-- ADITIVA: 4 colunas que aceitam vazio em fechamentos_diarios + 1 tabela nova. Não altera nem apaga nada.
--
-- balanca_kg : total pesado na balança no dia (kg). Vazio em dia antigo.
-- preco_kg   : preço do quilo USADO naquele dia (congelado pelo servidor; mudar o preço não mexe no passado).
-- perdas     : os 5 pesos da seção LIXO em gramas (lixo_buffet_g, lixo_salada_g, desperdicio_g, fritura_g,
--              doacao_corte_g). Só anotação: nunca entra em dinheiro. lixo_buffet_g (coluna antiga) continua.
-- feriado    : dia marcado como feriado (preço de fim de semana).
-- precos_kg  : tabela de preços com data de início (R$ 64,99 seg–sex; R$ 89,99 sáb/dom/feriado é o padrão
--              quando não há linha).

begin;

alter table fechamentos_diarios add column if not exists balanca_kg numeric(9, 3);
alter table fechamentos_diarios add column if not exists preco_kg numeric(8, 2);
alter table fechamentos_diarios add column if not exists perdas jsonb;
alter table fechamentos_diarios add column if not exists feriado boolean;

create table if not exists precos_kg (
  id bigserial primary key,
  tenant_id bigint not null,
  inicio date not null,
  preco_util numeric(8, 2) not null check (preco_util > 0),
  preco_fim_semana numeric(8, 2) not null check (preco_fim_semana > 0),
  criado_por text,
  created_at timestamptz not null default now(),
  unique (tenant_id, inicio)
);

-- Só o servidor (service_role). RLS ligado e sem política, como compras.
revoke all on table precos_kg from anon, authenticated;
grant select, insert, update on table precos_kg to service_role;
grant usage, select on sequence precos_kg_id_seq to service_role;
alter table precos_kg enable row level security;

commit;
