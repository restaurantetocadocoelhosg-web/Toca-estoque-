-- DELIVERY — receita por plataforma (30/08/2026)
-- Rode no Supabase → SQL Editor → New query → Run. Seguro rodar mais de uma vez.
--
-- Por que uma tabela nova e não uma linha no fechamento diário:
--   O fechamento é o caixa do SALÃO, lançado dia a dia por quem fecha. O delivery vem
--   de relatório mensal da plataforma, com comissão embutida e nome próprio. Enfiar um
--   total de mês dentro de um fechamento de dia misturaria duas coisas com origem,
--   granularidade e dono diferentes -- e o Rubens pediu explicitamente "cada delivery
--   com seu nome".
--
-- O que NÃO fica guardado: a comissão. Ela é sempre `vendas_bruto - valor_liquido`,
-- calculada na hora. Guardar valor derivado é como guardar saldo: na primeira correção
-- retroativa ele vira mentira silenciosa, e ninguém percebe.

create table if not exists delivery_receitas (
  id             bigserial   primary key,
  tenant_id      bigint      not null default 1,

  plataforma     text        not null,          -- '99food' | 'ifood'

  -- Período que o relatório cobre. Guardado como intervalo, e não como "mês", porque
  -- relatório de mês em andamento fecha numa data qualquer (o do 99Food veio 01-29/08).
  periodo_inicio date        not null,
  periodo_fim    date        not null,

  vendas_bruto   numeric(12,2) not null default 0,   -- o que o cliente pagou
  valor_liquido  numeric(12,2) not null default 0,   -- o que caiu para a empresa

  -- true = o período ainda não fechou; o número vai mudar quando o mês virar.
  parcial        boolean     not null default false,

  observacao     text        default '',
  origem         text        default '',            -- de onde veio o dado
  responsavel    text        default '',

  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),

  -- Reenviar o mesmo relatório ATUALIZA, não duplica. Sem isso, mandar o fechamento
  -- de agosto depois do parcial criaria duas linhas e dobraria a receita do mês.
  unique (tenant_id, plataforma, periodo_inicio, periodo_fim)
);

create index if not exists idx_delivery_receitas_tenant    on delivery_receitas (tenant_id);
create index if not exists idx_delivery_receitas_periodo   on delivery_receitas (periodo_inicio desc);
create index if not exists idx_delivery_receitas_plataforma on delivery_receitas (plataforma);

-- Sem policy de RLS: a tabela é lida e escrita só pelo servidor, com a service key.
alter table delivery_receitas enable row level security;
