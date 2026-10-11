-- FASE 1 DOS 3 LIVROS — LIVRO DE COMPRAS (11/10/2026, aprovado pelo Rubens).
-- ADITIVA: cria 1 tabela e 2 colunas que aceitam vazio. Não altera nem apaga coluna ou dado existente.
--
-- Antes: cada linha de estoque era uma "compra" solta; a nota em si (fornecedor, data, total) se perdia.
-- Agora a NOTA vira documento: uma linha em `compras`, e cada entrada no estoque (e cada pendência)
-- aponta para ela por `compra_id`. Compra lançada na mão sem nota também vira uma linha (sem_nota),
-- que o gerente aprova. As Contas NÃO mudam nesta fase.

begin;

create table if not exists compras (
  id bigserial primary key,
  tenant_id bigint not null,
  origem text not null check (origem in ('grupo', 'cupom', 'mao')),
  nota_hash text,                       -- impressão digital da foto (mesma foto = mesma compra)
  fornecedor text,
  data_nota date,                       -- data impressa na nota (quando a leitura achou)
  total_nota numeric(12, 2),            -- total impresso na nota (quando a leitura achou)
  remetente text,                       -- quem mandou a foto / lançou
  sem_nota boolean not null default false,
  motivo_sem_nota text,
  aprovado_por text,                    -- compra sem nota: gerente que aprovou
  aprovado_em timestamptz,
  criado_em timestamptz not null default now()
);
create unique index if not exists compras_tenant_hash on compras (tenant_id, nota_hash) where nota_hash is not null;
create index if not exists compras_tenant_criado on compras (tenant_id, criado_em desc);

alter table movimentacoes add column if not exists compra_id bigint references compras (id);
alter table nota_pendencias add column if not exists compra_id bigint references compras (id);
create index if not exists movimentacoes_compra on movimentacoes (compra_id) where compra_id is not null;
create index if not exists nota_pendencias_compra on nota_pendencias (compra_id) where compra_id is not null;

-- Só o servidor (service_role). RLS ligado e sem política, como movimentacao_eventos.
revoke all on table compras from anon, authenticated;
grant select, insert, update on table compras to service_role;
grant usage, select on sequence compras_id_seq to service_role;
alter table compras enable row level security;

commit;
