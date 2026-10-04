-- Onda 3 — estoque ATÔMICO e IDEMPOTENTE (F1, F2, F3).
-- ADITIVA: cria 1 tabela nova e 2 funções. Não altera nem apaga coluna ou dado existente.
--
-- Antes: o app mudava o saldo (UPDATE produtos) e DEPOIS gravava o histórico (INSERT movimentacoes),
-- em duas chamadas. Falha entre elas = saldo sem histórico (F2); dois cancelamentos ao mesmo tempo
-- devolviam a quantidade duas vezes (F1); a mesma nota/mensagem reenviada lançava de novo (F3).
-- Agora cada operação é UMA transação no banco, com o produto travado (FOR UPDATE) enquanto dura.
--
-- Idempotência: evento_id = chave da OPERAÇÃO LÓGICA (a mesma em todos os reenvios). Mesmo evento
-- com o mesmo conteúdo devolve o resultado da primeira vez; mesmo evento com conteúdo diferente é
-- RECUSADO (nunca "adivinha" qual vale). Duas saídas reais iguais têm eventos diferentes e valem as duas.

begin;

create table if not exists movimentacao_eventos (
  tenant_id bigint not null,
  evento_id text not null,
  conteudo text not null,            -- assinatura do pedido (tipo|produto|qtd|custo...) para recusar conflito
  mov_id bigint,
  resultado jsonb,
  criado_em timestamptz not null default now(),
  primary key (tenant_id, evento_id)
);

-- Lança uma movimentação: trava o produto, confere, muda o saldo e grava o histórico juntos.
create or replace function estoque_movimentar(
  p_tenant bigint, p_produto_id bigint, p_tipo text, p_qtd numeric,
  p_custo numeric, p_atualiza_custo boolean, p_valor numeric,
  p_motivo text, p_responsavel text, p_obs text, p_created_at timestamptz,
  p_evento_id text default null
) returns jsonb
language plpgsql
security invoker
-- search_path capturado na criação: em produção é public; num ambiente com outro schema, rode
-- "set search_path = <schema>;" antes desta migração e a função fica presa a ele.
set search_path from current
as $$
declare
  v_prod produtos%rowtype;
  v_antes numeric; v_depois numeric; v_custo numeric; v_valor numeric;
  v_mov_id bigint; v_conteudo text; v_ev movimentacao_eventos%rowtype; v_res jsonb;
begin
  if p_tipo not in ('Entrada', 'Saída', 'Perda', 'Ajuste') then raise exception 'TIPO_INVALIDO' using errcode = 'P0001'; end if;
  if p_qtd is null or p_qtd < 0 or (p_qtd = 0 and p_tipo <> 'Ajuste') then raise exception 'QTD_INVALIDA' using errcode = 'P0001'; end if;

  if p_evento_id is not null then
    -- Conteúdo que identifica o pedido: o mesmo evento com qualquer destes diferentes é RECUSADO.
    v_conteudo := concat_ws('|', p_tipo, p_produto_id, p_qtd::text, coalesce(p_custo::text, ''), coalesce(p_motivo, ''),
                            coalesce(p_valor::text, ''), coalesce(to_char(p_created_at at time zone 'America/Sao_Paulo', 'YYYY-MM-DD'), ''));
    -- Reserva o evento. Reenvio concorrente espera aqui até a 1ª transação terminar.
    insert into movimentacao_eventos (tenant_id, evento_id, conteudo) values (p_tenant, p_evento_id, v_conteudo)
      on conflict (tenant_id, evento_id) do nothing;
    if not found then
      select * into v_ev from movimentacao_eventos where tenant_id = p_tenant and evento_id = p_evento_id;
      if v_ev.conteudo <> v_conteudo then raise exception 'EVENTO_CONFLITANTE' using errcode = 'P0001'; end if;
      return coalesce(v_ev.resultado, '{}'::jsonb) || jsonb_build_object('repetido', true);
    end if;
  end if;

  select * into v_prod from produtos where id = p_produto_id and tenant_id = p_tenant for update;
  if not found then raise exception 'PRODUTO_NAO_ENCONTRADO' using errcode = 'P0001'; end if;

  v_antes := v_prod.qtd;
  if p_tipo = 'Entrada' then v_depois := round(v_antes + p_qtd, 3);
  elsif p_tipo in ('Saída', 'Perda') then
    if p_qtd > v_antes then raise exception 'ESTOQUE_INSUFICIENTE:%', v_antes using errcode = 'P0001'; end if;
    v_depois := round(v_antes - p_qtd, 3);
  else v_depois := round(p_qtd, 3);
  end if;

  v_custo := coalesce(p_custo, v_prod.custo, 0);
  v_valor := coalesce(p_valor, round(v_custo * (case when p_tipo = 'Ajuste' then abs(v_depois - v_antes) else p_qtd end), 2));

  update produtos set qtd = v_depois, custo = case when p_atualiza_custo then v_custo else custo end
    where id = v_prod.id;
  insert into movimentacoes (produto_id, produto_nome, categoria, tipo, qtd, unidade, custo, valor, motivo,
                             responsavel, obs, qtd_antes, qtd_depois, created_at, tenant_id)
    values (v_prod.id, v_prod.nome, v_prod.categoria, p_tipo, case when p_tipo = 'Ajuste' then v_depois else p_qtd end,
            v_prod.unidade, v_custo, v_valor, p_motivo, p_responsavel, p_obs, v_antes, v_depois,
            coalesce(p_created_at, now()), p_tenant)
    returning id into v_mov_id;

  v_res := jsonb_build_object('mov_id', v_mov_id, 'qtd_antes', v_antes, 'qtd_depois', v_depois,
                              'custo', v_custo, 'custo_anterior', v_prod.custo, 'valor', v_valor);
  if p_evento_id is not null then
    update movimentacao_eventos set mov_id = v_mov_id, resultado = v_res where tenant_id = p_tenant and evento_id = p_evento_id;
  end if;
  return v_res;
end $$;

-- Cancela (estorna) uma movimentação: trava o lançamento e o produto; o 2º cancelamento simultâneo
-- encontra o lançamento já apagado e não devolve a quantidade de novo.
create or replace function estoque_cancelar(p_tenant bigint, p_mov_id bigint) returns jsonb
language plpgsql
security invoker
-- search_path capturado na criação: em produção é public; num ambiente com outro schema, rode
-- "set search_path = <schema>;" antes desta migração e a função fica presa a ele.
set search_path from current
as $$
declare
  v_mov movimentacoes%rowtype; v_prod produtos%rowtype; v_depois numeric;
begin
  select * into v_mov from movimentacoes where id = p_mov_id and tenant_id = p_tenant for update;
  if not found then raise exception 'MOV_NAO_ENCONTRADA' using errcode = 'P0001'; end if;
  if v_mov.tipo = 'Ajuste' then raise exception 'AJUSTE_NAO_CANCELA' using errcode = 'P0001'; end if;
  select * into v_prod from produtos where id = v_mov.produto_id and tenant_id = p_tenant for update;
  if not found then raise exception 'PRODUTO_NAO_ENCONTRADO' using errcode = 'P0001'; end if;
  if v_mov.tipo = 'Entrada' then
    v_depois := round(v_prod.qtd - v_mov.qtd, 3);
    if v_depois < 0 then raise exception 'FICARIA_NEGATIVO:%', v_prod.qtd using errcode = 'P0001'; end if;
  else
    v_depois := round(v_prod.qtd + v_mov.qtd, 3);
  end if;
  update produtos set qtd = v_depois where id = v_prod.id;
  delete from movimentacoes where id = v_mov.id;
  -- Compra automática vinculada sai junto das Contas (lançamento digitado na mão nunca é tocado).
  delete from pagamentos_comprovantes where mov_id = v_mov.id and tenant_id = p_tenant
    and origem in ('estoque-auto', 'estoque-backfill');
  return jsonb_build_object('mov_id', v_mov.id, 'produto_id', v_prod.id, 'tipo', v_mov.tipo, 'qtd', v_mov.qtd,
                            'qtd_antes', v_prod.qtd, 'qtd_depois', v_depois, 'produto_nome', v_prod.nome);
end $$;

-- SÓ o servidor (service_role) executa. Nunca anon/authenticated (ver incidente 19/08: função aberta ao anônimo).
revoke all on function estoque_movimentar(bigint, bigint, text, numeric, numeric, boolean, numeric, text, text, text, timestamptz, text) from public, anon, authenticated;
revoke all on function estoque_cancelar(bigint, bigint) from public, anon, authenticated;
grant execute on function estoque_movimentar(bigint, bigint, text, numeric, numeric, boolean, numeric, text, text, text, timestamptz, text) to service_role;
grant execute on function estoque_cancelar(bigint, bigint) to service_role;
revoke all on table movimentacao_eventos from anon, authenticated;
grant select, insert, update on table movimentacao_eventos to service_role;
-- RLS ligado e SEM política: ninguém além do service_role (que ignora RLS) enxerga a tabela, mesmo
-- se um GRANT futuro reabrir o acesso pela API pública.
alter table movimentacao_eventos enable row level security;

commit;
