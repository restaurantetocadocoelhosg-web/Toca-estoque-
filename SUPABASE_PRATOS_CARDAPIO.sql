-- Catálogo de pratos do buffet (cadastro permanente, com foto) — separado do cardápio da
-- semana em si. Cadastra o prato UMA VEZ (nome + foto + produto principal opcional do estoque)
-- e depois é só escolher na tela de Cardápio, sem digitar/buscar de novo toda vez.
-- Rode no SQL Editor do Supabase deste projeto.

-- Sem FOREIGN KEY pra produtos.id de propósito — nenhuma outra tabela do app usa FK explícita
-- (fechamentos_diarios, pagamentos_comprovantes etc.), a integridade é controlada pelo próprio
-- server.js. Evita erro de incompatibilidade de tipo entre bancos criados em momentos diferentes.
CREATE TABLE IF NOT EXISTS pratos_cardapio (
  id BIGSERIAL PRIMARY KEY,
  nome TEXT NOT NULL,
  foto_url TEXT DEFAULT '',
  produto_id BIGINT,
  categoria TEXT DEFAULT '',
  ativo INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pratos_cardapio_nome ON pratos_cardapio (nome);
