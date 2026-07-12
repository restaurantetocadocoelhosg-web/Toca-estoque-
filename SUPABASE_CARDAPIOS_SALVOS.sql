-- Banco de cardápios salvos: substitui o modelo antigo de "1 cardápio fixo por dia da
-- semana" (cardapio_semanal) por uma biblioteca de cardápios NOMEADOS que não se
-- sobrescrevem — cada "Salvar" pede um nome e cria um registro novo (ex: "Terça Mineira",
-- "Quarta do Rock"), reutilizável quando quiser buscando pelo nome.
-- Rode no SQL Editor do Supabase deste projeto, DEPOIS de SUPABASE_PRATOS_CARDAPIO.sql.

CREATE TABLE IF NOT EXISTS cardapios_salvos (
  id BIGSERIAL PRIMARY KEY,
  nome TEXT NOT NULL,
  buffet_principal JSONB NOT NULL DEFAULT '[]'::jsonb,
  rechaud_redondo JSONB NOT NULL DEFAULT '[]'::jsonb,
  rechaud_retangular JSONB NOT NULL DEFAULT '[]'::jsonb,
  responsavel TEXT DEFAULT '',
  ativo INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cardapios_salvos_nome ON cardapios_salvos (nome);
CREATE INDEX IF NOT EXISTS idx_cardapios_salvos_updated ON cardapios_salvos (updated_at DESC);

-- Migra os 7 dias já montados (cardapio_semanal) pra cá como os primeiros cardápios
-- salvos, preservando o trabalho já feito, ANTES de aposentar o modelo antigo.
INSERT INTO cardapios_salvos (nome, buffet_principal, rechaud_redondo, rechaud_retangular, responsavel, created_at)
SELECT
  INITCAP(dia_semana),
  buffet_principal, rechaud_redondo, rechaud_retangular, responsavel, updated_at
FROM cardapio_semanal
WHERE EXISTS (SELECT 1 FROM cardapio_semanal)
ON CONFLICT DO NOTHING;
