-- Cardápio da semana: plano de produção do buffet, um registro por dia da semana (reutilizado
-- toda semana — não é por data). Cada cuba referencia um prato do catálogo (pratos_cardapio,
-- ver SUPABASE_PRATOS_CARDAPIO.sql) — precisa rodar aquele arquivo ANTES deste.
-- Rode no SQL Editor do Supabase deste projeto.

CREATE TABLE IF NOT EXISTS cardapio_semanal (
  dia_semana TEXT PRIMARY KEY CHECK (dia_semana IN ('segunda','terca','quarta','quinta','sexta','sabado','domingo')),
  buffet_principal JSONB NOT NULL DEFAULT '[]'::jsonb,
  rechaud_redondo JSONB NOT NULL DEFAULT '[]'::jsonb,
  rechaud_retangular JSONB NOT NULL DEFAULT '[]'::jsonb,
  responsavel TEXT DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Cada item dos 3 campos JSONB acima segue o formato:
-- { "prato_id": 12, "cubas": 1, "obs": "(TEM PRONTO)" }
-- nome/foto do prato vêm sempre do catálogo (pratos_cardapio) na hora de montar a tela —
-- assim, se trocar a foto do prato, todo dia que usa esse prato atualiza junto.
