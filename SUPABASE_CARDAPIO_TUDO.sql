-- BLOCO ÚNICO — cria as 3 tabelas do módulo Cardápio de uma vez só.
-- Todas usam "IF NOT EXISTS", então é seguro rodar mesmo se algumas já existirem
-- (o Postgres simplesmente ignora o que já está criado, sem dar erro).
-- Rode este arquivo INTEIRO de uma vez no SQL Editor do Supabase.

-- 1) Catálogo de pratos (nome + foto + produto do estoque opcional)
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

-- 2) Modelo antigo (7 dias fixos) — mantido só pra permitir a migração abaixo.
CREATE TABLE IF NOT EXISTS cardapio_semanal (
  dia_semana TEXT PRIMARY KEY CHECK (dia_semana IN ('segunda','terca','quarta','quinta','sexta','sabado','domingo')),
  buffet_principal JSONB NOT NULL DEFAULT '[]'::jsonb,
  rechaud_redondo JSONB NOT NULL DEFAULT '[]'::jsonb,
  rechaud_retangular JSONB NOT NULL DEFAULT '[]'::jsonb,
  responsavel TEXT DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3) Banco de cardápios salvos (nomeados, não se sobrescrevem)
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

-- 4) Migra os 7 dias já montados pro novo banco de cardápios (só roda se ainda não migrou
--    aquele dia especificamente, seguro rodar esse arquivo mais de uma vez)
INSERT INTO cardapios_salvos (nome, buffet_principal, rechaud_redondo, rechaud_retangular, responsavel, created_at)
SELECT
  INITCAP(cs.dia_semana),
  cs.buffet_principal, cs.rechaud_redondo, cs.rechaud_retangular, cs.responsavel, cs.updated_at
FROM cardapio_semanal cs
WHERE NOT EXISTS (SELECT 1 FROM cardapios_salvos WHERE nome = INITCAP(cs.dia_semana));
