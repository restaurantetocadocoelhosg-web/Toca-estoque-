-- Realidade do dia: salva a venda diaria para cruzar com estoque.
-- Rode no SQL Editor do Supabase deste projeto.

CREATE TABLE IF NOT EXISTS fechamentos_diarios (
  id BIGSERIAL PRIMARY KEY,
  data DATE NOT NULL UNIQUE,
  vendas NUMERIC(12,2) NOT NULL DEFAULT 0,
  observacao TEXT DEFAULT '',
  responsavel TEXT DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fechamentos_diarios_data
  ON fechamentos_diarios (data DESC);
