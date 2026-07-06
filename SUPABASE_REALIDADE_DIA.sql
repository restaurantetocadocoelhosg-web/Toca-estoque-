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

ALTER TABLE fechamentos_diarios
  ADD COLUMN IF NOT EXISTS pratos_vendidos INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS pagamentos JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS cortes JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS despesas JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS relatorio_texto TEXT DEFAULT '';
