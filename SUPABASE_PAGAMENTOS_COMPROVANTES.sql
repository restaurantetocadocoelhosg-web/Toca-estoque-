-- Pagamentos / comprovantes: mini planilha financeira ligada ao fechamento.
-- Rode no SQL Editor do Supabase deste projeto, se a migração automática não tiver sido aplicada.

CREATE TABLE IF NOT EXISTS pagamentos_comprovantes (
  id BIGSERIAL PRIMARY KEY,
  data DATE NOT NULL,
  forma TEXT NOT NULL DEFAULT '',
  operadora TEXT DEFAULT '',
  bandeira TEXT DEFAULT '',
  valor_bruto NUMERIC(12,2) NOT NULL DEFAULT 0,
  taxa NUMERIC(12,2) NOT NULL DEFAULT 0,
  valor_liquido NUMERIC(12,2) NOT NULL DEFAULT 0,
  nsu TEXT DEFAULT '',
  autorizacao TEXT DEFAULT '',
  parcelas INTEGER NOT NULL DEFAULT 0,
  descricao TEXT DEFAULT '',
  comprovante_texto TEXT DEFAULT '',
  origem TEXT DEFAULT '',
  responsavel TEXT DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pagamentos_comprovantes_data
  ON pagamentos_comprovantes (data DESC);

CREATE INDEX IF NOT EXISTS idx_pagamentos_comprovantes_forma
  ON pagamentos_comprovantes (forma);

ALTER TABLE pagamentos_comprovantes ENABLE ROW LEVEL SECURITY;
