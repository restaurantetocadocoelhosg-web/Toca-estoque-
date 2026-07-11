<!-- Generated: 2026-07-11 | Files scanned: 4 (server.js, public/index.html, package.json, railway.toml) | Token estimate: ~550 -->

# Toca Estoque — Arquitetura

Sistema de controle de estoque do Restaurante Toca do Coelho. Monolito Node/Express que serve
tanto a API quanto o front-end estático (mesmo processo, mesma porta).

## Tipo de projeto
App single-service (não é monorepo). 1 processo Node serve API + arquivos estáticos.

## Diagrama de alto nível

```
┌─────────────────────────────────────────────────────────────────┐
│  CELULAR/NAVEGADOR (equipe do restaurante)                      │
│  public/index.html (5.037 linhas — HTML+CSS+JS tudo num arquivo) │
└───────────────────────────┬───────────────────────────────────────┘
                             │ fetch() /api/*
┌───────────────────────────▼───────────────────────────────────────┐
│  server.js (4.615 linhas — Express)                                │
│  Auth (token+sessions) → Middlewares (auth/requireRole/requirePerm)│
│  → ~69 rotas /api/*  → helpers de negócio → Supabase client         │
└───┬─────────────────────────────────────────────┬─────────────────┘
    │                                              │
┌───▼──────────────┐                    ┌──────────▼──────────────┐
│ Supabase (Postgres)│                    │ Externos                │
│ produtos, movimenta-│                    │ - n8n (WhatsApp bot)     │
│ coes, categorias,   │                    │ - Anthropic (chat IA)    │
│ users, sessions,    │                    │ - Railway (hosting)      │
│ inventarios, etc.   │                    └──────────────────────────┘
└─────────────────────┘
```

## Fronteiras de serviço
- **Front-end**: 1 arquivo HTML com `<script>` inline (sem build step, sem framework — JS vanilla
  puro manipulando o DOM direto). PWA (manifest.json + sw.js).
- **Back-end**: Express puro, sem camada de "controller/service/repo" separada — cada rota já
  contém a lógica de negócio + chamada Supabase inline.
- **Banco**: Supabase (Postgres gerenciado) — acesso via `@supabase/supabase-js`, sem ORM.
- **Deploy**: Railway (`railway.toml`), build nixpacks, `npm start` → `node server.js`.

## Fluxo de dado típico (lançar uma movimentação)
```
Usuário digita no #f-busca → GET /api/produtos/buscar (nome OU apelido/sinônimo)
  → escolhe produto → preenche qtd → POST /api/movimentacoes
  → server: valida (produto existe? anomalia? ajuste recente?) → trava otimista (retry até 4x)
  → grava em `produtos` (qtd) + `movimentacoes` (histórico) → responde produto atualizado
  → front atualiza tela sem reload (SPA)
```

## Autenticação
Token próprio (não é Supabase Auth) — `hashPassword()`/`verifyPassword()` com scrypt, sessões
em memória OU tabela `sessions` do Supabase (`useSupabaseSessions`, ver backend.md). Roles:
`admin` > `gerente` > `operador`, mais permissões finas por chave (`permissoes` JSONB por user).

Ver também: [[backend]] [[frontend]] [[data]] [[dependencies]]
