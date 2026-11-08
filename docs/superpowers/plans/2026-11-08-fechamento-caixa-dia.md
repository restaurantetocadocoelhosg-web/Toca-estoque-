# Fechamento de caixa na tela Dia — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Colar o texto do movimento na tela Dia preenche tudo certo (inclusive 5 perdas em kg e a linha BALANÇA) e o app calcula "bebidas e derivados"; tudo aparece na impressão, Planilha e WhatsApp.

**Architecture:** Um módulo puro `public/movimento-caixa.js` (UMD, como `public/recibo-lancamentos.js`) com leitor, preço do quilo, feriados, conta da balança e avisos; usado pela tela e pelo servidor. Migração aditiva em `fechamentos_diarios` + tabela `precos_kg`. Relatórios leem os campos novos; dias antigos sem balança não mudam.

**Tech Stack:** Node/Express (`server.js`), front em `public/index.html` (JS inline), Supabase/PostgREST, `node --test` com banco descartável (`test/ambiente`).

**Spec:** `docs/superpowers/specs/2026-11-08-fechamento-caixa-dia-design.md`

## Global Constraints

- Preço do quilo: R$ 64,99 seg–sex; R$ 89,99 sábado, domingo e feriado (padrão quando não há linha em `precos_kg`).
- Linha nova no texto: `BALANÇA: 70,402 KG` (aceitar BALANCA, KG antes ou depois, vírgula ou ponto decimal).
- comida pesada = balança_kg × preço; comida vendida = comida pesada − soma dos cortes (Relatório); bebidas = total vendido (soma das formas) − comida vendida. Arredondar a centavos.
- Seção `__LIXO FINAL BUFFET__`: tudo é peso (g). Chaves: `lixo_buffet_g`, `lixo_salada_g`, `desperdicio_g`, `fritura_g`, `doacao_corte_g`. `----` ou vazio = null. Peso NUNCA vira valor em dinheiro.
- Migração só ADITIVA; `lixo_buffet_g` continua recebendo o lixo final do buffet.
- Porcionamento e Observação: escondidos na tela, nunca apagados.
- Horário/data de Brasília (`America/Sao_Paulo`), nunca `toISOString()` para "hoje".
- Selo de versão v127. Publicação, migração e push: o Rubens roda (`!`). Teste e commit em comandos separados.

## Review Focus

- Texto antigo (txt de `Desktop/fechamento/`) sem seção LIXO ou sem BALANÇA → pagamentos/cortes/despesas iguais ao leitor antigo, balança vazia, sem conta de bebidas e sem aviso de "balança faltando" antes de 08/11/2026.
- Linha de despesa com "KG" fora da seção LIXO (ex.: "FRANGO 2KG R$ 30,00") → continua despesa de R$ 30,00.
- Dia salvo sem `preco_kg` (antigo) reaberto → mostra como antes, não recalcula com preço de hoje.
- Feriado móvel (Carnaval não é feriado nacional; Sexta-feira Santa e Corpus Christi são) e 20/11 → preço de fim de semana.
- Total escrito diferente da soma → bebidas usa a SOMA e o aviso de total aparece junto.

---

### Task 1: Módulo `movimento-caixa.js` (leitor + conta)

**Files:**
- Create: `public/movimento-caixa.js`
- Test: `test/movimento-caixa.test.js`, fixture `test/fixtures/movimento-08-11-2026.txt`

**Interfaces (Produces):**
- `lerMovimento(texto: string, opts?: {anoPadrao?: number}) -> { data: string|'', pratos: number, pagamentos: {qtd,descricao,valor}[], cortes: {qtd,descricao,valor}[], despesas: {descricao,valor}[], perdas: {lixo_buffet_g,lixo_salada_g,desperdicio_g,fritura_g,doacao_corte_g}, balancaKg: number|null, feriadoNoTexto: boolean, totalDeclarado: number|null, naoEntendidas: string[] }`
- `feriadoAutomatico(dataISO: string) -> string|null` (nome do feriado nacional ou RJ: 01/01, Carnaval NÃO, Sexta Santa, 21/04, 23/04 São Jorge, 01/05, Corpus Christi, 07/09, 12/10, 02/11, 15/11, 20/11, 25/12)
- `precoKgDoDia(dataISO: string, {feriado: boolean, tabela?: {inicio:string, util:number, fimSemana:number}[]}) -> {preco: number, tipo: 'util'|'fim_semana'|'feriado'}`
- `contaBalanca({balancaKg, precoKg, cortes, totalVendido}) -> {comidaPesada, relatorio, comidaVendida, bebidas, pesoCortesKg: number[]} | null` (null se balancaKg ausente)
- `valorPerdas(perdas, precoKg) -> number` (só informação)
- `avisosMovimento({totalDeclarado, totalVendido, conta, data, balancaKg, mediaBebidas14d, naoEntendidas}) -> string[]`
- `PRECOS_PADRAO = {util: 64.99, fimSemana: 89.99}`, `DATA_INICIO_BALANCA = '2026-11-08'`

- [ ] **Step 1: testes que falham**, com o texto de 08/11:
  - `pratos === 150`; 6 pagamentos somando 6468.07; cortes `[90.17, 248.98, 359.24]` com qtd `[2,5,6]`;
  - despesas: 6 itens somando 124.10, descrição `'PAO'` (sem traço sobrando);
  - perdas: `{lixo_buffet_g:2890, lixo_salada_g:6200, desperdicio_g:null, fritura_g:1750, doacao_corte_g:2750}`; `totalDeclarado === 6358.07`; `data === '2026-11-08'`;
  - com `BALANÇA: 70,402 KG` acrescentado: `balancaKg === 70.402`; e variantes `BALANCA 70.402KG`, `BALANÇA KG 70,402`;
  - `precoKgDoDia('2026-11-08',{feriado:false}).preco === 89.99`; `'2026-11-10'` → 64.99; `'2026-11-20'` com `feriado: !!feriadoAutomatico(...)` → 89.99; `feriadoAutomatico('2026-04-03') === 'Sexta-feira Santa'`; `feriadoAutomatico('2026-02-17') === null`;
  - `contaBalanca({balancaKg:70.402, precoKg:89.99, cortes, totalVendido:6468.07})` → `comidaPesada 6335.48, relatorio 698.39, comidaVendida 5637.09, bebidas 830.98`;
  - avisos: diferença de 110,00 no total; bebidas negativa; balança faltando quando `data >= DATA_INICIO_BALANCA`, nunca antes;
  - "FRANGO 2KG R$ 30,00" em DESPESA → despesa 30.00;
  - REGRESSÃO: para cada `*.txt` de `C:/Users/User/Desktop/fechamento/**` (pular se a pasta não existir), nenhuma despesa cuja descrição contenha LIXO/FRITURA/DOAC/DESPERD/KG sem `R$`, e soma de pagamentos igual ao leitor antigo (extraído com `test/helpers/extrair-funcao.js` de `public/index.html`).
- [ ] **Step 2:** `node --test test/movimento-caixa.test.js` → FAIL (módulo não existe).
- [ ] **Step 3:** implementar o módulo (UMD igual ao recibo). Seções pelo título normalizado; dentro de LIXO, peso com unidade antes ou depois (`KG|KGB|G`), `----` = null; linha com número não classificado vai para `naoEntendidas`.
- [ ] **Step 4:** teste → PASS.
- [ ] **Step 5:** commit `feat: leitor do movimento com perdas, balanca e conta das bebidas (modulo)`.

### Task 2: Banco + servidor (salvar, carregar, preço do quilo)

**Files:**
- Create: `migracoes/2026-11-08-fechamento-balanca.sql`
- Modify: `test/ambiente/schema-producao.sql` (mesmas colunas/tabela), `server.js` (`buscarFechamentoDia` ~2963, GET/POST `/api/realidade-dia` ~4167-4245, novas rotas de preço)
- Test: `test/fechamento-balanca.test.js`

**Interfaces:**
- Consumes: `movimento-caixa.js` (`precoKgDoDia`, `feriadoAutomatico`, `contaBalanca`, `PRECOS_PADRAO`).
- Produces: colunas `fechamentos_diarios.balanca_kg numeric`, `preco_kg numeric`, `perdas jsonb`, `feriado boolean`; tabela `precos_kg(id, tenant_id, inicio date, preco_util numeric, preco_fim_semana numeric, criado_por text, created_at)` com RLS sem acesso público; `GET /api/precos-kg` (todos com perm `dia`), `POST /api/precos-kg` (admin; `{inicio, preco_util, preco_fim_semana}`); GET `/api/realidade-dia` devolve `balanca_kg, preco_kg, feriado, perdas, conta_balanca`.

- [ ] **Step 1: testes que falham** (app real + banco descartável): salvar dia com `balanca_kg 70.402`, `perdas`, `feriado false` em 2026-11-08 → banco tem `preco_kg 89.99` (congelado pelo servidor, não pelo cliente) e `lixo_buffet_g 2890`; GET devolve `conta_balanca.bebidas 830.98`; despesas do POST não criam conta para itens sem valor; POST `/api/precos-kg` como operador → 403; como admin com `inicio 2026-12-01, util 69.99` → dia 2026-12-02 salva com 69.99 e 2026-11-10 continua 64.99; dia antigo sem colunas novas → GET igual ao de antes (`conta_balanca null`).
- [ ] **Step 2:** `npm test -- test/fechamento-balanca.test.js` → FAIL.
- [ ] **Step 3:** migração + schema de teste + servidor. Sem a tabela/colunas (migração não rodada) o POST segue salvando como hoje (padrão do livro de compras).
- [ ] **Step 4:** teste → PASS; `npm test` inteiro verde.
- [ ] **Step 5:** commit `feat: balanca, perdas e preco do quilo no fechamento do dia (banco e servidor)`.

### Task 3: Tela Dia

**Files:**
- Modify: `public/index.html` (bloco `#p-realidade` ~1074-1135; `lerRelatorioColado` ~4932; `conferirMovimentoCaixa` ~4842; `loadRealidade` ~4992; `salvarRealidade` ~5263; `<script src>` ~2111)
- Test: `test/movimento-caixa-tela.test.js` (extrai funções com `extrair-funcao.js`) + teste Playwright local `tests/fechamento-dia.spec.js` contra o app local de teste

**Interfaces:**
- Consumes: Task 1 (browser global `MovimentoCaixa`), Task 2 (campos do GET/POST, `/api/precos-kg`).

- [ ] **Step 1: teste que falha**: colar o texto de 08/11 + BALANÇA na tela → campos `#real-balanca` 70,402; 5 campos de perda; quadro mostra 6.335,48 / 698,39 / 5.637,09 / 6.468,07 / 830,98; preço "R$ 89,99 (domingo)"; Porcionamento e Observação invisíveis; aviso do total visível; salvar envia `balanca_kg, perdas, feriado`.
- [ ] **Step 2:** rodar → FAIL.
- [ ] **Step 3:** implementar: `lerRelatorioColado` usa `MovimentoCaixa.lerMovimento`; campo Balança (kg, aceita vírgula — NÃO `type=number`); 5 perdas; botão "dia útil / feriado"; quadro da conta (com peso de cada item do Relatório e perdas em R$); avisos de `avisosMovimento` no `checarConferenciaCaixaAntesDeSalvar`; `#real-porc-block` e `#real-obs` com `hidden`.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** commit `feat: tela Dia igual ao texto do movimento, com balanca e bebidas`.

### Task 4: Relatórios (impressão, Planilha, WhatsApp)

**Files:**
- Modify: `public/index.html` `imprimirDia` (~5133); `server.js` resumo/planilha mensal (~3413-3600), CSV/HTML (~5284-5600), mensagem do dia (~4106)
- Test: `test/relatorios-conferencias.test.js` (novos casos)

- [ ] **Step 1: testes que falham**: mensagem do dia 08/11 contém "Balança: 70,402 kg", "Bebidas e derivados: R$ 830,98" e as 5 perdas; Planilha do mês tem colunas Balança (kg), Bebidas, e uma por perda, com totais; dia sem balança mostra "—".
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** implementar (bebidas calculada a partir de `balanca_kg`/`preco_kg` salvos).
- [ ] **Step 4:** → PASS; `npm test` inteiro verde.
- [ ] **Step 5:** commit `feat: balanca, bebidas e perdas nos relatorios do dia e do mes`.

### Task 5: Versão + conferência dos dias antigos (só leitura)

**Files:**
- Modify: selo de versão para v127 (onde o v126 aparece em `public/index.html`/`server.js`)
- Create: `scripts/conferir-despesas-de-peso.mjs` (só GET: lista dias com despesa cujo texto é peso e contas geradas por elas; não grava nada)

- [ ] **Step 1:** bump v127; `npm test` verde.
- [ ] **Step 2:** commit `chore: versao v127 (fechamento com balanca)`.
- [ ] **Step 3:** pacote de subida para o Rubens: migração (com conferência depois), push, e o script de conferência para rodar após publicar.
