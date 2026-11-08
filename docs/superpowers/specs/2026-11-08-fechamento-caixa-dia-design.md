# Fechamento de caixa na tela Dia: texto igual ao relatório + conta da balança

Data: 08/11/2026 · Pedido do Rubens · App: toca-estoque-fix (tela "Dia" = Realidade do Dia)

## Por quê

Todo fim de dia o Rubens escreve o movimento num texto (modelo abaixo) e cola na tela Dia.
O que fica salvo e o que sai nos relatórios tem que ser **exatamente** o que está no texto.
Hoje o leitor erra a parte final e falta a conta que ele mais quer: quanto do dia foi
**bebida e derivados**, descontando da venda a comida pesada na balança.

Teste com o texto real de 08/11/2026 (leitor atual, sem salvar):
- lixo do buffet **não entra** (texto usa "KG 2,890", leitor só entende "2,890 KG");
- "FRITURA KG 1,750" e "DOAÇÃO/CORTE KG 2,750" viram **despesa de R$ 1,75 e R$ 2,75**.
  Como despesa do caixa é lançada nas Contas, isso pode ter criado contas falsas em dias antigos;
- só existe 1 campo de peso; o texto tem 5;
- soma das formas R$ 6.468,07 × TOTAL escrito R$ 6.358,07 (diferença R$ 110,00) — o app já avisa.

## Modelo do texto (fonte da verdade)

```
MOVIMENTO
08/11/2026
DOMINGO
150 PRATOS VENDIDOS
CRED STONE: R$ 123,83
DEB STONE:  R$
VOUCHER STONE: R$ 729,21
PIX : R$
CRED PAG BANK:R$ 1.580,72
DEB PAG BANK: R$ 2.127,03
PIX PAG BANK:R$ 988,49
DINHEIRO: 918,79
TOTAL VENDIDO: R$ 6.358,07
BALANÇA: 70,402 KG            <- linha NOVA a partir de 08/11/2026
__RELATÓRIO__
02 ERRO/TARA/CANC R$ 90,17
05 PATRÕES R$  248,98
06 FUNCIONARIO R$ 359,24
__DESPESA DO DIA__
PAO - 8,00
PASSAGEM VILMA R$ 11,20
...
__LIXO FINAL BUFFET__
LIXO FINAL BUFFET  KG 2,890
LIXO SALADA        KGB 6,200
DESPERDICIO        KG ----
FRITURA           KG 1,750
DOAÇÃO/CORTE       KG 2,750
```

## O que o Rubens decidiu

1. A tela Dia mostra **só o que está no texto**, na mesma ordem. Porcionamento e Observação
   saem da tela (dados antigos ficam no banco, só escondidos).
2. Recebimentos: Cred/Deb/Voucher/Pix Stone, Cred/Deb/Pix PagBank, Dinheiro. Linha vazia = 0.
3. Relatório (erro/tara/canc, patrões, funcionário): quantidade + valor. **Foi pesado na balança
   e não foi pago.**
4. Despesa do dia: cada linha com o nome escrito.
5. Lixo: 5 pesos em kg — lixo final buffet, lixo salada, desperdício, fritura, doação/corte.
   É **perda**: NÃO passa pela balança de venda, NÃO é dinheiro, NÃO entra na conta das bebidas.
   Serve para saber quanto está perdendo.
6. Balança: total pesado do dia em kg, lançado junto a partir de hoje.
7. Preço do quilo: **R$ 64,99 de segunda a sexta; R$ 89,99 sábado, domingo e feriado.**
8. Conta das bebidas:
   - comida pesada = kg da balança × preço do quilo do dia
   - comida vendida = comida pesada − soma do Relatório (R$)
   - **bebidas e derivados = total vendido − comida vendida**
   - exemplo 08/11 (domingo): 70,402 × 89,99 = 6.335,48; − 698,39 = 5.637,09; 6.468,07 − 5.637,09 = **830,98**
9. Tudo aparece na impressão do dia, na Planilha do mês e na mensagem do dia no WhatsApp.

## Objetivos

- Colar o texto → tela preenchida 100% certa, centavo por centavo e grama por grama.
- Ver na hora a conta: comida pesada, relatório, comida vendida, total, **bebidas**.
- Avisar antes de salvar quando algo não fecha.

## Fora do escopo

- Ler o relatório da balança por foto/arquivo (por enquanto ele digita a linha BALANÇA).
- Mudar o que já é salvo nas Contas além de **parar** de criar despesa a partir de peso.
- Corrigir dias antigos sozinho (ver "Dias antigos").

## O que seria fracasso mesmo funcionando

- Peso virar dinheiro em qualquer lugar (despesa, conta, venda).
- Conta das bebidas usar o preço errado do dia (dia útil × fim de semana/feriado).
- Relatórios antigos mudarem de valor ou quebrarem.
- Salvar em silêncio um dia que não fecha.

## Avisos (antes de salvar, com "salvar mesmo assim?")

- TOTAL escrito ≠ soma das formas (já existe; mostrar a diferença).
- Bebidas negativa.
- Bebidas fora do normal: abaixo de metade ou acima do dobro da média dos últimos 14 dias com balança.
- Linha BALANÇA ausente em dia a partir de 08/11/2026.
- Linha com número que o leitor não soube onde pôr: mostrar a linha (nunca jogar em despesa no chute).

## Decisões minhas (o Rubens pode trocar)

- **Feriado**: o app já marca sozinho os feriados nacionais e os do estado do RJ; na tela aparece
  "Preço do quilo: R$ 89,99 (domingo)" com um botão para trocar dia útil/feriado no dia
  (ex.: feriado municipal de São Gonçalo). A palavra FERIADO no texto também marca.
- **Preço com histórico**: os dois preços ficam salvos no app com data de início; mudar o preço
  não altera dias passados. Admin troca.
- **Perdas em R$**: além dos kg, mostrar quanto as perdas valem pelo preço do quilo do dia
  ("as perdas de hoje = R$ X"). Só informação, fora de qualquer soma.
- **Peso de cada item do Relatório**: mostrar ao lado (R$ ÷ preço do quilo), só informação.
- **Banco**: campos novos em `fechamentos_diarios`, migração só ADITIVA:
  `balanca_kg numeric`, `preco_kg numeric` (o preço usado naquele dia, congelado),
  `perdas jsonb` (os 5 pesos em gramas), `feriado boolean`. `lixo_buffet_g` continua recebendo o
  "lixo final buffet" para relatórios antigos. Bebidas é calculado, não salvo.
- **Leitor**: seções pelo título (`__RELATÓRIO__`, `__DESPESA DO DIA__`, `__LIXO FINAL BUFFET__`);
  dentro de LIXO, tudo é peso ("KG 2,890", "2,890 KG", "KGB 6,200", "----" = vazio).
  Mesma lógica no servidor (lançamento pelo WhatsApp/IA) e na tela — um leitor só, testado.

## Dias antigos

Depois de publicado, rodar uma conferência **só leitura** em todos os dias salvos procurando
despesas que eram peso (FRITURA, DOAÇÃO, DESPERDÍCIO, LIXO, "KG") e contas geradas por elas.
Mostrar a lista ao Rubens; corrigir só com "pode", item por item.

## Teste (antes do Rubens publicar)

- O texto de 08/11 e os txt de `Desktop/fechamento/<mês>/` lidos pelo leitor novo: cada número
  confere com o texto; nenhuma despesa de peso.
- Conta das bebidas: 08/11 = R$ 830,98; um dia útil com 64,99; um feriado.
- Avisos disparam nos casos acima e não disparam no dia que fecha.
- Impressão, Planilha e WhatsApp mostram balança, bebidas e perdas; dia antigo sem balança
  continua igual.
- `npm test` verde + teste de tela (Playwright) colando o texto.
- Selo de versão sobe (v127). Publicação e migração: o Rubens roda.
