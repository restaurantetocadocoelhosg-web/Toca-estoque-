# 🐰 Toca do Coelho — Sistema de Estoque v2

## Melhorias incluídas nesta versão
- Login com senha
- Perfis de acesso: administrador, gerente e operador
- Travamento do reset do estoque com confirmação forte
- Validação para impedir saída/perda maior que o estoque
- Registro automático do responsável logado
- Auditoria básica de ações sensíveis
- Exportação CSV protegida por login

## Login inicial
- Usuário: `admin`
- Senha: `Toca123!`

Troque a senha logo no primeiro acesso.

---

## Como colocar no Railway
1. Suba o projeto no Railway pelo GitHub.
2. Em **Volumes**, adicione um volume em `/app/data`
3. Em **Variables**, crie:
   - `DB_PATH=/app/data/estoque.db`
4. Faça novo deploy.
5. Gere o domínio público em **Settings > Networking > Generate Domain**.

---

## Perfis
- **Administrador**: acesso total, inclusive resetar estoque.
- **Gerente**: pode operar e editar produtos, sem reset geral.
- **Operador**: pode lançar movimentações e consultar relatórios.

---

## Observações
- As sessões expiram quando o servidor reinicia. Nesse caso basta entrar novamente.
- O responsável das movimentações agora é sempre o usuário logado.
- O botão de reset só aparece para administrador.

---

## Estrutura
- `server.js` — backend e regras de segurança
- `public/index.html` — interface
- `produtos_seed.json` — base inicial
- `railway.toml` — deploy Railway
