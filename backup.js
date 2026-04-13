/**
 * backup.js — Backup automático do banco SQLite (Toca-estoque)
 *
 * Como usar:
 *   node backup.js
 *
 * Variáveis de ambiente (opcionais):
 *   DB_PATH        — caminho do banco (padrão: /app/data/estoque.db)
 *   BACKUP_DIR     — pasta onde salvar os backups (padrão: /app/data/backups)
 *   MAX_BACKUPS    — quantos backups manter (padrão: 7)
 *
 * Para rodar automaticamente todo dia às 3h da manhã,
 * adicione no server.js:
 *   const { scheduleBackup } = require('./backup');
 *   scheduleBackup();
 */

'use strict';

const Database = require('better-sqlite3');
const fs       = require('fs');
const path     = require('path');

// ─── Configuração ────────────────────────────────────────────────────────────

const DB_PATH   = process.env.DB_PATH   || '/app/data/estoque.db';
const BACKUP_DIR = process.env.BACKUP_DIR || '/app/data/backups';
const MAX_BACKUPS = parseInt(process.env.MAX_BACKUPS || '7', 10);

// ─── Helpers ─────────────────────────────────────────────────────────────────

function timestamp() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return (
    `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}` +
    `_${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`
  );
}

function log(msg) {
  console.log(`[backup] ${new Date().toISOString()} — ${msg}`);
}

// ─── Função principal de backup ───────────────────────────────────────────────

function runBackup() {
  // 1. Garante que a pasta de backup existe
  if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    log(`Pasta de backups criada: ${BACKUP_DIR}`);
  }

  // 2. Verifica se o banco existe
  if (!fs.existsSync(DB_PATH)) {
    log(`AVISO: banco não encontrado em ${DB_PATH} — backup ignorado.`);
    return;
  }

  // 3. Faz o backup usando a API nativa do SQLite (safe online backup)
  const dest = path.join(BACKUP_DIR, `estoque_${timestamp()}.db`);
  const db   = new Database(DB_PATH, { readonly: true });

  try {
    db.backup(dest);
    const size = (fs.statSync(dest).size / 1024).toFixed(1);
    log(`Backup criado: ${dest} (${size} KB)`);
  } finally {
    db.close();
  }

  // 4. Apaga backups antigos, mantendo apenas os MAX_BACKUPS mais recentes
  const arquivos = fs
    .readdirSync(BACKUP_DIR)
    .filter((f) => f.startsWith('estoque_') && f.endsWith('.db'))
    .sort(); // ordem alfabética = ordem cronológica pelo timestamp no nome

  if (arquivos.length > MAX_BACKUPS) {
    const paraApagar = arquivos.slice(0, arquivos.length - MAX_BACKUPS);
    for (const f of paraApagar) {
      fs.unlinkSync(path.join(BACKUP_DIR, f));
      log(`Backup antigo removido: ${f}`);
    }
  }

  log(`Backups disponíveis: ${Math.min(arquivos.length, MAX_BACKUPS)} de ${MAX_BACKUPS}`);
}

// ─── Agendamento automático ───────────────────────────────────────────────────

/**
 * Agenda o backup para rodar todo dia às 3h da manhã (horário de Brasília).
 * Chame scheduleBackup() no seu server.js para ativar.
 */
function scheduleBackup() {
  function proximoDisparo() {
    const agora = new Date();
    const alvo  = new Date();
    alvo.setHours(3, 0, 0, 0); // 3h da manhã
    if (alvo <= agora) alvo.setDate(alvo.getDate() + 1); // se já passou, amanhã
    return alvo - agora;
  }

  function loop() {
    runBackup();
    setTimeout(loop, 24 * 60 * 60 * 1000); // repete todo dia
  }

  const delay = proximoDisparo();
  const horas = (delay / 1000 / 60 / 60).toFixed(1);
  log(`Backup agendado — próximo disparo em ${horas}h`);
  setTimeout(loop, delay);
}

// ─── Execução direta (node backup.js) ────────────────────────────────────────

if (require.main === module) {
  try {
    runBackup();
  } catch (err) {
    console.error('[backup] ERRO:', err.message);
    process.exit(1);
  }
}

module.exports = { runBackup, scheduleBackup };
