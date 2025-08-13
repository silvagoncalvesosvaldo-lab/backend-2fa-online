// server.js — Backend 2FA Admin (Appwrite + Express)
// Tipo de módulo: ESM (package.json tem "type": "module")

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import { Client, Databases, Query, ID } from 'node-appwrite';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const {
  DEV_MODE = 'true',
  PORT = 3000,

  // Appwrite
  APPWRITE_ENDPOINT,
  APPWRITE_PROJECT_ID,
  APPWRITE_API_KEY,
  APPWRITE_DB_ID,
  APPWRITE_ADMINS_COLLECTION_ID,      // collection de admins
  APPWRITE_2FA_COLLECTION_ID,         // collection admin_2fa_codes
} = process.env;

// ---------- Appwrite ----------
let db = null;
try {
  const client = new Client()
    .setEndpoint(APPWRITE_ENDPOINT)
    .setProject(APPWRITE_PROJECT_ID)
    .setKey(APPWRITE_API_KEY);

  db = new Databases(client);
  console.log('[Appwrite] Client inicializado.');
} catch (err) {
  console.error('[Appwrite] Falha ao inicializar:', err?.message || err);
}

// ---------- Utils ----------
const isDev = String(DEV_MODE).toLowerCase() === 'true';

function generateCodeSix() {
  // 6 dígitos, preservando zeros à esquerda
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ---------- Health & Debug ----------
app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

app.get('/debug/env', (_req, res) => {
  res.json({
    DEV_MODE: isDev,
    APPWRITE_ENDPOINT: !!APPWRITE_ENDPOINT,
    APPWRITE_PROJECT_ID: !!APPWRITE_PROJECT_ID,
    APPWRITE_API_KEY: !!APPWRITE_API_KEY,
    APPWRITE_DB_ID: !!APPWRITE_DB_ID,
    APPWRITE_ADMINS_COLLECTION_ID: !!APPWRITE_ADMINS_COLLECTION_ID,
    APPWRITE_2FA_COLLECTION_ID: !!APPWRITE_2FA_COLLECTION_ID,
  });
});

// Form simples para testar no navegador
app.get('/debug/form', (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(`
    <h2>Login Admin (DEBUG)</h2>
    <form method="POST" action="/admin/login">
      <input name="email" placeholder="email" />
      <input name="senha" placeholder="senha" type="password" />
      <button>Login</button>
    </form>
    <hr/>
    <h2>Verificar 2FA (DEBUG)</h2>
    <form method="POST" action="/admin/verify-2fa">
      <input name="email" placeholder="email" />
      <input name="code" placeholder="código 6 dígitos" />
      <button>Verificar</button>
    </form>
    <script>
      // envia como JSON
      for (const f of document.querySelectorAll('form')) {
        f.addEventListener('submit', async (e) => {
          e.preventDefault();
          const body = Object.fromEntries(new FormData(f).entries());
          const r = await fetch(f.action, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
          const j = await r.json();
          alert(JSON.stringify(j, null, 2));
        });
      }
    </script>
  `);
});

// ---------- Rotas principais ----------

// POST /admin/login
// 1) Busca admin por email
// 2) Confere senha (bcrypt com campo senha_hash no Appwrite)
// 3) Gera código 2FA, salva em admin_2fa_codes com "code" e "code_hash"
// 4) Se DEV_MODE=true, retorna code_dev para facilitar teste
app.post('/admin/login', async (req, res) => {
  try {
    const { email, senha } = req.body || {};
    if (!email || !senha) {
      return res.status(400).json({ success: false, message: 'Informe email e senha.' });
    }
    if (!db) throw new Error('Appwrite DB não inicializado');

    // Buscar admin
    const admins = await db.listDocuments(APPWRITE_DB_ID, APPWRITE_ADMINS_COLLECTION_ID, [
      Query.equal('email', email),
      Query.limit(1)
    ]);
    if (!admins.total) {
      return res.status(401).json({ success: false, message: 'Admin não encontrado' });
    }
    const admin = admins.documents[0];

    // Conferir senha
    if (!admin.senha_hash) {
      return res.status(500).json({ success: false, message: 'Admin sem senha_hash configurada' });
    }
    const ok = await bcrypt.compare(senha, admin.senha_hash);
    if (!ok) {
      return res.status(401).json({ success: false, message: 'Senha incorreta' });
    }

    // Gerar e salvar o 2FA
    const code = generateCodeSix();
    const code_hash = await bcrypt.hash(code, 10);

    // ⚠️ IMPORTANTE: salvar "code" E "code_hash"
    const payload = {
      admin_id: admin.$id,
      email: admin.email,
      code,           // campo exigido pela collection (para DEV; em prod pode-se remover/criptografar)
      code_hash,      // verificação segura
      created_at: new Date().toISOString(),
      used: false,
    };

    const created = await db.createDocument(
      APPWRITE_DB_ID,
      APPWRITE_2FA_COLLECTION_ID,
      ID.unique(),
      payload
    );

    // Em DEV, retornamos o código para facilitar teste
    const response = { success: true, message: 'Código 2FA gerado e enviado.' };
    if (String(process.env.DEV_MODE).toLowerCase() === 'true') response.code_dev = code;

    res.json(response);
  } catch (err) {
    console.error('Erro /admin/login', err);
    res.status(500).json({ success: false, message: 'Erro interno no login' });
  }
});

// POST /admin/verify-2fa
// Confere último código do admin e marca como usado
app.post('/admin/verify-2fa', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) {
      return res.status(400).json({ success: false, message: 'Informe email e código.' });
    }
    if (!db) throw new Error('Appwrite DB não inicializado');

    // Buscar admin
    const admins = await db.listDocuments(APPWRITE_DB_ID, APPWRITE_ADMINS_COLLECTION_ID, [
      Query.equal('email', email),
      Query.limit(1)
    ]);
    if (!admins.total) {
      return res.status(401).json({ success: false, message: 'Admin não encontrado' });
    }
    const admin = admins.documents[0];

    // Buscar códigos desse admin (pega o mais recente não usado)
    const codes = await db.listDocuments(APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, [
      Query.equal('admin_id', admin.$id),
      Query.equal('used', false),
      Query.orderDesc('$createdAt'),
      Query.limit(1),
    ]);
    if (!codes.total) {
      return res.status(400).json({ success: false, message: 'Nenhum código ativo encontrado' });
    }
    const entry = codes.documents[0];

    // Verificar bcrypt
    const ok = await bcrypt.compare(code, entry.code_hash);
    if (!ok) {
      return res.status(401).json({ success: false, message: 'Código inválido' });
    }

    // Marcar como usado
    await db.updateDocument(APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, entry.$id, { used: true });

    res.json({ success: true, message: '2FA verificado com sucesso' });
  } catch (err) {
    console.error('Erro /admin/verify-2fa', err);
    res.status(500).json({ success: false, message: 'Erro interno na verificação' });
  }
});

// ---------- Start ----------
app.listen(process.env.PORT || 3000, () => {
  console.log(`Servidor rodando na porta ${process.env.PORT || 3000}`);
});
