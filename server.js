// server.js — Backend 2FA (Appwrite + Z-API) — CommonJS

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Client, Databases, ID, Query } = require('node-appwrite');

// =========================
//  App
// =========================
const app = express();
app.use(cors());
app.use(express.json());

// =========================
//  ENV (Render -> Environment)
// =========================
const {
  PORT = 3000,

  // Appwrite
  APPWRITE_ENDPOINT,
  APPWRITE_PROJECT_ID,
  APPWRITE_API_KEY,
  APPWRITE_DB_ID,
  APPWRITE_ADMINS_COLLECTION_ID,   // collection: admins
  APPWRITE_2FA_COLLECTION_ID,      // collection: admin_2fa_codes

  // Z-API (WhatsApp)
  ZAPI_INSTANCE_ID,
  ZAPI_TOKEN,
  ADMIN_WHATSAPP,                  // ex: 5543999533321
} = process.env;

// =========================
//  Appwrite Client
// =========================
const client = new Client()
  .setEndpoint(APPWRITE_ENDPOINT)
  .setProject(APPWRITE_PROJECT_ID)
  .setKey(APPWRITE_API_KEY);

const db = new Databases(client);

// =========================
function gerarCodigo() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function enviarWhatsAppZAPI(phone, message) {
  // Node 20 tem fetch global
  const url = `https://api.z-api.io/instances/${ZAPI_INSTANCE_ID}/token/${ZAPI_TOKEN}/send-text`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phone, message }),
  });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`Falha ao enviar WhatsApp: ${res.status} ${txt}`);
  }
  return await res.json();
}

async function salvarCodigo2FA(email, code, minutos = 10) {
  const expiresAt = new Date(Date.now() + minutos * 60 * 1000).toISOString();
  const payload = {
    email,
    code,
    used: false,
    expiresAt,
    createdAt: new Date().toISOString(),
  };
  await db.createDocument(
    APPWRITE_DB_ID,
    APPWRITE_2FA_COLLECTION_ID,
    ID.unique(),
    payload
  );
  return { code, expiresAt };
}

async function buscarUltimoCodigo(email) {
  const result = await db.listDocuments(
    APPWRITE_DB_ID,
    APPWRITE_2FA_COLLECTION_ID,
    [Query.equal('email', email), Query.orderDesc('$createdAt'), Query.limit(1)]
  );
  return result.documents?.[0] || null;
}

async function marcarCodigoComoUsado(documentId) {
  await db.updateDocument(
    APPWRITE_DB_ID,
    APPWRITE_2FA_COLLECTION_ID,
    documentId,
    { used: true }
  );
}

async function buscarAdminPorEmail(email) {
  const result = await db.listDocuments(
    APPWRITE_DB_ID,
    APPWRITE_ADMINS_COLLECTION_ID,
    [Query.equal('email', email), Query.limit(1)]
  );
  return result.documents?.[0] || null;
}

// =========================
//  Rotas
// =========================
app.get('/', (_req, res) => {
  res.send('OK - login-admin-2fa (Appwrite only)');
});

// Login: confere admin e envia código por WhatsApp
app.post('/admin/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) {
      return res.status(400).json({ success: false, message: 'E-mail e senha são obrigatórios.' });
    }

    const admin = await buscarAdminPorEmail(email);
    if (!admin) return res.status(401).json({ success: false, message: 'Admin não encontrado.' });

    const ok = await bcrypt.compare(senha, admin.senha_hash);
    if (!ok) return res.status(401).json({ success: false, message: 'Senha incorreta.' });

    const code = gerarCodigo();
    const { expiresAt } = await salvarCodigo2FA(email, code, 10);

    const message = `Seu código de verificação (2FA) é: ${code}. Validade: 10 minutos.`;
    await enviarWhatsAppZAPI(ADMIN_WHATSAPP, message);

    return res.json({
      success: true,
      message: 'Código enviado por WhatsApp.',
      next: '/verificar-codigo',
      email,
      expiresAt,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Erro interno no login.' });
  }
});

// Verificar código 2FA
app.post('/admin/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ success: false, message: 'E-mail e código são obrigatórios.' });
    }

    const doc = await buscarUltimoCodigo(email);
    if (!doc) return res.status(401).json({ success: false, message: 'Código não encontrado.' });

    const agora = new Date();
    const expira = new Date(doc.expiresAt);

    if (doc.used) return res.status(401).json({ success: false, message: 'Código já utilizado.' });
    if (agora > expira) return res.status(401).json({ success: false, message: 'Código expirado.' });
    if (String(code).trim() !== String(doc.code).trim()) {
      return res.status(401).json({ success: false, message: 'Código inválido.' });
    }

    await marcarCodigoComoUsado(doc.$id);
    return res.json({ success: true, message: 'Verificação concluída. Acesso liberado.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Erro interno na verificação do código.' });
  }
});

// =========================
app.listen(PORT, () => {
  console.log(`Backend 2FA rodando na porta ${PORT}`);
});
