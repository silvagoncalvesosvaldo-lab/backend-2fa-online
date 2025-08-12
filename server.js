// server.js (produção)
try { require('dotenv').config(); } catch { /* ok no Render */ }

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Client, Databases, ID, Query } = require('node-appwrite');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ==== ENV ====
const {
  DEV_MODE,
  APPWRITE_ENDPOINT,
  APPWRITE_PROJECT_ID,
  APPWRITE_API_KEY,
  APPWRITE_DB_ID,
  APPWRITE_2FA_COLLECTION_ID,
  APPWRITE_ADMINS_COLLECTION_ID,
  ADMIN_WHATSAPP,         // 55DDDNUMERO (sem + e sem espaços)
  ZAPI_INSTANCE_ID,
  ZAPI_TOKEN,
} = process.env;

// ==== Appwrite ====
let databases = null;
if (
  APPWRITE_ENDPOINT && APPWRITE_PROJECT_ID && APPWRITE_API_KEY &&
  APPWRITE_DB_ID && APPWRITE_2FA_COLLECTION_ID && APPWRITE_ADMINS_COLLECTION_ID
) {
  const client = new Client()
    .setEndpoint(APPWRITE_ENDPOINT)
    .setProject(APPWRITE_PROJECT_ID)
    .setKey(APPWRITE_API_KEY);
  databases = new Databases(client);
} else {
  console.warn('Appwrite env incompleto.');
}

// ==== helpers ====
function randCode6() { return String(Math.floor(100000 + Math.random() * 900000)); }

async function checkPassword(plain, stored) {
  if (!stored) return false;
  const isHash = typeof stored === 'string' && stored.startsWith('$2');
  return isHash ? bcrypt.compare(plain, stored) : (plain === stored);
}

async function saveCode(email, code, ttlSec = 300) {
  const expiresAt = new Date(Date.now() + ttlSec * 1000).toISOString();
  try {
    const old = await databases.listDocuments(
      APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID,
      [Query.equal('email', email)]
    );
    for (const d of old.documents) {
      try { await databases.deleteDocument(APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, d.$id); } catch {}
    }
  } catch {}
  return databases.createDocument(
    APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, ID.unique(),
    { email, code, expiresAt }
  );
}

async function validateCode(email, code) {
  const res = await databases.listDocuments(
    APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID,
    [Query.equal('email', email), Query.equal('code', code)]
  );
  if (!res.total) return { ok: false, reason: 'not-found' };
  const doc = res.documents.sort((a,b)=> a.$createdAt < b.$createdAt ? 1 : -1)[0];
  if (new Date(doc.expiresAt).getTime() < Date.now()) return { ok: false, reason: 'expired' };
  try { await databases.deleteDocument(APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, doc.$id); } catch {}
  return { ok: true };
}

async function sendWhatsAppCode(phone, code) {
  if (!ZAPI_INSTANCE_ID || !ZAPI_TOKEN) throw new Error('Z-API não configurada');
  const url = `https://api.z-api.io/instances/${ZAPI_INSTANCE_ID}/token/${ZAPI_TOKEN}/send-text`;
  const body = { phone, message: `Código de login: ${code}` };
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`Z-API falhou (${r.status})`);
}

// ==== rotas ====
app.get('/health', (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// Gera e envia código (WhatsApp quando DEV_MODE=false)
app.post('/admin/login', async (req, res) => {
  try {
    if (!databases) return res.status(500).json({ success:false, message:'Appwrite não configurado' });
    const { email, senha } = req.body || {};
    if (!email || !senha) return res.status(400).json({ success:false, message:'Informe email e senha' });

    const admins = await databases.listDocuments(
      APPWRITE_DB_ID, APPWRITE_ADMINS_COLLECTION_ID, [Query.equal('email', email)]
    );
    if (!admins.total) return res.status(401).json({ success:false, message:'Admin não encontrado' });

    const admin = admins.documents[0];
    const okPass = await checkPassword(senha, admin.senha);
    if (!okPass) return res.status(401).json({ success:false, message:'Senha incorreta' });

    const dev = String(DEV_MODE).toLowerCase() === 'true';
    const code = dev ? '123456' : randCode6();
    await saveCode(email, code, 300);

    if (dev) {
      return res.json({ success:true, message:'DEV MODE: código gerado', code_dev: code, expiresInSec: 300 });
    } else {
      if (!ADMIN_WHATSAPP) return res.status(500).json({ success:false, message:'ADMIN_WHATSAPP não configurado' });
      await sendWhatsAppCode(ADMIN_WHATSAPP, code);
      return res.json({ success:true, message:'Código enviado via WhatsApp' });
    }
  } catch (err) {
    console.error('login err:', err);
    res.status(500).json({ success:false, message:'Erro ao gerar código' });
  }
});

app.post('/admin/verify-2fa', async (req, res) => {
  try {
    if (!databases) return res.status(500).json({ success:false, message:'Appwrite não configurado' });
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ success:false, message:'Informe email e code' });
    const { ok, reason } = await validateCode(email, code);
    if (!ok) return res.status(401).json({ success:false, message: reason==='expired'?'Código expirado':'Código inválido' });
    return res.json({ success:true, message:'Código válido' });
  } catch (err) {
    console.error('verify err:', err);
    res.status(500).json({ success:false, message:'Erro ao validar código' });
  }
});

app.listen(PORT, () => console.log(`OK na porta ${PORT}`));
