require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Client, Databases, ID, Query } = require('node-appwrite');

const app = express();
app.use(express.json());

const DEV_MODE = process.env.DEV_MODE === 'true';
app.use(cors({ origin: '*', credentials: true }));

const {
  PORT = 3000,
  APPWRITE_ENDPOINT,
  APPWRITE_PROJECT_ID,
  APPWRITE_API_KEY,
  APPWRITE_DB_ID,
  APPWRITE_ADMINS_COLLECTION_ID,
  APPWRITE_2FA_COLLECTION_ID
} = process.env;

let databases;
(function initAppwrite(){
  try {
    const client = new Client()
      .setEndpoint(APPWRITE_ENDPOINT)
      .setProject(APPWRITE_PROJECT_ID)
      .setKey(APPWRITE_API_KEY);
    databases = new Databases(client);
    console.log('Appwrite client OK');
  } catch (e) {
    console.error('Failed to init Appwrite:', e);
  }
})();

app.get('/health', (_req, res)=> {
  res.json({ ok: true, service: 'backend-2fa-online', time: new Date().toISOString() });
});

if (DEV_MODE) {
  app.get('/debug/env', (_req, res)=> {
    res.json({
      DEV_MODE,
      APPWRITE_ENDPOINT: !!APPWRITE_ENDPOINT,
      APPWRITE_PROJECT_ID: !!APPWRITE_PROJECT_ID,
      APPWRITE_API_KEY: !!APPWRITE_API_KEY,
      APPWRITE_DB_ID: !!APPWRITE_DB_ID,
      APPWRITE_ADMINS_COLLECTION_ID: !!APPWRITE_ADMINS_COLLECTION_ID,
      APPWRITE_2FA_COLLECTION_ID: !!APPWRITE_2FA_COLLECTION_ID
    });
  });

  app.get('/debug/form', (_req, res)=> {
    res.set('Content-Type', 'text/html; charset=utf-8').send(`
<!doctype html><html><head><meta charset="utf-8"><title>Admin Test</title></head>
<body style="font-family:sans-serif;max-width:720px;margin:40px auto;">
<h1>Teste de Login Admin</h1>
<label>Email: <input id="email" value=""></label><br><br>
<label>Senha: <input id="senha" type="password" value=""></label><br><br>
<button onclick="login()">Login /admin/login</button>
<pre id="loginOut"></pre>
<hr>
<h2>Verificar 2FA</h2>
<label>code_id: <input id="code_id" value=""></label><br><br>
<label>code: <input id="code" value=""></label><br><br>
<button onclick="verify()">Verify /admin/verify-2fa</button>
<pre id="verifyOut"></pre>
<script>
async function login(){
  const email = document.getElementById('email').value.trim();
  const senha = document.getElementById('senha').value;
  const out = document.getElementById('loginOut');
  out.textContent = '...';
  const r = await fetch('/admin/login', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ email, senha })
  });
  const j = await r.json();
  out.textContent = JSON.stringify(j, null, 2);
  if (j.code_id && j.code_dev) {
    document.getElementById('code_id').value = j.code_id;
    document.getElementById('code').value = j.code_dev;
  }
}
async function verify(){
  const code_id = document.getElementById('code_id').value.trim();
  const code = document.getElementById('code').value.trim();
  const out = document.getElementById('verifyOut');
  out.textContent = '...';
  const r = await fetch('/admin/verify-2fa', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ code_id, code })
  });
  out.textContent = JSON.stringify(await r.json(), null, 2);
}
</script>
</body></html>`);
  });
}

function sixDigits(){ return String(Math.floor(100000 + Math.random()*900000)); }

app.post('/admin/login', async (req, res)=> {
  try {
    const { email, senha } = req.body || {};
    if (!email || !senha) return res.status(400).json({ success:false, message:'Email e senha são obrigatórios' });

    const docs = await databases.listDocuments(APPWRITE_DB_ID, APPWRITE_ADMINS_COLLECTION_ID, [
      Query.equal('email', email)
    ]);
    if (!docs.total) return res.status(401).json({ success:false, message:'Admin não encontrado' });
    const admin = docs.documents[0];

    const ok = admin.senha_hash && bcrypt.compareSync(senha, admin.senha_hash);
    if (!ok) return res.status(401).json({ success:false, message:'Senha incorreta' });

    const code = sixDigits();
    const code_hash = bcrypt.hashSync(code, 10);
    const expiresAt = new Date(Date.now() + 5*60*1000).toISOString();

    // 🔴 Ajuste: incluir também o campo "code" porque a collection exige esse atributo
    const created = await databases.createDocument(APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, ID.unique(), {
      admin_id: admin.$id,
      email,
      code,        // <— campo exigido pela collection
      code_hash,
      expires_at: expiresAt,
      used: false
    });

    const payload = {
      success: true,
      message: 'Login OK. Código enviado.',
      code_id: created.$id,
      expires_at: expiresAt
    };
    if (DEV_MODE) payload.code_dev = code;

    return res.json(payload);
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success:false, message:'Erro interno no login' });
  }
});

app.post('/admin/verify-2fa', async (req, res)=> {
  try {
    const { code_id, code } = req.body || {};
    if (!code_id || !code) return res.status(400).json({ success:false, message:'code_id e code são obrigatórios' });

    const doc = await databases.getDocument(APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, code_id);
    if (doc.used) return res.status(400).json({ success:false, message:'Código já usado' });
    if (new Date(doc.expires_at).getTime() < Date.now())
      return res.status(400).json({ success:false, message:'Código expirado' });

    const ok = bcrypt.compareSync(code, doc.code_hash);
    if (!ok) return res.status(401).json({ success:false, message:'Código inválido' });

    await databases.updateDocument(APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, code_id, { used: true });

    return res.json({ success:true, message:'2FA verificada' });
  } catch (err) {
    console.error('Verify error:', err);
    return res.status(500).json({ success:false, message:'Erro interno na verificação' });
  }
});

app.listen(PORT, ()=> console.log(`Server listening on :${PORT}`));
