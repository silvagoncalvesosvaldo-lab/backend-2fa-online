require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Client, Databases, ID } = require('node-appwrite');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Variáveis de ambiente
const {
  DEV_MODE,
  APPWRITE_ENDPOINT,
  APPWRITE_PROJECT_ID,
  APPWRITE_API_KEY,
  APPWRITE_DB_ID,
  APPWRITE_2FA_COLLECTION_ID
} = process.env;

// Inicialização do Appwrite
let appwriteClient = null;
let appwriteDB = null;

if (APPWRITE_ENDPOINT && APPWRITE_PROJECT_ID && APPWRITE_API_KEY && APPWRITE_DB_ID && APPWRITE_2FA_COLLECTION_ID) {
  try {
    appwriteClient = new Client()
      .setEndpoint(APPWRITE_ENDPOINT)
      .setProject(APPWRITE_PROJECT_ID)
      .setKey(APPWRITE_API_KEY);

    appwriteDB = new Databases(appwriteClient);
    console.log('Appwrite inicializado com sucesso.');
  } catch (err) {
    console.warn('Falha ao inicializar Appwrite:', err.message);
  }
} else {
  console.warn('Variáveis de ambiente do Appwrite incompletas. Appwrite não será inicializado.');
}

// Rota de saúde
app.get('/health', (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// Rota de depuração (ANTES do listen)
app.get('/debug/env', (req, res) => {
  if (DEV_MODE !== 'true') return res.status(404).end();

  const maskValue = (val) => {
    if (!val) return null;
    if (val.length <= 3) return '***';
    return '***' + val.slice(-3);
  };

  res.json({
    DEV_MODE,
    APPWRITE_ENDPOINT: !!APPWRITE_ENDPOINT,
    APPWRITE_PROJECT_ID: maskValue(APPWRITE_PROJECT_ID),
    APPWRITE_API_KEY: maskValue(APPWRITE_API_KEY),
    APPWRITE_DB_ID: maskValue(APPWRITE_DB_ID),
    APPWRITE_2FA_COLLECTION_ID: maskValue(APPWRITE_2FA_COLLECTION_ID)
  });
});

// Login admin (DEV)
app.post('/admin/login', async (req, res) => {
  const { email, senha } = req.body || {};
  if (typeof email !== 'string' || typeof senha !== 'string') {
    return res.status(400).json({ success: false, message: 'Parâmetros inválidos' });
  }

  if (DEV_MODE === 'true') {
    const code = '123456';
    const expiresInSec = 300;
    const expiresAtISO = new Date(Date.now() + expiresInSec * 1000).toISOString();

    try {
      if (appwriteDB) {
        await appwriteDB.createDocument(
          APPWRITE_DB_ID,
          APPWRITE_2FA_COLLECTION_ID,
          ID.unique(),
          { email, code, expiresAt: expiresAtISO }
        );
      } else {
        console.warn('Appwrite não configurado. Código não armazenado.');
      }
    } catch (err) {
      console.warn('Falha ao salvar código no Appwrite:', err.message);
    }

    return res.status(200).json({
      success: true,
      message: 'DEV MODE: código gerado',
      code_dev: code,
      expiresInSec
    });
  }

  res.status(501).json({ success: false, message: 'Implementação de produção pendente' });
});

// Verificação 2FA (DEV)
app.post('/admin/verify-2fa', (req, res) => {
  const { email, code } = req.body || {};
  if (typeof email !== 'string' || typeof code !== 'string') {
    return res.status(400).json({ success: false, message: 'Parâmetros inválidos' });
  }

  if (DEV_MODE === 'true') {
    if (code === '123456') {
      return res.json({ success: true, message: 'Código válido (DEV)' });
    }
    return res.status(400).json({ success: false, message: 'Código inválido (DEV)' });
  }

  res.status(501).json({ success: false, message: 'Implementação de produção pendente' });
});

// Start
app.listen(PORT, () => {
  console.log(`Servidor ouvindo na porta ${PORT} (DEV_MODE=${process.env.DEV_MODE})`);
});
