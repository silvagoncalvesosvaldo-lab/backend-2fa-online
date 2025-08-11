import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { Client, Databases, Query } from "node-appwrite";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(cors());
app.use(express.json());
app.use(rateLimit({ windowMs: 60 * 1000, max: 60 }));

// === ENV ===
const {
  // Appwrite
  APPWRITE_ENDPOINT,
  APPWRITE_PROJECT_ID,
  APPWRITE_API_KEY,
  APPWRITE_DB_ID,
  APPWRITE_2FA_COLLECTION_ID,
  // Z-API
  ZAPI_URL,
  ZAPI_TOKEN,
  ZAPI_PHONE
} = process.env;

// Appwrite client (service)
function aw() {
  const client = new Client()
    .setEndpoint(APPWRITE_ENDPOINT)
    .setProject(APPWRITE_PROJECT_ID)
    .setKey(APPWRITE_API_KEY);
  return new Databases(client);
}

app.get("/health", (_, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// Envio manual p/ teste
app.post("/send-code", async (req, res) => {
  try {
    if (!ZAPI_URL || !ZAPI_TOKEN) {
      return res.status(500).json({ success: false, message: "ZAPI_URL/ZAPI_TOKEN ausentes" });
    }
    const phone = String(req.body.phone || ZAPI_PHONE || "").trim();
    const message = String(req.body.message || "").trim() || "Teste via Render + Z-API.";
    if (!phone) return res.status(400).json({ success: false, message: "phone ausente" });

    const r = await fetch(`${ZAPI_URL}/token/${ZAPI_TOKEN}/send-text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, message })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) return res.status(r.status).json({ success: false, details: data });

    res.json({ success: true, delivered: true, zapi: data });
  } catch (e) {
    res.status(500).json({ success: false, message: "Erro interno", error: String(e) });
  }
});

// === 2FA - iniciar ===
app.post("/start-2fa", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ success: false, message: "email ausente" });

    const code = String(Math.floor(100000 + Math.random() * 900000)); // 6 dígitos
    const codeHash = bcrypt.hashSync(code, bcrypt.genSaltSync(12));
    const verifyToken = uuidv4();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    const db = aw();
    await db.createDocument(
      APPWRITE_DB_ID,
      APPWRITE_2FA_COLLECTION_ID,
      "unique()",
      {
        admin_email: email,
        code_hash: codeHash,
        verify_token: verifyToken,
        expires_at: expiresAt,
        used_at: null,
        created_at: new Date().toISOString()
      }
    );

    // tenta enviar via WhatsApp (não falha o fluxo se der erro)
    if (ZAPI_URL && ZAPI_TOKEN && ZAPI_PHONE) {
      try {
        await fetch(`${ZAPI_URL}/token/${ZAPI_TOKEN}/send-text`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            phone: ZAPI_PHONE,
            message: `Seu código de verificação (admin): ${code}\nVálido por 10 minutos.`
          })
        });
      } catch {}
    }

    res.json({ success: true, verify_token: verifyToken });
  } catch (e) {
    res.status(500).json({ success: false, message: "Erro interno", error: String(e) });
  }
});

// === 2FA - verificar ===
app.post("/verify-code", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const code = String(req.body.code || "").trim();
    const verifyToken = String(req.body.verify_token || "").trim();
    if (!email || !code || !verifyToken) {
      return res.status(400).json({ success: false, message: "dados incompletos" });
    }

    const nowIso = new Date().toISOString();
    const db = aw();
    const list = await db.listDocuments(APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, [
      Query.equal("admin_email", email),
      Query.equal("verify_token", verifyToken),
      Query.isNull("used_at"),
      Query.greaterThanEqual("expires_at", nowIso),
      Query.limit(1)
    ]);

    if (!list.total) {
      return res.status(401).json({ success: false, message: "token inválido/expirado" });
    }

    const doc = list.documents[0];
    const ok = bcrypt.compareSync(code, doc.code_hash);
    if (!ok) return res.status(401).json({ success: false, message: "código incorreto" });

    await db.updateDocument(APPWRITE_DB_ID, APPWRITE_2FA_COLLECTION_ID, doc.$id, {
      used_at: new Date().toISOString()
    });

    res.json({ success: true, message: "2FA verificado" });
  } catch (e) {
    res.status(500).json({ success: false, message: "Erro interno", error: String(e) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend 2FA rodando na porta ${PORT}`));
