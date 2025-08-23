// diag-create-code.js — tenta criar 1 doc em admin_2fa_codes e mostra o erro exato
require('dotenv').config();
const { Client, Databases, ID } = require('node-appwrite');

(async () => {
  try {
    const c = new Client()
      .setEndpoint(process.env.APPWRITE_ENDPOINT)
      .setProject(process.env.APPWRITE_PROJECT_ID)
      .setKey(process.env.APPWRITE_API_KEY);

    const db = new Databases(c);

    const payload = { admin_id: 'diag_admin', code: '123456' }; // exatamente o que o backend envia
    const res = await db.createDocument(
      process.env.APPWRITE_DB_ID,
      process.env.CODES_COLL_ID,
      ID.unique(),
      payload
    );

    console.log('OK create:', res.$id, payload);
  } catch (err) {
    const msg = (err && err.response && err.response.message) || err.message || String(err);
    console.error('ERR create:', msg);
  }
})();
