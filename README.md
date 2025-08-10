# Backend 2FA Admin (Render + Appwrite + Z-API)

Servidor Node/Express para 2FA do admin. Gera código de 6 dígitos, salva no Appwrite e envia via Z-API (WhatsApp).

## Stack
- Node 20 + Express
- Appwrite (Databases)
- Z-API (WhatsApp)
- Hospedagem: Render (Free)

## Endpoints
- `GET /health` → status do serviço
- `POST /start-2fa`  
  Body: `{ "email": "admin@dominio.com" }`  
  Retorno: `{ "success": true, "verify_token": "uuid" }`
- `POST /verify-code`  
  Body: `{ "email": "admin@dominio.com", "code": "123456", "verify_token": "uuid" }`  
  Retorno: `{ "success": true }`
- `POST /send-code` *(opcional p/ teste)*  
  Body: `{ "phone": "55DDDNNNNNNN", "message": "texto" }`

## Variáveis de ambiente (Render → Settings → Environment)
### Appwrite
- `APPWRITE_ENDPOINT` – ex: `https://cloud.appwrite.io/v1`
- `APPWRITE_PROJECT_ID`
- `APPWRITE_API_KEY` – com acesso a Databases
- `APPWRITE_DB_ID`
- `APPWRITE_2FA_COLLECTION_ID` – collection `admin_2fa_codes`

### Z-API
- `ZAPI_URL` – ex: `https://api.z-api.io/instances/SEU_INSTANCE_ID`
- `ZAPI_TOKEN`
- `ZAPI_PHONE` – ex: `5543999533321`

## Rodar local (opcional)
```bash
npm install
node server.js
# http://localhost:3000/health
