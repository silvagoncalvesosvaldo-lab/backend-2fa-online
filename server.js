import express from 'express';
import axios from 'axios';
import cors from 'cors';
import dotenv from 'dotenv';
import morgan from 'morgan';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Rota de teste
app.get('/', (req, res) => {
  res.json({ message: 'Backend 2FA Online funcionando!' });
});

// Exemplo de rota de envio de código 2FA via Z-API
app.post('/enviar-codigo', async (req, res) => {
  const { telefone, codigo } = req.body;
  try {
    const resposta = await axios.post(`${process.env.ZAPI_URL}/send-text`, {
      phone: telefone,
      message: `Seu código de verificação é: ${codigo}`
    }, {
      headers: {
        'client-token': process.env.ZAPI_TOKEN
      }
    });
    res.json({ sucesso: true, resposta: resposta.data });
  } catch (erro) {
    res.status(500).json({ sucesso: false, erro: erro.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
