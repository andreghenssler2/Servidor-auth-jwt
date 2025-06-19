// Andre, Andrei , Luciano
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

dotenv.config(); // Carregar variáveis ​​de ambiente


const app = express(); // Crie um aplicativo expresso
const PORT = process.env.PORT || 3000; // Defina a porta para o servidor
const JWT_SECRET = process.env.JWT_SECRET; // Chave secreta para JWT

app.use(helmet()); // Adiciona headers de segurança
app.use(cors());   // Protege contra alguns ataques de CORS
app.use(express.json());

// Limitação de requisições
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 5 // máximo de 5 requisições por minuto por IP
  , message: 'Muitas solicitações, tente novamente mais tarde.'
});
app.use(limiter);

// Simulando um usuário cadastrado com senha criptografada
const usuarios = [
  {
    id: 1,
    email: 'usuario@exemplo.com',
    senha: bcrypt.hashSync('123456', 10) // Senha criptografada
  }
];


// Rota de login
app.post('/login', (req, res) => {
  const { email, senha } = req.body;

  // Verifica se o usuário existe
  const usuario = usuarios.find(u => u.email === email);
  if (!usuario) {
    return res.status(401).json({ message: 'Usuário ou senha inválidos.' });
  }

  // Verifica a senha
  const senhaValida = bcrypt.compareSync(senha, usuario.senha);
  if (!senhaValida) {
    return res.status(401).json({ message: 'Usuário ou senha inválidos.' });
  }
  // Gera o token JWT
  const token = jwt.sign({ id: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  if (!token) return res.status(401).json({ erro: 'Token não enviado' });

  jwt.verify(token, JWT_SECRET, (err, usuario) => {
    if (err) return res.status(403).json({ erro: 'Token inválido ou expirado' });
    req.usuario = usuario;
    next();
  });
}
app.get('/protegido', autenticarToken, (req, res) => {
  res.json({ mensagem: `Bem-vindo, usuário ${req.usuario.email}!`, dados: req.usuario });
});

app.post('/reauth', autenticarToken, (req, res) => {
  const { id, email } = req.usuario;
  const novoToken = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token: novoToken });
});

// Boas práticas: resposta para rota não encontrada
app.use((req, res) => {
  res.status(404).json({ erro: 'Rota não encontrada' });
});

app.listen(PORT, () => {
  console.log(`API segura rodando na porta https://localhost:${PORT}`);
});