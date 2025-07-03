require('dotenv').config();
const express = require('express');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const port = process.env.PORT || 4000;

app.use(express.json());

let tarefas = [];

// Simulando um usuário cadastrado com senha criptografada
const usuarios = [
  {
    id: 1,
    email: 'usuario@exemplo.com',
    senha: bcrypt.hashSync('123456', 10) // senha: 123456
  }
];

// Carrega o arquivo JSON ao iniciar
fs.readFile('notas.json', 'utf8', (err, data) => {
  if (!err) {
    tarefas = JSON.parse(data);
    console.log('Tarefas carregadas com sucesso.');
  } else {
    console.error('Erro ao ler o arquivo de tarefas:', err);
  }
});

// Middleware de autenticação
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token não informado' });

  jwt.verify(token, process.env.JWT_SECRET, (err, usuario) => {
    if (err) return res.status(403).json({ message: 'Token inválido ou expirado' });

    req.usuario = usuario;
    next();
  });
}

// Rota para login e geração do token
app.post('/login', (req, res) => {
  const { email, senha } = req.body;
  const usuario = usuarios.find(u => u.email === email);

  if (!usuario || !bcrypt.compareSync(senha, usuario.senha)) {
    return res.status(401).json({ message: 'Credenciais inválidas' });
  }
  
  const token = jwt.sign(
    { id: usuario.id, email: usuario.email },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );

  res.json({ token });
});

// Rotas protegidas com JWT
app.get('/tarefas', autenticarToken, (req, res) => {
  res.json(tarefas);
});

app.get('/tarefas/vendas', autenticarToken, (req, res) => {
  res.json(tarefas);
});

app.get('/tarefas/:index', autenticarToken, (req, res) => {
  const { index } = req.params;
  const tarefa = tarefas[index];
  tarefa ? res.json(tarefa) : res.status(404).json({ message: 'Tarefa não encontrada' });
});

app.post('/tarefas', autenticarToken, (req, res) => {
  const { tipo, titulo, tituloResumido, peso, periodo } = req.body;
  const novaTarefa = { tipo, titulo, tituloResumido, peso, periodo };
  tarefas.push(novaTarefa);
  res.status(201).json(tarefas);
});

app.put('/tarefas/:index', autenticarToken, (req, res) => {
  const { index } = req.params;
  const { tipo, titulo, tituloResumido, peso, periodo } = req.body;
  if (tarefas[index]) {
    tarefas[index] = { tipo, titulo, tituloResumido, peso, periodo };
    res.json(tarefas[index]);
  } else {
    res.status(404).json({ message: 'Tarefa não encontrada' });
  }
});

app.delete('/tarefas/:index', autenticarToken, (req, res) => {
  const { index } = req.params;
  if (tarefas[index]) {
    const tarefaRemovida = tarefas.splice(index, 1);
    res.json(tarefaRemovida);
  } else {
    res.status(404).json({ message: 'Tarefa não encontrada' });
  }
});

// Iniciar o servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
