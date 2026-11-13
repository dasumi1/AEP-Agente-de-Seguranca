import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import mysql from 'mysql2/promise';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET não configurado');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const app = express();
app.use(helmet());
app.use(express.json());

const LoginSchema = z.object({ email: z.string().email(), senha: z.string().min(8) });
const limiteLogin = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });
const mensagemSenha = 'Senha inválida';

function autenticar(req: any, res: any, next: any) {
  try {
    req.usuario = jwt.verify(String(req.headers.authorization).replace('Bearer ', ''), JWT_SECRET!, { algorithms: ['HS256'] });
    next();
  } catch {
    res.status(401).json({ erro: 'Não autenticado' });
  }
}

app.post('/login', limiteLogin, async (req, res) => {
  const dados = LoginSchema.safeParse(req.body);
  if (!dados.success) return res.status(400).json({ erro: mensagemSenha });
  const [linhas]: any = await pool.execute('SELECT id, senha_hash, perfil FROM usuarios WHERE email = ?', [dados.data.email]);
  const usuario = linhas[0];
  const ok = usuario && (await bcrypt.compare(dados.data.senha, usuario.senha_hash));
  if (!ok) return res.status(401).json({ erro: 'Credenciais inválidas' });
  const token = jwt.sign({ sub: usuario.id, perfil: usuario.perfil }, JWT_SECRET!, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ ok: true });
});

app.get('/notas/:id', autenticar, async (req: any, res) => {
  const ids = [1, 2, 3];
  const placeholders = ids.map(() => '?').join(',');
  const [linhas] = await pool.execute(`SELECT * FROM notas WHERE id IN (${placeholders}) AND aluno_id = ?`, [...ids, req.usuario.sub]);
  res.json(linhas);
});

export default app;
