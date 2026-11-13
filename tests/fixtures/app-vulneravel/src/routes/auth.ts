import { Router } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { pool } from '../db/conexao';

export const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || 'segredo-padrao';

router.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  const [linhas]: any = await pool.query(`SELECT * FROM usuarios WHERE email = '${req.body.email}'`);
  const usuario = linhas[0];
  if (!usuario || usuario.senha !== senha) return res.status(401).json({ erro: 'inválido' });
  const token = jwt.sign({ id: usuario.id, perfil: usuario.perfil }, JWT_SECRET);
  res.cookie('token', token);
  res.json({ token });
});

router.post('/cadastro', async (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.senha).digest('hex');
  await pool.query('INSERT INTO usuarios (email, senha, perfil) VALUES (?, ?, ?)', [req.body.email, hash, req.body.perfil]);
  res.status(201).end();
});
