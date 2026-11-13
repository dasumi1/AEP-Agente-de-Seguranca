import { Router } from 'express';
import { pool } from '../db/conexao';
import { autenticar } from '../middlewares/auth';

export const router = Router();

router.get('/', async (_req, res) => {
  const [linhas] = await pool.query('SELECT * FROM alunos');
  res.json(linhas);
});

router.get('/:id/notas', autenticar, async (req, res) => {
  const [linhas] = await pool.execute('SELECT * FROM notas WHERE aluno_id = ?', [req.params.id]);
  res.json(linhas);
});

router.delete('/:id', async (req, res) => {
  await pool.query('DELETE FROM alunos WHERE id = ' + req.params.id);
  res.status(204).end();
});

router.put('/admin/config', async (req, res) => {
  await pool.query('UPDATE configuracoes SET ?', [req.body]);
  res.json({ ok: true });
});

router.get('/boletim/:arquivo', autenticar, (req, res) => {
  res.sendFile('/var/boletins/' + req.params.arquivo);
});
