import express from 'express';
import cors from 'cors';
import { router as alunos } from './routes/alunos';
import { router as auth } from './routes/auth';

const app = express();
app.use(cors());
app.use(express.json());
app.use('/alunos', alunos);
app.use('/auth', auth);

app.use((err: any, _req: any, res: any, _next: any) => {
  res.status(500).json(err);
});

app.listen(3000);
