import { AnalisadorSeguranca } from './AnalisadorSeguranca.js';
import type { ArquivoFonte, ContextoAnalise } from '../models/ContextoAnalise.js';
import { Categoria, type Regra, type Vulnerabilidade } from '../models/Vulnerabilidade.js';
import { Severidade } from '../models/Severidade.js';
import { ehJsTs } from '../utils/arquivos.js';

const OWASP_CONFIG = 'A05:2021 – Security Misconfiguration';

export const REGRAS_API = {
  corsAberto: {
    id: 'API-001',
    titulo: 'CORS liberado para qualquer origem',
    categoria: Categoria.API,
    severidade: Severidade.MEDIO,
    owasp: OWASP_CONFIG,
    confianca: 'alta',
    explicacao: 'A API aceita requisições de qualquer origem (cors() sem opções, origin: "*" ou origin: true).',
    impacto: 'Qualquer site pode chamar a API pelo navegador do usuário; combinado com credenciais, permite ler dados em nome da vítima.',
    recomendacao: 'Restrinja as origens permitidas ao(s) domínio(s) do front-end, lidos de configuração.',
    exemploCorrecao: `app.use(cors({
  origin: process.env.FRONTEND_URL?.split(','),   // ex.: https://app.escola.com.br
  credentials: true,
}));`,
  },
  semHelmet: {
    id: 'API-002',
    titulo: 'Cabeçalhos de segurança HTTP não configurados',
    categoria: Categoria.API,
    severidade: Severidade.BAIXO,
    owasp: OWASP_CONFIG,
    confianca: 'media',
    explicacao: 'O servidor Express é criado sem o helmet (ou equivalente) e mantém o cabeçalho X-Powered-By.',
    impacto: 'Facilita a identificação da tecnologia pelo atacante e deixa de aplicar proteções do navegador (clickjacking, MIME sniffing, HSTS).',
    recomendacao: 'Adicione o helmet logo após criar o app e desabilite X-Powered-By.',
    exemploCorrecao: `import helmet from 'helmet';
const app = express();
app.use(helmet());
app.disable('x-powered-by');`,
  },
  loginSemLimite: {
    id: 'API-003',
    titulo: 'Rota de login sem limitação de tentativas',
    categoria: Categoria.API,
    severidade: Severidade.MEDIO,
    owasp: 'A07:2021 – Identification and Authentication Failures',
    confianca: 'media',
    explicacao: 'A rota de autenticação não possui rate limiting identificável no arquivo.',
    impacto: 'Permite ataques de força bruta e credential stuffing contra as contas de usuários.',
    recomendacao: 'Limite tentativas por IP/usuário (ex.: express-rate-limit) e considere bloqueio temporário após falhas.',
    exemploCorrecao: `import rateLimit from 'express-rate-limit';
const limiteLogin = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });
router.post('/login', limiteLogin, login);`,
  },
  erroExposto: {
    id: 'API-004',
    titulo: 'Detalhes internos de erro retornados ao cliente',
    categoria: Categoria.API,
    severidade: Severidade.MEDIO,
    owasp: OWASP_CONFIG,
    confianca: 'media',
    explicacao: 'O objeto de erro (ou sua stack) é enviado diretamente na resposta HTTP.',
    impacto: 'Expõe estrutura do banco, caminhos de arquivos, consultas SQL e versões de bibliotecas, ajudando o atacante a planejar ataques.',
    recomendacao: 'Registre o erro no log do servidor e devolva ao cliente uma mensagem genérica.',
    exemploCorrecao: `} catch (erro) {
  logger.error(erro);
  return res.status(500).json({ erro: 'Erro interno. Tente novamente.' });
}`,
  },
} satisfies Record<string, Regra>;

/** Elo da cadeia: configuração e exposição de APIs HTTP (Express / Next.js). */
export class AnalisadorApi extends AnalisadorSeguranca {
  readonly nome = 'API';

  protected suporta(arquivo: ArquivoFonte): boolean {
    return ehJsTs(arquivo.linguagem);
  }

  protected verificar(arquivo: ArquivoFonte, ctx: ContextoAnalise): Vulnerabilidade[] {
    const achados: Vulnerabilidade[] = [];
    const temLimite = /rateLimit|rate-limit|slowDown|limiter|limite\w*/i.test(arquivo.conteudo);

    this.paraCadaLinha(arquivo, (texto, linha) => {
      if (this.casaForaDeString(/\bcors\(\s*\)/, texto) || this.casaForaDeString(/origin\s*:\s*(['"]\*['"]|true)\b/, texto) || /Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]/.test(texto)) {
        achados.push(this.criarAchado(REGRAS_API.corsAberto, arquivo, linha));
        return;
      }
      if (/=\s*express\(\s*\)/.test(texto) && !/helmet/.test(arquivo.conteudo) && !ctx.stack.dependencias.includes('helmet')) {
        achados.push(this.criarAchado(REGRAS_API.semHelmet, arquivo, linha));
        return;
      }
      if (/\.(post)\s*\(\s*['"`][^'"`]*(login|signin|entrar|autenticar|auth)[^'"`]*['"`]/i.test(texto) && !temLimite) {
        achados.push(this.criarAchado(REGRAS_API.loginSemLimite, arquivo, linha));
        return;
      }
      if (/\.(send|json)\s*\(\s*(err|erro|error|e|ex)(\.stack|\.sqlMessage)?\s*\)/.test(texto) || /(stack|sqlMessage)\s*:\s*(err|erro|error|e)\.(stack|sqlMessage)/.test(texto)) {
        achados.push(this.criarAchado(REGRAS_API.erroExposto, arquivo, linha));
      }
    });
    return achados;
  }
}
