import { AnalisadorSeguranca } from './AnalisadorSeguranca.js';
import type { ArquivoFonte, ContextoAnalise } from '../models/ContextoAnalise.js';
import { Categoria, type Regra, type Vulnerabilidade } from '../models/Vulnerabilidade.js';
import { Severidade } from '../models/Severidade.js';
import { ehJsTs } from '../utils/arquivos.js';

const OWASP = 'A01:2021 – Broken Access Control';

const EXEMPLO_MIDDLEWARE = `// middleware de autenticação + autorização por perfil
export function autenticar(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ erro: 'Não autenticado' });
  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

export const exigirPerfil = (...perfis: string[]) => (req, res, next) =>
  perfis.includes(req.usuario?.perfil) ? next() : res.status(403).json({ erro: 'Acesso negado' });

router.delete('/alunos/:id', autenticar, exigirPerfil('admin'), excluirAluno);`;

const base = {
  categoria: Categoria.AUTORIZACAO,
  owasp: OWASP,
  confianca: 'media' as const,
  impacto: 'Usuários não autenticados (ou sem o perfil adequado) podem acessar ou alterar dados e funcionalidades restritas.',
  recomendacao:
    'Proteja a rota com middleware de autenticação e, quando aplicável, de autorização por perfil (ex.: admin, professor, aluno). Se a rota for propositalmente pública, documente com o comentário "seguranca-ignore".',
  exemploCorrecao: EXEMPLO_MIDDLEWARE,
};

export const REGRAS_AUTORIZACAO = {
  rotaEscritaSemAuth: {
    ...base,
    id: 'AUZ-001',
    titulo: 'Rota que altera dados sem middleware de autenticação',
    severidade: Severidade.ALTO,
    explicacao: 'Uma rota POST/PUT/PATCH/DELETE foi declarada sem nenhum middleware de autenticação/autorização identificável.',
  },
  rotaLeituraSemAuth: {
    ...base,
    id: 'AUZ-002',
    titulo: 'Rota de consulta sem middleware de autenticação',
    severidade: Severidade.MEDIO,
    explicacao: 'Uma rota GET foi declarada sem middleware de autenticação identificável; ela pode expor dados a qualquer pessoa.',
  },
  rotaAdminSemAuth: {
    ...base,
    id: 'AUZ-003',
    titulo: 'Rota administrativa sem autenticação',
    severidade: Severidade.CRITICO,
    explicacao: 'Uma rota cujo caminho indica função administrativa foi declarada sem middleware de autenticação/autorização.',
  },
  handlerApiSemAuth: {
    ...base,
    id: 'AUZ-004',
    titulo: 'Handler de API (Next.js / serverless) sem verificação de sessão',
    severidade: Severidade.MEDIO,
    confianca: 'baixa',
    explicacao: 'O arquivo exporta handlers de API mas não foi encontrada nenhuma verificação de sessão/token (getServerSession, auth(), verify...).',
    exemploCorrecao: `// app/api/notas/route.ts
export async function POST(req: Request) {
  const sessao = await auth();
  if (!sessao?.user) return Response.json({ erro: 'Não autenticado' }, { status: 401 });
  if (sessao.user.perfil !== 'professor') return Response.json({ erro: 'Acesso negado' }, { status: 403 });
  // ...
}`,
  },
} satisfies Record<string, Regra>;

/** Nomes típicos de middlewares de autenticação/autorização. */
const MIDDLEWARE_AUTH =
  /\b(auth\w*|autentica\w*|autoriza\w*|verify\w*|verifica\w*|protect\w*|protege\w*|require\w*|exig\w*|ensure\w*|garant\w*|isAuth\w*|isAdmin|isLogged\w*|checkRole|checkAuth|checkToken|validateToken|validarToken|passport\.authenticate|jwtCheck|jwtMiddleware|guard\w*|permit\w*|permiss\w*|role\w*|perfil\w*|somente\w*|apenas\w*|logado|privad\w*|session\w*)\b/i;

/** Caminhos geralmente públicos. */
const ROTA_PUBLICA =
  /(login|logout|signin|signup|sign-in|sign-up|entrar|registr|cadastr|register|health|status|ping|public|publico|forgot|reset|recuperar|esqueci|webhook|callback|oauth|docs|swagger|metrics)/i;

const ROTA = /\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete)\s*\(\s*(['"`])([^'"`]*)\3\s*,?([^\n]*)/;

/** Elo da cadeia: autorização de rotas (Express e handlers de API do Next.js). */
export class AnalisadorAutorizacao extends AnalisadorSeguranca {
  readonly nome = 'Autorização';

  protected suporta(arquivo: ArquivoFonte): boolean {
    return ehJsTs(arquivo.linguagem);
  }

  protected verificar(arquivo: ArquivoFonte, _ctx: ContextoAnalise): Vulnerabilidade[] {
    const achados: Vulnerabilidade[] = [];
    let protecaoGlobal = false;

    arquivo.linhas.forEach((texto, i) => {
      const linha = i + 1;
      const t = texto.trim();
      if (t.startsWith('//') || t.startsWith('*')) return;

      // app.use(autenticar) / router.use(auth) => rotas seguintes do arquivo ficam protegidas
      const uso = /\b[A-Za-z_$][\w$]*\.use\s*\(([^)]*)\)/.exec(texto);
      if (uso && MIDDLEWARE_AUTH.test(uso[1]) && !/^\s*['"`]/.test(uso[1])) protecaoGlobal = true;
      if (uso && /^\s*['"`]/.test(uso[1]) && MIDDLEWARE_AUTH.test(uso[1].replace(/^\s*(['"`])[^'"`]*\1/, ''))) protecaoGlobal = true;

      const rota = ROTA.exec(texto);
      if (!rota) return;
      const [, objeto, metodo, , caminho] = rota;
      if (!/^(app|router|rotas|routes|server|api|\w*router|\w*Router|\w*rotas|\w*Rotas)$/.test(objeto)) return;

      // considera a declaração completa (pode quebrar em várias linhas)
      const declaracao = this.declaracaoCompleta(arquivo, linha).replace(/(['"`])[^'"`]*\1/, '');
      if (protecaoGlobal || MIDDLEWARE_AUTH.test(declaracao)) return;
      if (ROTA_PUBLICA.test(caminho)) return;

      let regra: Regra;
      if (/admin|adm\b|gestao|configurac|usuarios?\/.*(perfil|papel|role)/i.test(caminho)) regra = REGRAS_AUTORIZACAO.rotaAdminSemAuth;
      else if (metodo === 'get') regra = REGRAS_AUTORIZACAO.rotaLeituraSemAuth;
      else regra = REGRAS_AUTORIZACAO.rotaEscritaSemAuth;

      achados.push(this.criarAchado(regra, arquivo, linha, { titulo: `${regra.titulo}: ${metodo.toUpperCase()} ${caminho}` }));
    });

    // Next.js (pages/api ou app/**/route.ts) e handlers serverless
    const ehApi = /(^|\/)(pages\/api|app\/.*\/route\.(t|j)sx?$|api\/)/.test(arquivo.caminho);
    const exportaHandler = /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|handler)\b|export\s+default\s+(async\s+)?function/.test(arquivo.conteudo);
    if (ehApi && exportaHandler && !ROTA_PUBLICA.test(arquivo.caminho)) {
      const verificaSessao = /getServerSession|getSession|auth\(\)|currentUser|verify\w*\(|verifica\w*\(|autentica\w*\(|withAuth|requireAuth|getToken\(|cookies\(\)\.get/.test(arquivo.conteudo);
      if (!verificaSessao) {
        const idx = arquivo.linhas.findIndex((l) => /export\s+(async\s+)?function|export\s+default/.test(l));
        achados.push(this.criarAchado(REGRAS_AUTORIZACAO.handlerApiSemAuth, arquivo, idx + 1));
      }
    }
    return achados;
  }

  /** Junta as linhas da chamada até os parênteses fecharem (máx. 6 linhas). Ignora o corpo de funções inline. */
  private declaracaoCompleta(arquivo: ArquivoFonte, linha: number): string {
    let saldo = 0;
    const partes: string[] = [];
    for (let i = linha - 1; i < Math.min(arquivo.linhas.length, linha + 5); i++) {
      const texto = arquivo.linhas[i];
      const corte = texto.search(/=>\s*\{|function\s*\(/); // para antes do corpo do handler
      const util = corte >= 0 ? texto.slice(0, corte) : texto;
      partes.push(util);
      for (const c of texto) saldo += c === '(' ? 1 : c === ')' ? -1 : 0;
      if (corte >= 0 || saldo <= 0) break;
    }
    return partes.join(' ');
  }
}
