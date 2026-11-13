import { AnalisadorSeguranca } from './AnalisadorSeguranca.js';
import type { ArquivoFonte, ContextoAnalise } from '../models/ContextoAnalise.js';
import { Categoria, type Regra, type Vulnerabilidade } from '../models/Vulnerabilidade.js';
import { Severidade } from '../models/Severidade.js';
import { ehArquivoDeCodigo, ehJsTs } from '../utils/arquivos.js';

const OWASP = 'A03:2021 – Injection';
const ENTRADA = /\b(req|request|ctx)\.(body|query|params|headers|cookies|args|form)\b|\$_(GET|POST|REQUEST)|request\.(args|form|json)/;

export const REGRAS_ENTRADA = {
  execucaoDinamica: {
    id: 'ENT-001',
    titulo: 'Execução dinâmica de código (eval / new Function)',
    categoria: Categoria.VALIDACAO_ENTRADA,
    severidade: Severidade.CRITICO,
    owasp: OWASP,
    confianca: 'alta',
    explicacao: 'O código usa eval(), new Function() ou equivalente com conteúdo não literal.',
    impacto: 'Se qualquer parte do conteúdo vier do usuário, o atacante executa código arbitrário no servidor (RCE).',
    recomendacao: 'Remova eval/new Function. Para interpretar dados, use JSON.parse; para lógica variável, use um mapa de funções permitidas.',
    exemploCorrecao: `// em vez de eval(expressao)
const operacoes = { somar: (a: number, b: number) => a + b } as const;
const op = operacoes[nome as keyof typeof operacoes];
if (!op) throw new Error('Operação não permitida');`,
  },
  comandoSistema: {
    id: 'ENT-002',
    titulo: 'Comando do sistema operacional montado com variáveis',
    categoria: Categoria.VALIDACAO_ENTRADA,
    severidade: Severidade.CRITICO,
    owasp: OWASP,
    confianca: 'media',
    explicacao: 'Um comando de shell (exec/execSync/system/popen) é construído com interpolação ou concatenação.',
    impacto: 'Permite injeção de comandos: o atacante pode executar qualquer programa no servidor com as permissões da aplicação.',
    recomendacao: 'Use execFile/spawn com a lista de argumentos separada (sem shell) e valide os valores contra uma allowlist.',
    exemploCorrecao: `import { execFile } from 'node:child_process';
// argumentos passados separadamente, sem interpretação pelo shell
execFile('swipl', ['-q', '-f', arquivoValidado, '-g', 'main'], (erro, saida) => { /* ... */ });`,
  },
  caminhoArquivo: {
    id: 'ENT-003',
    titulo: 'Caminho de arquivo controlado pelo usuário (Path Traversal)',
    categoria: Categoria.VALIDACAO_ENTRADA,
    severidade: Severidade.ALTO,
    owasp: 'A01:2021 – Broken Access Control',
    confianca: 'media',
    explicacao: 'Um caminho de arquivo é montado a partir de dados da requisição sem normalização/validação.',
    impacto: 'Com valores como "../../.env", o atacante lê ou sobrescreve arquivos fora do diretório permitido.',
    recomendacao: 'Resolva o caminho com path.resolve e confirme que ele continua dentro do diretório base; prefira identificadores em vez de nomes de arquivo.',
    exemploCorrecao: `import path from 'node:path';
const BASE = path.resolve('uploads');
const destino = path.resolve(BASE, String(req.params.nome));
if (!destino.startsWith(BASE + path.sep)) return res.status(400).json({ erro: 'Caminho inválido' });
res.sendFile(destino);`,
  },
  semValidacao: {
    id: 'ENT-004',
    titulo: 'Dados da requisição usados sem validação de esquema',
    categoria: Categoria.VALIDACAO_ENTRADA,
    severidade: Severidade.BAIXO,
    owasp: 'A04:2021 – Insecure Design',
    confianca: 'baixa',
    explicacao: 'O arquivo manipula req.body mas nenhuma validação de esquema (zod, joi, yup, express-validator, class-validator) foi identificada.',
    impacto: 'Tipos e formatos inesperados podem causar erros, gravação de dados inválidos (ex.: nota negativa) ou abrir caminho para outras injeções.',
    recomendacao: 'Valide o corpo de cada requisição com um esquema explícito antes de usá-lo e rejeite campos desconhecidos.',
    exemploCorrecao: `import { z } from 'zod';
const NotaSchema = z.object({
  alunoId: z.number().int().positive(),
  valor: z.number().min(0).max(10),
}).strict();

const dados = NotaSchema.safeParse(req.body);
if (!dados.success) return res.status(400).json({ erros: dados.error.flatten() });`,
  },
} satisfies Record<string, Regra>;

/** Elo da cadeia: validação de entrada (injeção de código/comando, path traversal, ausência de validação). */
export class AnalisadorValidacaoEntrada extends AnalisadorSeguranca {
  readonly nome = 'Validação de Entrada';

  protected suporta(arquivo: ArquivoFonte): boolean {
    return ehArquivoDeCodigo(arquivo.linguagem);
  }

  protected verificar(arquivo: ArquivoFonte, _ctx: ContextoAnalise): Vulnerabilidade[] {
    const achados: Vulnerabilidade[] = [];

    this.paraCadaLinha(arquivo, (texto, linha) => {
      if (this.casaForaDeString(/(^|[^.\w])eval\s*\(\s*[^'"`)\s]/, texto) || this.casaForaDeString(/new\s+Function\s*\(/, texto)) {
        achados.push(this.criarAchado(REGRAS_ENTRADA.execucaoDinamica, arquivo, linha));
        return;
      }
      const shell = /\b(exec|execSync|system|popen|shell_exec|passthru|subprocess\.(?:call|run|Popen))\s*\(([^)]*)/.exec(texto);
      if (shell && (/\$\{|\+\s*\w|\.format\(|\bf["']/.test(shell[2]) || /shell\s*=\s*True/.test(texto) && ENTRADA.test(texto))) {
        achados.push(this.criarAchado(REGRAS_ENTRADA.comandoSistema, arquivo, linha));
        return;
      }
      if (/\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|sendFile|download|unlink|open)\s*\(/.test(texto) && ENTRADA.test(texto) && !/path\.basename|resolverDentro|startsWith/.test(texto)) {
        achados.push(this.criarAchado(REGRAS_ENTRADA.caminhoArquivo, arquivo, linha));
      }
    });

    if (ehJsTs(arquivo.linguagem)) {
      const usaCorpo = arquivo.linhas.findIndex((l) => this.casaForaDeString(/\breq\.body\b/, l));
      const temValidacao = /\b(zod|joi|yup|express-validator|class-validator|ajv|valibot|superstruct)\b|\.safeParse\(|\.parse\(req\.body|validationResult\(|checkSchema\(|celebrate\(/.test(arquivo.conteudo);
      if (usaCorpo >= 0 && !temValidacao) {
        achados.push(this.criarAchado(REGRAS_ENTRADA.semValidacao, arquivo, usaCorpo + 1));
      }
    }
    return achados;
  }
}
