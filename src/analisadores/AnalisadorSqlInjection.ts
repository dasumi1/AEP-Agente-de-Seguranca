import { AnalisadorSeguranca } from './AnalisadorSeguranca.js';
import type { ArquivoFonte, ContextoAnalise } from '../models/ContextoAnalise.js';
import { Categoria, type Regra, type Vulnerabilidade } from '../models/Vulnerabilidade.js';
import { Severidade } from '../models/Severidade.js';
import { ehArquivoDeCodigo } from '../utils/arquivos.js';

const OWASP = 'A03:2021 – Injection';

const EXEMPLO_PARAMETRIZADO = `// mysql2 — consulta parametrizada (prepared statement)
const [linhas] = await pool.execute(
  'SELECT * FROM usuarios WHERE email = ? AND ativo = ?',
  [email, true],
);`;

const base = {
  categoria: Categoria.SQL_INJECTION,
  owasp: OWASP,
  impacto:
    'Um atacante pode alterar a consulta SQL enviada ao banco: ler dados de outros usuários (notas, faltas, dados pessoais), contornar o login, alterar ou apagar registros.',
  recomendacao:
    'Nunca monte SQL com interpolação/concatenação de valores. Use consultas parametrizadas (placeholders ? ou :nome) ou os métodos seguros do ORM/query builder. Para nomes de colunas/ordenação dinâmicos, use uma lista de valores permitidos (allowlist).',
  exemploCorrecao: EXEMPLO_PARAMETRIZADO,
};

export const REGRAS_SQL = {
  interpolacao: {
    ...base,
    id: 'SQL-001',
    titulo: 'Consulta SQL montada com interpolação de variáveis',
    severidade: Severidade.ALTO,
    confianca: 'media',
    explicacao: 'O texto da consulta SQL é construído com template string/f-string e recebe valores via ${...} ou {...}.',
  },
  interpolacaoEntrada: {
    ...base,
    id: 'SQL-002',
    titulo: 'Entrada do usuário inserida diretamente na consulta SQL',
    severidade: Severidade.CRITICO,
    confianca: 'alta',
    explicacao: 'Dados vindos da requisição (req.body, req.query, req.params, $_GET, request.args...) são colocados diretamente no texto da consulta SQL.',
  },
  concatenacao: {
    ...base,
    id: 'SQL-003',
    titulo: 'Consulta SQL montada por concatenação de strings',
    severidade: Severidade.ALTO,
    confianca: 'media',
    explicacao: 'O texto da consulta SQL é construído concatenando strings com variáveis (operador + ou .).',
  },
  multiplasInstrucoes: {
    ...base,
    id: 'SQL-004',
    titulo: 'Execução de múltiplas instruções SQL habilitada',
    severidade: Severidade.MEDIO,
    confianca: 'alta',
    explicacao: 'A opção multipleStatements permite que uma única chamada execute várias instruções separadas por ponto e vírgula.',
    impacto: 'Se existir qualquer ponto de injeção, o atacante pode encadear comandos destrutivos (ex.: DROP TABLE) na mesma chamada.',
    recomendacao: 'Desabilite multipleStatements, a menos que seja estritamente necessário e restrito a scripts internos.',
    exemploCorrecao: `const pool = mysql.createPool({
  // ...
  multipleStatements: false,
});`,
  },
} satisfies Record<string, Regra>;

const PALAVRAS_SQL = /\b(SELECT\s[\s\S]*?\sFROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|WHERE\s|ORDER\s+BY|GROUP\s+BY|VALUES\s*\(|JOIN\s+\S+\s+ON|DROP\s+TABLE|CREATE\s+TABLE)/i;
const ENTRADA_USUARIO = /\b(req|request|ctx\.request|ctx)\.(body|query|params|headers|cookies|args|form|json|GET|POST)\b|\$_(GET|POST|REQUEST|COOKIE)|request\.(args|form|json|GET|POST)/;

/**
 * Elo da cadeia: SQL Injection. Multilinguagem (JS/TS, Python, PHP, Java...).
 */
export class AnalisadorSqlInjection extends AnalisadorSeguranca {
  readonly nome = 'SQL Injection';

  protected suporta(arquivo: ArquivoFonte): boolean {
    return ehArquivoDeCodigo(arquivo.linguagem);
  }

  protected verificar(arquivo: ArquivoFonte, _ctx: ContextoAnalise): Vulnerabilidade[] {
    const achados: Vulnerabilidade[] = [];
    const linhasComAchado = new Set<number>();
    const conteudo = arquivo.conteudo;

    // 1) Template strings (podem ocupar várias linhas): `SELECT ... ${x}`
    for (const m of conteudo.matchAll(/`((?:[^`\\]|\\.)*)`/g)) {
      const corpo = m[1];
      if (!PALAVRAS_SQL.test(corpo) || !corpo.includes('${')) continue;
      const interpolacoes = [...corpo.matchAll(/\$\{([^}]*)\}/g)].map((x) => x[1]);
      // ${placeholders} gerados internamente (ex.: lista de '?') não são entrada do usuário
      if (interpolacoes.every((v) => /placeholders|marcadores|\.map\(\s*\(\)\s*=>\s*['"]\?['"]\)/.test(v))) continue;
      const linhaInicio = this.linhaDoIndice(conteudo, m.index ?? 0);
      const offsetInterp = corpo.indexOf('${');
      const linha = this.linhaDoIndice(conteudo, (m.index ?? 0) + 1 + offsetInterp);
      const comEntrada = interpolacoes.some((v) => ENTRADA_USUARIO.test(v));
      achados.push(this.criarAchado(comEntrada ? REGRAS_SQL.interpolacaoEntrada : REGRAS_SQL.interpolacao, arquivo, linha));
      linhasComAchado.add(linha).add(linhaInicio);
    }

    this.paraCadaLinha(arquivo, (texto, linha) => {
      if (linhasComAchado.has(linha)) return;

      // 2) f-strings Python / .format() / interpolação PHP
      const fString = /\bf(["'])(.*?)\1/.exec(texto);
      if (fString && PALAVRAS_SQL.test(fString[2]) && /\{[^}]+\}/.test(fString[2])) {
        const regra = ENTRADA_USUARIO.test(texto) ? REGRAS_SQL.interpolacaoEntrada : REGRAS_SQL.interpolacao;
        achados.push(this.criarAchado(regra, arquivo, linha));
        return;
      }
      if (/(["']).*?\1\s*\.format\(/.test(texto) && PALAVRAS_SQL.test(texto)) {
        achados.push(this.criarAchado(REGRAS_SQL.interpolacao, arquivo, linha));
        return;
      }
      if (arquivo.linguagem === 'php' && PALAVRAS_SQL.test(texto) && /"[^"]*\$[A-Za-z_{][^"]*"/.test(texto)) {
        const regra = ENTRADA_USUARIO.test(texto) ? REGRAS_SQL.interpolacaoEntrada : REGRAS_SQL.interpolacao;
        achados.push(this.criarAchado(regra, arquivo, linha));
        return;
      }

      // 3) Concatenação: "SELECT ... " + variavel  |  "..." . $var (PHP)
      const literal = /(["'])((?:(?!\1).)*)\1\s*(\+|\.(?=\s*\$))\s*[A-Za-z_$(]/.exec(texto);
      const literalAntes = /[A-Za-z_$)\]]\s*(\+|\.)\s*(["'])((?:(?!\2).)*)\2/.exec(texto);
      const sqlNoLiteral = (literal && PALAVRAS_SQL.test(literal[2] + ' ')) || (literalAntes && /\b(WHERE|AND|OR|SET|VALUES|FROM|LIMIT|ORDER BY)\b/i.test(literalAntes[3]) && PALAVRAS_SQL.test(texto));
      if (sqlNoLiteral) {
        const regra = ENTRADA_USUARIO.test(texto) ? REGRAS_SQL.interpolacaoEntrada : REGRAS_SQL.concatenacao;
        achados.push(this.criarAchado(regra, arquivo, linha));
        return;
      }

      if (/multipleStatements\s*:\s*true/.test(texto)) {
        achados.push(this.criarAchado(REGRAS_SQL.multiplasInstrucoes, arquivo, linha));
      }
    });

    return achados;
  }
}
