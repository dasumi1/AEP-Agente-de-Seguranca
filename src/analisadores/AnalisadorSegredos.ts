import { AnalisadorSeguranca } from './AnalisadorSeguranca.js';
import type { ArquivoFonte, ContextoAnalise } from '../models/ContextoAnalise.js';
import { Categoria, type Regra, type Vulnerabilidade } from '../models/Vulnerabilidade.js';
import { Severidade } from '../models/Severidade.js';

const OWASP = 'A07:2021 – Identification and Authentication Failures / A02:2021 – Cryptographic Failures';

const EXEMPLO_ENV_TS = `// .env (NÃO versionar — adicione ao .gitignore)
// DB_PASSWORD=...

// código
const senhaBanco = process.env.DB_PASSWORD;
if (!senhaBanco) throw new Error('DB_PASSWORD não configurada');`;

const base = {
  categoria: Categoria.SEGREDOS,
  owasp: OWASP,
  impacto:
    'Qualquer pessoa com acesso ao repositório (ou ao histórico do Git) obtém a credencial e pode acessar o recurso protegido: banco de dados, APIs pagas ou contas de terceiros.',
  recomendacao:
    'Remova o valor do código, mova-o para uma variável de ambiente (.env fora do versionamento ou cofre de segredos) e REVOGUE/troque a credencial exposta, pois ela continua no histórico do Git.',
  exemploCorrecao: EXEMPLO_ENV_TS,
};

export const REGRAS_SEGREDOS = {
  chavePrivada: {
    ...base,
    id: 'SEG-001',
    titulo: 'Chave privada versionada no código',
    severidade: Severidade.CRITICO,
    confianca: 'alta',
    explicacao: 'Foi encontrado o cabeçalho de uma chave privada (RSA/EC/SSH) dentro de um arquivo do repositório.',
    exemploCorrecao: `// carregar a chave de um caminho/secret montado em tempo de execução
import { readFileSync } from 'node:fs';
const chavePrivada = readFileSync(process.env.PRIVATE_KEY_PATH!, 'utf8');`,
  },
  tokenConhecido: {
    ...base,
    id: 'SEG-002',
    titulo: 'Token de serviço exposto (formato conhecido)',
    severidade: Severidade.CRITICO,
    confianca: 'alta',
    explicacao: 'O trecho contém um token com formato de provedor conhecido (AWS, GitHub, OpenAI/Anthropic, Slack).',
  },
  stringConexao: {
    ...base,
    id: 'SEG-003',
    titulo: 'String de conexão com usuário e senha embutidos',
    severidade: Severidade.CRITICO,
    confianca: 'alta',
    explicacao: 'A URL de conexão com o banco/serviço contém a senha em texto puro.',
    exemploCorrecao: `const conexao = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});`,
  },
  senhaFixa: {
    ...base,
    id: 'SEG-004',
    titulo: 'Senha, segredo ou chave de API escrito diretamente no código',
    severidade: Severidade.ALTO,
    confianca: 'media',
    explicacao: 'Uma variável/propriedade com nome de credencial recebe um valor literal fixo.',
  },
  valorPadraoInseguro: {
    ...base,
    id: 'SEG-005',
    titulo: 'Segredo com valor padrão fixo quando a variável de ambiente não existe',
    severidade: Severidade.ALTO,
    confianca: 'alta',
    explicacao:
      'O código lê o segredo de process.env, mas usa um valor literal como alternativa (|| ou ??). Se a variável não for configurada em produção, o sistema roda com um segredo conhecido publicamente.',
    impacto:
      'Com um JWT_SECRET/SESSION_SECRET previsível, um atacante consegue forjar tokens e se autenticar como qualquer usuário, inclusive administradores.',
    recomendacao: 'Remova o valor padrão e faça a aplicação falhar na inicialização se o segredo não estiver definido.',
    exemploCorrecao: `const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET não configurado');`,
  },
  envVersionado: {
    ...base,
    id: 'SEG-006',
    titulo: 'Arquivo .env versionado no repositório',
    severidade: Severidade.CRITICO,
    confianca: 'alta',
    explicacao: 'Um arquivo .env com variáveis de ambiente reais está sendo rastreado pelo Git.',
    recomendacao:
      'Execute `git rm --cached <arquivo>`, adicione `.env*` ao .gitignore (mantendo apenas um `.env.example` sem valores reais) e troque todas as credenciais que estavam no arquivo.',
    exemploCorrecao: `# .gitignore
.env
.env.*
!.env.example

# .env.example (versionado, sem valores reais)
DB_PASSWORD=
JWT_SECRET=`,
  },
} satisfies Record<string, Regra>;

const TOKENS = [
  /AKIA[0-9A-Z]{16}/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
];

const NOME_CREDENCIAL =
  /(?:pass(?:word|wd)?|pwd|senha|secret|segredo|token|api[_-]?key|apikey|private[_-]?key|client[_-]?secret|credencial)/i;

/** (nome) [:=] "valor" — captura nome e valor literal. */
const ATRIBUICAO = /["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*(["'`])([^"'`\n]{3,})\2/g;

const VALOR_PLACEHOLDER =
  /^(\*+|x+|\.\.\.|changeme|change_me|example|exemplo|your[_-].*|seu[_-].*|sua[_-].*|<.*>|\$\{.*\}|%.*%|null|undefined|none|true|false|password|senha|secret|token|string|text|hidden|bearer|basic|sha\d*|md5|bcrypt|hex|base64|utf-?8)$/i;

const NOMES_NAO_SECRETOS = /(type|input|label|placeholder|field|name|key_?name|header|policy|reset|forgot|confirm|min|max|length|regex|pattern|route|path|url|endpoint|message|msg|error|hint|tipo|campo|rotulo|mensagem|erro)$/i;

const STRING_CONEXAO = /\b(mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|ftp|smtp):\/\/[^:\s'"`/]+:([^@\s'"`]+)@/i;

/**
 * Elo da cadeia: exposição de senhas, tokens e chaves.
 * Independente de linguagem — funciona em código, configurações e scripts.
 */
export class AnalisadorSegredos extends AnalisadorSeguranca {
  readonly nome = 'Credenciais/Segredos';

  protected suporta(): boolean {
    return true;
  }

  protected verificar(arquivo: ArquivoFonte, _ctx: ContextoAnalise): Vulnerabilidade[] {
    const achados: Vulnerabilidade[] = [];
    const nome = arquivo.caminho.split('/').pop()!.toLowerCase();
    const ehExemplo = /\.(example|sample|template|dist|exemplo)$/.test(nome);
    // Manifestos de dependências: nomes como "jsonwebtoken": "^9.0.0" não são credenciais
    const ehManifesto = /^(package|composer|tsconfig|jsconfig|app)\.json$|^package-lock|lock\.json$/.test(nome);

    if (arquivo.tipo === 'env' && !ehExemplo) {
      const comValor = arquivo.linhas.filter((l) => /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+/.test(l));
      if (comValor.length > 0) {
        achados.push(
          this.criarAchado(REGRAS_SEGREDOS.envVersionado, arquivo, 1, {
            trecho: `${comValor.length} variável(is) com valor definido`,
          }),
        );
      }
      return achados; // não detalha linha a linha para não repetir o mesmo problema
    }

    this.paraCadaLinha(arquivo, (texto, linha) => {
      if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(texto)) {
        achados.push(this.criarAchado(REGRAS_SEGREDOS.chavePrivada, arquivo, linha));
        return;
      }
      if (TOKENS.some((t) => t.test(texto))) {
        achados.push(this.criarAchado(REGRAS_SEGREDOS.tokenConhecido, arquivo, linha));
        return;
      }
      const conexao = STRING_CONEXAO.exec(texto);
      if (conexao && !/^\$\{|^\{\{|^%|^\*+$/.test(conexao[2])) {
        achados.push(this.criarAchado(REGRAS_SEGREDOS.stringConexao, arquivo, linha));
        return;
      }
      const padrao = /(?:process\.env|os\.environ(?:\.get)?|getenv)[.[('"]*([A-Z0-9_]+)['")\]]*\s*(?:\|\||\?\?|,|or)\s*(["'`])[^"'`]{3,}\2/.exec(texto);
      if (padrao && NOME_CREDENCIAL.test(padrao[1])) {
        achados.push(this.criarAchado(REGRAS_SEGREDOS.valorPadraoInseguro, arquivo, linha));
        return;
      }
      if (ehExemplo || ehManifesto) return;
      for (const m of texto.matchAll(ATRIBUICAO)) {
        const [, chave, , valor] = m;
        if (!NOME_CREDENCIAL.test(chave) || NOMES_NAO_SECRETOS.test(chave)) continue;
        // Mensagens/rótulos (espaços, acentos) e placeholders não são credenciais.
        if (VALOR_PLACEHOLDER.test(valor.trim()) || /[^\x21-\x7e]/.test(valor)) continue;
        if (/^(process\.env|import\.meta\.env|env\.|config\.)/.test(valor)) continue;
        if (NOME_CREDENCIAL.test(valor) && /[/\s_-]/.test(valor)) continue; // rótulos como 'Credenciais/Segredos'
        if (/^[\^~>=<]*\d+(\.\d+){1,2}([-+.\w]*)?$/.test(valor.trim())) continue; // versão (ex.: ^9.0.0)
        achados.push(this.criarAchado(REGRAS_SEGREDOS.senhaFixa, arquivo, linha));
        break;
      }
    });
    return achados;
  }
}
