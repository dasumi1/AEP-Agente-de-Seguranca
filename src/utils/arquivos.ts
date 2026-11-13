import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import type { TipoArquivo } from '../models/ContextoAnalise.js';

/** Diretórios nunca analisados. */
export const DIRETORIOS_IGNORADOS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', 'coverage',
  'vendor', '__pycache__', '.venv', 'venv', 'target', '.turbo', '.cache',
  'relatorios-seguranca',
]);

const LINGUAGENS: Record<string, string> = {
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.py': 'python', '.php': 'php', '.java': 'java', '.kt': 'kotlin', '.cs': 'csharp',
  '.go': 'go', '.rb': 'ruby', '.pl': 'prolog', '.pro': 'prolog',
  '.sql': 'sql', '.prisma': 'prisma',
  '.json': 'json', '.yml': 'yaml', '.yaml': 'yaml', '.xml': 'xml',
  '.properties': 'properties', '.ini': 'ini', '.toml': 'toml', '.conf': 'conf',
};

export const TAMANHO_MAXIMO_BYTES = 1_000_000;

export function detectarLinguagem(caminho: string): string | undefined {
  const nome = path.basename(caminho).toLowerCase();
  if (nome === '.env' || nome.startsWith('.env.')) return 'dotenv';
  if (nome === 'dockerfile' || nome === 'docker-compose.yml') return 'docker';
  return LINGUAGENS[path.extname(nome)];
}

export function detectarTipo(caminho: string, linguagem: string): TipoArquivo {
  if (linguagem === 'dotenv') return 'env';
  if (linguagem === 'sql' || linguagem === 'prisma') return 'esquema-banco';
  if (['json', 'yaml', 'xml', 'properties', 'ini', 'toml', 'conf', 'docker'].includes(linguagem)) return 'config';
  return 'codigo';
}

export function ehArquivoDeCodigo(linguagem: string): boolean {
  return [
    'typescript', 'javascript', 'python', 'php', 'java', 'kotlin', 'csharp', 'go', 'ruby', 'prolog',
  ].includes(linguagem);
}

export function ehJsTs(linguagem: string): boolean {
  return linguagem === 'typescript' || linguagem === 'javascript';
}

/** Converte padrões simples de glob (*, **, ?) em RegExp. */
export function globParaRegex(glob: string): RegExp {
  let g = glob.trim().replace(/\\/g, '/');
  const ancorado = g.startsWith('/');
  if (ancorado) g = g.slice(1);
  if (g.endsWith('/')) g += '**';
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*') {
      if (g[i + 1] === '*') {
        re += '.*';
        i++;
        if (g[i + 1] === '/') i++;
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(ancorado || g.includes('/') ? `^${re}$` : `(^|/)${re}$`);
}

/** Lê padrões do arquivo .segurancaignore na raiz do projeto analisado. */
export function carregarIgnorados(raiz: string): RegExp[] {
  const arq = path.join(raiz, '.segurancaignore');
  if (!existsSync(arq)) return [];
  return readFileSync(arq, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map(globParaRegex);
}

/**
 * Lista arquivos do projeto. Em repositórios Git usa `git ls-files`, o que
 * respeita o .gitignore e reflete exatamente o que está versionado
 * (um .env aparecendo aqui significa que ele FOI commitado).
 */
export function listarArquivos(raiz: string): string[] {
  if (existsSync(path.join(raiz, '.git'))) {
    try {
      const saida = execFileSync('git', ['-C', raiz, 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
      });
      return saida.split('\0').filter(Boolean).map((p) => p.replace(/\\/g, '/'));
    } catch {
      /* cai para a varredura manual */
    }
  }
  const resultado: string[] = [];
  const visitar = (dir: string) => {
    for (const entrada of readdirSync(dir, { withFileTypes: true })) {
      if (entrada.isDirectory()) {
        if (!DIRETORIOS_IGNORADOS.has(entrada.name)) visitar(path.join(dir, entrada.name));
      } else if (entrada.isFile()) {
        resultado.push(path.relative(raiz, path.join(dir, entrada.name)).replace(/\\/g, '/'));
      }
    }
  };
  visitar(raiz);
  return resultado;
}

/** Garante que um caminho relativo não escape da raiz (proteção contra path traversal). */
export function resolverDentroDaRaiz(raiz: string, relativo: string): string | undefined {
  const absRaiz = path.resolve(raiz);
  const abs = path.resolve(absRaiz, relativo);
  if (abs !== absRaiz && !abs.startsWith(absRaiz + path.sep)) return undefined;
  return abs;
}

export function lerArquivoTexto(abs: string): string | undefined {
  try {
    const st = statSync(abs);
    if (!st.isFile() || st.size > TAMANHO_MAXIMO_BYTES) return undefined;
    const buf = readFileSync(abs);
    if (buf.subarray(0, 8000).includes(0)) return undefined; // binário
    return buf.toString('utf8');
  } catch {
    return undefined;
  }
}
