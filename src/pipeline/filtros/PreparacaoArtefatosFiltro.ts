import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import type { Filtro } from '../Pipeline.js';
import type { ArquivoFonte, ContextoAnalise, StackDetectada } from '../../models/ContextoAnalise.js';
import {
  DIRETORIOS_IGNORADOS,
  carregarIgnorados,
  detectarLinguagem,
  detectarTipo,
  lerArquivoTexto,
  listarArquivos,
  resolverDentroDaRaiz,
} from '../../utils/arquivos.js';

const ARQUIVOS_IGNORADOS = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|poetry\.lock|.*\.min\.js|.*\.map)$/;

/**
 * FILTRO 1 — Preparação dos artefatos.
 * Lê o código-fonte e o esquema do banco, aplica exclusões e detecta a stack.
 */
export class PreparacaoArtefatosFiltro implements Filtro {
  readonly nome = 'Preparação dos artefatos';
  readonly essencial = true;

  async executar(ctx: ContextoAnalise): Promise<ContextoAnalise> {
    if (!existsSync(ctx.raiz) || !statSync(ctx.raiz).isDirectory()) {
      throw new Error(`Diretório do projeto não encontrado: ${ctx.raiz}`);
    }
    const ignorados = carregarIgnorados(ctx.raiz);

    let candidatos: string[];
    if (ctx.arquivosAlvo && ctx.arquivosAlvo.length > 0) {
      ctx.modo = 'incremental';
      candidatos = ctx.arquivosAlvo.map((p) => p.replace(/\\/g, '/').replace(/^\.\//, ''));
    } else {
      ctx.modo = 'completo';
      candidatos = listarArquivos(ctx.raiz);
    }

    const arquivos: ArquivoFonte[] = [];
    for (const rel of candidatos) {
      if (rel.split('/').some((seg) => DIRETORIOS_IGNORADOS.has(seg))) continue;
      if (ARQUIVOS_IGNORADOS.test(rel) || ignorados.some((re) => re.test(rel))) continue;
      const abs = resolverDentroDaRaiz(ctx.raiz, rel);
      if (!abs) {
        ctx.avisos.push(`Caminho ignorado por estar fora do projeto: ${rel}`);
        continue;
      }
      const linguagem = detectarLinguagem(rel);
      if (!linguagem) continue;
      const conteudo = lerArquivoTexto(abs);
      if (conteudo === undefined) continue; // removido, binário ou grande demais
      arquivos.push({
        caminho: rel,
        conteudo,
        linhas: conteudo.split(/\r?\n/),
        linguagem,
        tipo: detectarTipo(rel, linguagem),
      });
    }

    ctx.arquivos = arquivos;
    ctx.stack = detectarStack(ctx.raiz, arquivos);
    if (arquivos.length === 0) ctx.avisos.push('Nenhum arquivo analisável foi encontrado.');
    return ctx;
  }
}

/** Detecta linguagem/frameworks/banco a partir dos manifestos do projeto. */
export function detectarStack(raiz: string, arquivos: ArquivoFonte[]): StackDetectada {
  const stack: StackDetectada = { ecossistemas: [], frameworks: [], bancos: [], dependencias: [] };
  const add = (lista: string[], v: string) => !lista.includes(v) && lista.push(v);

  // package.json na raiz e em subpastas comuns (monorepo frontend/backend)
  const manifestos = ['package.json', 'backend/package.json', 'frontend/package.json', 'server/package.json', 'api/package.json', 'web/package.json'];
  for (const m of manifestos) {
    const abs = path.join(raiz, m);
    if (!existsSync(abs)) continue;
    try {
      const pkg = JSON.parse(readFileSync(abs, 'utf8'));
      add(stack.ecossistemas, 'node');
      for (const dep of Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })) add(stack.dependencias, dep);
    } catch {
      /* package.json inválido: ignora */
    }
  }

  const linguagens = new Set(arquivos.map((a) => a.linguagem));
  if (linguagens.has('typescript') || linguagens.has('javascript')) add(stack.ecossistemas, 'node');
  if (linguagens.has('python') || existsSync(path.join(raiz, 'requirements.txt')) || existsSync(path.join(raiz, 'pyproject.toml'))) add(stack.ecossistemas, 'python');
  if (linguagens.has('php') || existsSync(path.join(raiz, 'composer.json'))) add(stack.ecossistemas, 'php');
  if (linguagens.has('java') || existsSync(path.join(raiz, 'pom.xml'))) add(stack.ecossistemas, 'java');
  if (linguagens.has('prolog')) add(stack.ecossistemas, 'prolog');

  const d = stack.dependencias;
  const mapa: [string, string][] = [
    ['express', 'express'], ['next', 'next'], ['@nestjs/core', 'nestjs'], ['fastify', 'fastify'], ['koa', 'koa'], ['react', 'react'],
  ];
  for (const [dep, fw] of mapa) if (d.includes(dep)) add(stack.frameworks, fw);
  if (d.some((x) => ['mysql', 'mysql2', 'mariadb'].includes(x))) add(stack.bancos, 'mysql');
  if (d.some((x) => ['pg', 'postgres'].includes(x))) add(stack.bancos, 'postgresql');
  if (d.includes('mongoose') || d.includes('mongodb')) add(stack.bancos, 'mongodb');
  if (d.includes('sqlite3') || d.includes('better-sqlite3')) add(stack.bancos, 'sqlite');
  if (d.includes('prisma') || d.includes('@prisma/client')) add(stack.frameworks, 'prisma');
  if (d.includes('sequelize')) add(stack.frameworks, 'sequelize');
  if (linguagens.has('sql') && stack.bancos.length === 0) add(stack.bancos, 'sql');
  return stack;
}
