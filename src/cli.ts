#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { carregarEnv } from './config.js';
import { AgenteSegurancaFacade } from './facade/AgenteSegurancaFacade.js';
import { resumoConsole } from './apresentacao/ApresentadorMarkdown.js';
import type { Gatilho } from './models/ContextoAnalise.js';

const AJUDA = `Agente de Segurança — uso:
  npm run analisar -- [diretório] [opções]

Opções:
  --ultimo-commit        analisa só os arquivos alterados no último commit (usado pelo hook)
  --desde <ref>          analisa os arquivos alterados entre <ref> e HEAD (ex.: push com vários commits)
  --arquivos a.ts,b.ts   analisa apenas os arquivos indicados
  --gatilho <tipo>       sob-demanda (padrão) | commit | push
  --sem-llm              usa apenas as regras determinísticas
  --profundo             também envia ao LLM arquivos sensíveis sem achados
  --saida <dir>          diretório dos relatórios (padrão: <projeto>/relatorios-seguranca)
  --json                 imprime o relatório completo em JSON
  -h, --ajuda            mostra esta ajuda

O agente é consultivo: sempre termina com código 0 e nunca bloqueia o fluxo.`;

function git(raiz: string, args: string[]): string {
  return execFileSync('git', ['-C', raiz, ...args], { encoding: 'utf8' }).trim();
}

async function main(): Promise<void> {
  process.stdout.on('error', () => undefined); // ex.: saída redirecionada para `head`
  carregarEnv();
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      'ultimo-commit': { type: 'boolean' },
      desde: { type: 'string' },
      arquivos: { type: 'string' },
      gatilho: { type: 'string' },
      'sem-llm': { type: 'boolean' },
      profundo: { type: 'boolean' },
      saida: { type: 'string' },
      json: { type: 'boolean' },
      ajuda: { type: 'boolean', short: 'h' },
    },
  });
  if (values.ajuda) {
    console.log(AJUDA);
    return;
  }

  const raiz = path.resolve(positionals[0] ?? process.env.SECURITY_AGENT_REPO_PATH ?? process.cwd());
  let arquivos = values.arquivos?.split(',').map((a) => a.trim()).filter(Boolean);
  let commit: string | undefined;
  let gatilho = (values.gatilho ?? 'sob-demanda') as Gatilho;
  if (!['sob-demanda', 'commit', 'push'].includes(gatilho)) gatilho = 'sob-demanda';

  if (values.desde) {
    try {
      if (!/^[\w./~^-]+$/.test(values.desde)) throw new Error('referência inválida');
      commit = git(raiz, ['rev-parse', 'HEAD']);
      arquivos = git(raiz, ['diff', '--name-only', '--diff-filter=AM', `${values.desde}..HEAD`]).split('\n').filter(Boolean);
      if (arquivos.length === 0) {
        console.log('[Agente de Segurança] Nenhum arquivo adicionado/modificado no intervalo.');
        return;
      }
    } catch (e) {
      console.warn(`[Agente de Segurança] Não foi possível comparar com ${values.desde} (${(e as Error).message}); analisando o projeto completo.`);
      arquivos = undefined;
    }
  } else if (values['ultimo-commit']) {
    try {
      commit = git(raiz, ['rev-parse', 'HEAD']);
      arquivos = git(raiz, ['diff-tree', '--no-commit-id', '--name-only', '--diff-filter=AM', '-r', '--root', 'HEAD'])
        .split('\n')
        .filter(Boolean);
      if (!values.gatilho) gatilho = 'commit';
      if (arquivos.length === 0) {
        console.log('[Agente de Segurança] Último commit não alterou arquivos analisáveis.');
        return;
      }
    } catch (e) {
      console.warn(`[Agente de Segurança] Não foi possível ler o último commit (${(e as Error).message}); analisando o projeto completo.`);
    }
  }

  const agente = new AgenteSegurancaFacade({
    config: { raizProjeto: raiz, ...(values.saida ? { diretorioRelatorios: path.resolve(values.saida) } : { diretorioRelatorios: path.join(raiz, 'relatorios-seguranca') }) },
  });
  const relatorio = await agente.analisar({
    raiz,
    gatilho,
    commit,
    arquivos,
    usarLlm: !values['sem-llm'],
    analiseProfunda: values.profundo ?? false,
  });

  if (values.json) console.log(JSON.stringify(relatorio, null, 2));
  else {
    console.log(resumoConsole(relatorio));
    for (const a of relatorio.avisos) console.log(`  ⚠ ${a}`);
    console.log(`  Relatório: ${path.join(agente.config.diretorioRelatorios, `relatorio-${relatorio.id}.md`)}`);
  }
}

main().catch((e) => {
  // Consultivo: registra o erro, mas não interrompe commits/pipelines.
  console.error(`[Agente de Segurança] Erro: ${(e as Error).message}`);
}).finally(() => {
  process.exitCode = 0;
});
