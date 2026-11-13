import path from 'node:path';

/** Carrega .env do diretório atual, se existir (recurso nativo do Node ≥ 20.12). */
export function carregarEnv(): void {
  try {
    process.loadEnvFile?.();
  } catch {
    /* sem .env: usa apenas variáveis do ambiente */
  }
}

export interface ConfigAgente {
  /** Repositório analisado pela API/webhook. */
  raizProjeto: string;
  diretorioRelatorios: string;
  llmMaxArquivos: number;
  llmMaxCaracteres: number;
  llmConcorrencia: number;
  /** Token exigido nas rotas da API (Authorization: Bearer ...). */
  tokenApi?: string;
  /** Segredo configurado no webhook do GitHub. */
  segredoWebhook?: string;
  /** Executa `git pull --ff-only` antes de analisar um push recebido via webhook. */
  autoPull: boolean;
}

export function lerConfig(env: NodeJS.ProcessEnv = process.env): ConfigAgente {
  const raizProjeto = path.resolve(env.SECURITY_AGENT_REPO_PATH ?? process.cwd());
  return {
    raizProjeto,
    diretorioRelatorios: path.resolve(env.SECURITY_AGENT_REPORTS_DIR ?? path.join(raizProjeto, 'relatorios-seguranca')),
    llmMaxArquivos: Number(env.LLM_MAX_ARQUIVOS ?? 15),
    llmMaxCaracteres: Number(env.LLM_MAX_CARACTERES ?? 24_000),
    llmConcorrencia: Number(env.LLM_CONCORRENCIA ?? 3),
    tokenApi: env.SECURITY_AGENT_TOKEN || undefined,
    segredoWebhook: env.GITHUB_WEBHOOK_SECRET || undefined,
    autoPull: env.SECURITY_AGENT_AUTO_PULL === 'true',
  };
}
