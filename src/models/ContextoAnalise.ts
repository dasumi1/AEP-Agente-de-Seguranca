import type { Vulnerabilidade } from './Vulnerabilidade.js';
import type { RelatorioSeguranca } from './RelatorioSeguranca.js';

export type Gatilho = 'push' | 'commit' | 'sob-demanda';
export type ModoAnalise = 'completo' | 'incremental';
export type TipoArquivo = 'codigo' | 'esquema-banco' | 'config' | 'env';

/** MODEL — Artefato preparado para análise. */
export interface ArquivoFonte {
  /** Caminho relativo à raiz do projeto, sempre com "/". */
  caminho: string;
  conteudo: string;
  linhas: string[];
  linguagem: string;
  tipo: TipoArquivo;
}

/** MODEL — Stack detectada no projeto analisado (torna o agente independente de domínio). */
export interface StackDetectada {
  ecossistemas: string[]; // ex.: ['node'], ['python'], ['php']
  frameworks: string[]; // ex.: ['express', 'next']
  bancos: string[]; // ex.: ['mysql']
  dependencias: string[];
}

export interface OpcoesAnalise {
  usarLlm: boolean;
  /** Sob demanda: também envia ao LLM arquivos sensíveis sem achados determinísticos. */
  analiseProfunda: boolean;
}

/** MODEL — Objeto que trafega pelos "pipes" entre os filtros. */
export interface ContextoAnalise {
  raiz: string;
  gatilho: Gatilho;
  modo: ModoAnalise;
  commit?: string;
  /** Em modo incremental, os arquivos alterados (relativos à raiz). */
  arquivosAlvo?: string[];
  arquivos: ArquivoFonte[];
  stack: StackDetectada;
  achados: Vulnerabilidade[];
  avisos: string[];
  opcoes: OpcoesAnalise;
  llmUtilizado: boolean;
  inicio: number;
  relatorio?: RelatorioSeguranca;
}
