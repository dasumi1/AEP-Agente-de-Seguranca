import type { Severidade } from './Severidade.js';
import type { Vulnerabilidade } from './Vulnerabilidade.js';
import type { Gatilho, ModoAnalise, StackDetectada } from './ContextoAnalise.js';

/** MODEL — Relatório final do agente (saída principal). */
export interface RelatorioSeguranca {
  id: string;
  geradoEm: string;
  gatilho: Gatilho;
  modo: ModoAnalise;
  commit?: string;
  projeto: string;
  stack: StackDetectada;
  arquivosAnalisados: number;
  llmUtilizado: boolean;
  duracaoMs: number;
  resumo: {
    total: number;
    porSeveridade: Record<Severidade, number>;
  };
  /** O agente é consultivo: nunca bloqueia commits, pushes ou merges. */
  bloqueante: false;
  avisos: string[];
  vulnerabilidades: Vulnerabilidade[];
}
