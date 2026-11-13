/**
 * MODEL — Níveis de severidade usados pelo agente.
 * Baixo | Médio | Alto | Crítico
 */
export enum Severidade {
  BAIXO = 'Baixo',
  MEDIO = 'Médio',
  ALTO = 'Alto',
  CRITICO = 'Crítico',
}

const PESO: Record<Severidade, number> = {
  [Severidade.BAIXO]: 1,
  [Severidade.MEDIO]: 2,
  [Severidade.ALTO]: 3,
  [Severidade.CRITICO]: 4,
};

export const TODAS_SEVERIDADES: Severidade[] = [
  Severidade.CRITICO,
  Severidade.ALTO,
  Severidade.MEDIO,
  Severidade.BAIXO,
];

export function pesoSeveridade(s: Severidade): number {
  return PESO[s];
}

export function maiorSeveridade(a: Severidade, b: Severidade): Severidade {
  return PESO[a] >= PESO[b] ? a : b;
}

/** Converte texto livre (ex.: resposta do LLM) em Severidade. Retorna undefined se não reconhecer. */
export function parseSeveridade(valor: unknown): Severidade | undefined {
  if (typeof valor !== 'string') return undefined;
  const v = valor
    .trim()
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '');
  if (['baixo', 'baixa', 'low'].includes(v)) return Severidade.BAIXO;
  if (['medio', 'media', 'medium', 'moderate'].includes(v)) return Severidade.MEDIO;
  if (['alto', 'alta', 'high'].includes(v)) return Severidade.ALTO;
  if (['critico', 'critica', 'critical'].includes(v)) return Severidade.CRITICO;
  return undefined;
}
