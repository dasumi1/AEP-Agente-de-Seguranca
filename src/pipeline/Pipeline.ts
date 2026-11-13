import type { ContextoAnalise } from '../models/ContextoAnalise.js';

/**
 * ESTILO ARQUITETURAL — Pipe-and-Filter.
 *
 * Cada filtro recebe o contexto, transforma-o e o entrega ao próximo.
 * O "pipe" é o próprio objeto ContextoAnalise.
 */
export interface Filtro {
  readonly nome: string;
  /** Filtros essenciais interrompem o pipeline em caso de erro; os demais apenas registram aviso. */
  readonly essencial: boolean;
  executar(ctx: ContextoAnalise): Promise<ContextoAnalise>;
}

export class Pipeline {
  constructor(private readonly filtros: Filtro[]) {}

  async processar(ctx: ContextoAnalise): Promise<ContextoAnalise> {
    let atual = ctx;
    for (const filtro of this.filtros) {
      try {
        atual = await filtro.executar(atual);
      } catch (e) {
        const msg = `Etapa "${filtro.nome}" falhou: ${(e as Error).message}`;
        if (filtro.essencial) throw new Error(msg);
        atual.avisos.push(msg);
      }
    }
    return atual;
  }

  get etapas(): string[] {
    return this.filtros.map((f) => f.nome);
  }
}
