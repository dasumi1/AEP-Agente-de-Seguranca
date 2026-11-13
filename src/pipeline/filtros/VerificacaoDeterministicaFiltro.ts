import type { Filtro } from '../Pipeline.js';
import type { ContextoAnalise } from '../../models/ContextoAnalise.js';
import { RegistroFabricas } from '../../fabricas/FabricaAnalisadores.js';

/**
 * FILTRO 2 — Validadores de segurança (regras determinísticas).
 * Usa a fábrica adequada à stack (Factory Method) e passa cada arquivo pela
 * cadeia de analisadores (Chain of Responsibility).
 */
export class VerificacaoDeterministicaFiltro implements Filtro {
  readonly nome = 'Validadores de segurança';
  readonly essencial = true;

  constructor(private readonly registro = new RegistroFabricas()) {}

  async executar(ctx: ContextoAnalise): Promise<ContextoAnalise> {
    const fabrica = this.registro.obter(ctx.stack);
    const cadeia = fabrica.criarCadeia();
    for (const arquivo of ctx.arquivos) {
      ctx.achados.push(...cadeia.analisar(arquivo, ctx));
    }
    return ctx;
  }
}
