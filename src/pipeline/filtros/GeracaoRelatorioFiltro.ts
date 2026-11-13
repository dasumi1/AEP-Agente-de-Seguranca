import path from 'node:path';
import type { Filtro } from '../Pipeline.js';
import type { ContextoAnalise } from '../../models/ContextoAnalise.js';
import type { RelatorioSeguranca } from '../../models/RelatorioSeguranca.js';
import { Severidade, TODAS_SEVERIDADES } from '../../models/Severidade.js';
import { idRelatorio } from '../../utils/id.js';
import type { RepositorioRelatorios } from '../../apresentacao/RepositorioRelatorios.js';

/** FILTRO 5 — Geração do relatório de segurança (JSON + Markdown). */
export class GeracaoRelatorioFiltro implements Filtro {
  readonly nome = 'Relatório de segurança';
  readonly essencial = true;

  constructor(private readonly repositorio?: RepositorioRelatorios) {}

  async executar(ctx: ContextoAnalise): Promise<ContextoAnalise> {
    const porSeveridade = Object.fromEntries(TODAS_SEVERIDADES.map((s) => [s, 0])) as Record<Severidade, number>;
    ctx.achados.forEach((a) => porSeveridade[a.severidade]++);

    const relatorio: RelatorioSeguranca = {
      id: idRelatorio(),
      geradoEm: new Date().toISOString(),
      gatilho: ctx.gatilho,
      modo: ctx.modo,
      commit: ctx.commit,
      projeto: path.basename(path.resolve(ctx.raiz)),
      stack: ctx.stack,
      arquivosAnalisados: ctx.arquivos.length,
      llmUtilizado: ctx.llmUtilizado,
      duracaoMs: Date.now() - ctx.inicio,
      resumo: { total: ctx.achados.length, porSeveridade },
      bloqueante: false,
      avisos: ctx.avisos,
      vulnerabilidades: ctx.achados,
    };

    if (this.repositorio) {
      try {
        this.repositorio.salvar(relatorio);
      } catch (e) {
        relatorio.avisos.push(`Não foi possível salvar o relatório: ${(e as Error).message}`);
      }
    }
    ctx.relatorio = relatorio;
    return ctx;
  }
}
