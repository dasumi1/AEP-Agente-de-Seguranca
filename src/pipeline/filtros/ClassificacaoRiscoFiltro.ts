import type { Filtro } from '../Pipeline.js';
import type { ContextoAnalise } from '../../models/ContextoAnalise.js';
import type { Vulnerabilidade } from '../../models/Vulnerabilidade.js';
import { maiorSeveridade, pesoSeveridade, Severidade } from '../../models/Severidade.js';

/**
 * FILTRO 4 — Classificação do risco (Baixo / Médio / Alto / Crítico).
 *
 * Política de consolidação:
 *  - Regra de confiança ALTA: a severidade da regra é o piso; o LLM só pode elevar.
 *  - Regra de confiança média/baixa: prevalece a sugestão do LLM (ele vê o contexto).
 *  - Possível falso positivo apontado pelo LLM em regra não-alta: rebaixa para Baixo
 *    e mantém no relatório com observação (nada é descartado silenciosamente).
 * Por fim remove duplicados e ordena por severidade.
 */
export class ClassificacaoRiscoFiltro implements Filtro {
  readonly nome = 'Classificação do risco';
  readonly essencial = true;

  async executar(ctx: ContextoAnalise): Promise<ContextoAnalise> {
    const vistos = new Map<string, Vulnerabilidade>();

    for (const a of ctx.achados) {
      if (a.possivelFalsoPositivo && a.confianca !== 'alta') {
        a.severidade = Severidade.BAIXO;
        a.confianca = 'baixa';
        a.observacao = [a.observacao, 'A análise contextual indicou possível falso positivo; confirme manualmente.'].filter(Boolean).join(' ');
      } else if (a.severidadeSugeridaLlm) {
        a.severidade = a.confianca === 'alta' ? maiorSeveridade(a.severidade, a.severidadeSugeridaLlm) : a.severidadeSugeridaLlm;
      }

      const chave = `${a.arquivo}|${a.linha}|${a.regraId}`;
      const existente = vistos.get(chave);
      if (!existente || pesoSeveridade(a.severidade) > pesoSeveridade(existente.severidade)) vistos.set(chave, a);
    }

    ctx.achados = [...vistos.values()].sort(
      (x, y) =>
        pesoSeveridade(y.severidade) - pesoSeveridade(x.severidade) ||
        x.arquivo.localeCompare(y.arquivo) ||
        x.linha - y.linha,
    );
    return ctx;
  }
}
