import type { Filtro } from '../Pipeline.js';
import type { ArquivoFonte, ContextoAnalise } from '../../models/ContextoAnalise.js';
import { Categoria, TODAS_CATEGORIAS, type Vulnerabilidade } from '../../models/Vulnerabilidade.js';
import { parseSeveridade, Severidade } from '../../models/Severidade.js';
import type { ProvedorLlm } from '../../llm/ProvedorLlm.js';
import { PROMPT_SISTEMA, montarPromptArquivo } from '../../llm/prompts.js';
import { idAchado } from '../../utils/id.js';
import { mascararSegredos } from '../../utils/mascarar.js';
import { ehArquivoDeCodigo } from '../../utils/arquivos.js';

export interface ConfigLlmFiltro {
  maxArquivos: number;
  maxCaracteresPorArquivo: number;
  concorrencia: number;
}

/** Arquivos com nomes que costumam concentrar lógica sensível. */
const ARQUIVO_SENSIVEL = /(auth|login|sess|token|jwt|usuario|user|perfil|role|permiss|admin|route|rota|controller|middleware|api\/|db|database|banco|model|repositor|service)/i;

const texto = (v: unknown, max = 4000): string | undefined =>
  typeof v === 'string' && v.trim() ? mascararSegredos(v.trim()).slice(0, max) : undefined;

/**
 * FILTRO 3 — Análise contextual via LLM (prompt estruturado).
 * Enriquece os achados das regras (explicação, impacto, código corrigido),
 * sinaliza falsos positivos e acrescenta falhas de lógica que regras não pegam.
 * Se o LLM não estiver configurado ou falhar, o pipeline segue apenas com as regras.
 */
export class AnaliseContextualLlmFiltro implements Filtro {
  readonly nome = 'Análise contextual via LLM';
  readonly essencial = false;

  constructor(
    private readonly provedor: ProvedorLlm,
    private readonly config: ConfigLlmFiltro = { maxArquivos: 15, maxCaracteresPorArquivo: 24_000, concorrencia: 3 },
  ) {}

  async executar(ctx: ContextoAnalise): Promise<ContextoAnalise> {
    if (!ctx.opcoes.usarLlm) return ctx;
    if (!this.provedor.disponivel()) {
      ctx.avisos.push('LLM não configurado (defina LLM_API_KEY/OPENAI_API_KEY): relatório gerado apenas com regras determinísticas.');
      return ctx;
    }

    const alvos = this.selecionarArquivos(ctx);
    let falhas = 0;
    const fila = [...alvos];
    const trabalhador = async () => {
      for (let arq = fila.shift(); arq; arq = fila.shift()) {
        try {
          await this.analisarArquivo(arq, ctx);
          ctx.llmUtilizado = true;
        } catch (e) {
          falhas++;
          if (falhas <= 3) ctx.avisos.push(`LLM falhou em ${arq.caminho}: ${(e as Error).message}`);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, this.config.concorrencia) }, trabalhador));
    if (falhas > 3) ctx.avisos.push(`LLM falhou em ${falhas} arquivo(s) no total.`);
    return ctx;
  }

  private selecionarArquivos(ctx: ContextoAnalise): ArquivoFonte[] {
    const comAchados = new Set(ctx.achados.map((a) => a.arquivo));
    const prioridade = ctx.arquivos.filter((a) => comAchados.has(a.caminho) && a.tipo !== 'env');
    const extras = ctx.opcoes.analiseProfunda
      ? ctx.arquivos.filter((a) => !comAchados.has(a.caminho) && ehArquivoDeCodigo(a.linguagem) && ARQUIVO_SENSIVEL.test(a.caminho))
      : [];
    const selecionados = [...prioridade, ...extras];
    if (selecionados.length > this.config.maxArquivos) {
      ctx.avisos.push(`Análise via LLM limitada a ${this.config.maxArquivos} de ${selecionados.length} arquivos (LLM_MAX_ARQUIVOS).`);
    }
    return selecionados.slice(0, this.config.maxArquivos);
  }

  private async analisarArquivo(arquivo: ArquivoFonte, ctx: ContextoAnalise): Promise<void> {
    const achadosDoArquivo = ctx.achados.filter((a) => a.arquivo === arquivo.caminho);
    const prompt = montarPromptArquivo(arquivo, achadosDoArquivo, ctx.stack, this.config.maxCaracteresPorArquivo);
    const resposta = (await this.provedor.gerarJson(PROMPT_SISTEMA, prompt)) as {
      enriquecimentos?: unknown;
      novosAchados?: unknown;
    };

    // 1) Enriquecimento dos achados das regras
    const porId = new Map(achadosDoArquivo.map((a) => [a.id, a]));
    for (const e of Array.isArray(resposta?.enriquecimentos) ? resposta.enriquecimentos : []) {
      const alvo = porId.get(String((e as { id?: unknown })?.id));
      if (!alvo) continue;
      const r = e as Record<string, unknown>;
      alvo.explicacao = texto(r.explicacao) ?? alvo.explicacao;
      alvo.impacto = texto(r.impacto) ?? alvo.impacto;
      alvo.recomendacao = texto(r.recomendacao) ?? alvo.recomendacao;
      alvo.exemploCorrecao = texto(r.exemploCorrecao, 6000) ?? alvo.exemploCorrecao;
      alvo.severidadeSugeridaLlm = parseSeveridade(r.severidadeSugerida);
      alvo.possivelFalsoPositivo = r.falsoPositivo === true;
      alvo.origem = 'regra+llm';
    }

    // 2) Novos achados (validados antes de entrar no relatório)
    for (const n of Array.isArray(resposta?.novosAchados) ? resposta.novosAchados : []) {
      const r = n as Record<string, unknown>;
      const titulo = texto(r.titulo, 200);
      const categoria = TODAS_CATEGORIAS.find((c) => c === r.categoria) ?? (titulo ? Categoria.VALIDACAO_ENTRADA : undefined);
      const linha = Number(r.linha);
      if (!titulo || !categoria || !Number.isInteger(linha) || linha < 1 || linha > arquivo.linhas.length) continue;
      const regraId = 'LLM';
      const id = idAchado(`${regraId}:${titulo}`, arquivo.caminho, linha);
      if (ctx.achados.some((a) => a.arquivo === arquivo.caminho && a.linha === linha && a.categoria === categoria)) continue;
      ctx.achados.push({
        id,
        regraId,
        titulo,
        categoria,
        severidade: parseSeveridade(r.severidade) ?? Severidade.MEDIO,
        arquivo: arquivo.caminho,
        linha,
        trecho: mascararSegredos(arquivo.linhas[linha - 1].trim()).slice(0, 300),
        explicacao: texto(r.explicacao) ?? 'Identificado pela análise contextual.',
        impacto: texto(r.impacto) ?? 'Não informado.',
        recomendacao: texto(r.recomendacao) ?? 'Revisar o trecho indicado.',
        exemploCorrecao: texto(r.exemploCorrecao, 6000) ?? '',
        owasp: texto(r.owasp, 120) ?? '—',
        origem: 'llm',
        confianca: 'media',
      } satisfies Vulnerabilidade);
    }
  }
}
