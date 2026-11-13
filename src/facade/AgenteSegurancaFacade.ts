import path from 'node:path';
import { Pipeline } from '../pipeline/Pipeline.js';
import { PreparacaoArtefatosFiltro } from '../pipeline/filtros/PreparacaoArtefatosFiltro.js';
import { VerificacaoDeterministicaFiltro } from '../pipeline/filtros/VerificacaoDeterministicaFiltro.js';
import { AnaliseContextualLlmFiltro } from '../pipeline/filtros/AnaliseContextualLlmFiltro.js';
import { ClassificacaoRiscoFiltro } from '../pipeline/filtros/ClassificacaoRiscoFiltro.js';
import { GeracaoRelatorioFiltro } from '../pipeline/filtros/GeracaoRelatorioFiltro.js';
import { RegistroFabricas } from '../fabricas/FabricaAnalisadores.js';
import { ProvedorOpenAiCompativel, type ProvedorLlm } from '../llm/ProvedorLlm.js';
import { RepositorioRelatorios, type ResumoRelatorio } from '../apresentacao/RepositorioRelatorios.js';
import type { ContextoAnalise, Gatilho } from '../models/ContextoAnalise.js';
import type { RelatorioSeguranca } from '../models/RelatorioSeguranca.js';
import { lerConfig, type ConfigAgente } from '../config.js';

export interface SolicitacaoAnalise {
  /** Diretório do projeto. Padrão: SECURITY_AGENT_REPO_PATH ou diretório atual. */
  raiz?: string;
  gatilho?: Gatilho;
  commit?: string;
  /** Arquivos alterados (modo incremental). Vazio/ausente = repositório completo. */
  arquivos?: string[];
  usarLlm?: boolean;
  analiseProfunda?: boolean;
}

export interface DependenciasAgente {
  config?: Partial<ConfigAgente>;
  provedorLlm?: ProvedorLlm;
  registroFabricas?: RegistroFabricas;
  /** false = não grava relatórios em disco. */
  persistir?: boolean;
}

/**
 * PADRÃO GoF ESTRUTURAL — Facade.
 *
 * Única porta de entrada do agente. O restante do sistema (controller HTTP,
 * CLI, hook de Git, GitHub Actions) chama apenas `analisar()`, sem conhecer
 * filtros, fábricas, analisadores, LLM ou persistência.
 */
export class AgenteSegurancaFacade {
  readonly config: ConfigAgente;
  private readonly provedorLlm: ProvedorLlm;
  private readonly registro: RegistroFabricas;
  private readonly repositorio: RepositorioRelatorios;
  private readonly persistir: boolean;

  constructor(deps: DependenciasAgente = {}) {
    this.config = { ...lerConfig(), ...deps.config };
    this.provedorLlm = deps.provedorLlm ?? ProvedorOpenAiCompativel.doAmbiente();
    this.registro = deps.registroFabricas ?? new RegistroFabricas();
    this.repositorio = new RepositorioRelatorios(this.config.diretorioRelatorios);
    this.persistir = deps.persistir ?? true;
  }

  private montarPipeline(): Pipeline {
    return new Pipeline([
      new PreparacaoArtefatosFiltro(),
      new VerificacaoDeterministicaFiltro(this.registro),
      new AnaliseContextualLlmFiltro(this.provedorLlm, {
        maxArquivos: this.config.llmMaxArquivos,
        maxCaracteresPorArquivo: this.config.llmMaxCaracteres,
        concorrencia: this.config.llmConcorrencia,
      }),
      new ClassificacaoRiscoFiltro(),
      new GeracaoRelatorioFiltro(this.persistir ? this.repositorio : undefined),
    ]);
  }

  async analisar(s: SolicitacaoAnalise = {}): Promise<RelatorioSeguranca> {
    const ctx: ContextoAnalise = {
      raiz: path.resolve(s.raiz ?? this.config.raizProjeto),
      gatilho: s.gatilho ?? 'sob-demanda',
      modo: s.arquivos?.length ? 'incremental' : 'completo',
      commit: s.commit,
      arquivosAlvo: s.arquivos,
      arquivos: [],
      stack: { ecossistemas: [], frameworks: [], bancos: [], dependencias: [] },
      achados: [],
      avisos: [],
      opcoes: { usarLlm: s.usarLlm ?? true, analiseProfunda: s.analiseProfunda ?? false },
      llmUtilizado: false,
      inicio: Date.now(),
    };
    const final = await this.montarPipeline().processar(ctx);
    return final.relatorio!;
  }

  listarRelatorios(limite?: number): ResumoRelatorio[] {
    return this.repositorio.listar(limite);
  }

  obterRelatorio(id: string): RelatorioSeguranca | undefined {
    return this.repositorio.obter(id);
  }

  get llmDisponivel(): boolean {
    return this.provedorLlm.disponivel();
  }

  get etapas(): string[] {
    return this.montarPipeline().etapas;
  }
}
