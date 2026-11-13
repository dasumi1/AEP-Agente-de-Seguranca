import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { AgenteSegurancaFacade, SolicitacaoAnalise } from '../facade/AgenteSegurancaFacade.js';
import { resumoConsole } from '../apresentacao/ApresentadorMarkdown.js';

const execFileAsync = promisify(execFile);

/** Requisição independente de framework (adaptada a partir do Express ou do node:http). */
export interface RequisicaoAgente {
  cabecalhos: Record<string, string | string[] | undefined>;
  corpoBruto?: Buffer;
  corpo?: unknown;
  parametros?: Record<string, string>;
}

export interface RespostaAgente {
  status: number;
  corpo: unknown;
}

const ok = (corpo: unknown, status = 200): RespostaAgente => ({ status, corpo });
const erro = (status: number, mensagem: string): RespostaAgente => ({ status, corpo: { erro: mensagem } });

function cabecalho(req: RequisicaoAgente, nome: string): string | undefined {
  const v = req.cabecalhos[nome.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/** Comparação em tempo constante (evita ataques de tempo na validação de tokens). */
function iguaisSeguro(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

/**
 * GRASP CONTROLLER (+ "C" do MVC).
 *
 * Primeiro objeto a receber os eventos do sistema (requisição sob demanda,
 * webhook de push). Valida e traduz a entrada e delega TODO o trabalho à
 * Facade — não contém nenhuma regra de detecção de vulnerabilidades.
 */
export class ControladorSeguranca {
  private readonly analisesEmAndamento = new Set<Promise<unknown>>();

  constructor(
    private readonly agente: AgenteSegurancaFacade,
    private readonly log: (msg: string) => void = (m) => console.log(m),
  ) {}

  /** Exige `Authorization: Bearer <SECURITY_AGENT_TOKEN>`. Falha fechada se o token não estiver configurado. */
  autenticar(req: RequisicaoAgente): RespostaAgente | undefined {
    const esperado = this.agente.config.tokenApi;
    if (!esperado) return erro(503, 'SECURITY_AGENT_TOKEN não configurado no servidor.');
    const recebido = cabecalho(req, 'authorization')?.replace(/^Bearer\s+/i, '');
    if (!recebido || !iguaisSeguro(recebido, esperado)) return erro(401, 'Token inválido ou ausente.');
    return undefined;
  }

  status(req: RequisicaoAgente): RespostaAgente {
    const negado = this.autenticar(req);
    if (negado) return negado;
    return ok({
      agente: 'Agente de Segurança',
      projeto: this.agente.config.raizProjeto,
      llmDisponivel: this.agente.llmDisponivel,
      etapas: this.agente.etapas,
      analisesEmAndamento: this.analisesEmAndamento.size,
    });
  }

  /** POST /analises — acionamento sob demanda pelo desenvolvedor. */
  async analisarSobDemanda(req: RequisicaoAgente): Promise<RespostaAgente> {
    const negado = this.autenticar(req);
    if (negado) return negado;

    const corpo = (req.corpo ?? {}) as Record<string, unknown>;
    if (typeof corpo !== 'object' || Array.isArray(corpo)) return erro(400, 'Corpo deve ser um objeto JSON.');
    const solicitacao: SolicitacaoAnalise = { gatilho: 'sob-demanda' };

    if (corpo.arquivos !== undefined) {
      if (!Array.isArray(corpo.arquivos) || corpo.arquivos.length > 5000 || !corpo.arquivos.every((a) => typeof a === 'string' && a.length < 500)) {
        return erro(400, '"arquivos" deve ser uma lista de caminhos relativos (texto).');
      }
      solicitacao.arquivos = corpo.arquivos as string[];
    }
    if (corpo.analiseProfunda !== undefined) solicitacao.analiseProfunda = corpo.analiseProfunda === true;
    if (corpo.usarLlm !== undefined) solicitacao.usarLlm = corpo.usarLlm !== false;
    if (typeof corpo.commit === 'string' && /^[0-9a-f]{7,40}$/i.test(corpo.commit)) solicitacao.commit = corpo.commit;

    try {
      const relatorio = await this.acompanhar(this.agente.analisar(solicitacao));
      return ok(relatorio);
    } catch (e) {
      this.log(`[Agente de Segurança] falha na análise: ${(e as Error).message}`);
      return erro(500, 'Falha ao executar a análise de segurança.');
    }
  }

  /** POST /webhooks/github — acionamento por evento a cada push. Responde 202 e analisa em segundo plano. */
  receberWebhookGithub(req: RequisicaoAgente): RespostaAgente {
    const segredo = this.agente.config.segredoWebhook;
    if (!segredo) return erro(503, 'GITHUB_WEBHOOK_SECRET não configurado no servidor.');
    if (!req.corpoBruto) return erro(400, 'Corpo bruto ausente (use express.raw no webhook).');

    const assinatura = cabecalho(req, 'x-hub-signature-256') ?? '';
    const esperada = 'sha256=' + createHmac('sha256', segredo).update(req.corpoBruto).digest('hex');
    if (!iguaisSeguro(assinatura, esperada)) return erro(401, 'Assinatura do webhook inválida.');

    const evento = cabecalho(req, 'x-github-event');
    if (evento === 'ping') return ok({ mensagem: 'pong' });
    if (evento !== 'push') return ok({ mensagem: `Evento "${evento}" ignorado.` });

    let payload: {
      after?: string;
      ref?: string;
      deleted?: boolean;
      commits?: { added?: string[]; modified?: string[] }[];
      head_commit?: { added?: string[]; modified?: string[] } | null;
    };
    try {
      payload = JSON.parse(req.corpoBruto.toString('utf8'));
    } catch {
      return erro(400, 'Payload JSON inválido.');
    }
    if (payload.deleted) return ok({ mensagem: 'Branch removida: nada a analisar.' });

    const commits = [...(payload.commits ?? []), ...(payload.head_commit ? [payload.head_commit] : [])];
    const arquivos = [...new Set(commits.flatMap((c) => [...(c.added ?? []), ...(c.modified ?? [])]))];
    const commit = payload.after && /^[0-9a-f]{40}$/i.test(payload.after) ? payload.after : undefined;

    const execucao = (async () => {
      if (this.agente.config.autoPull) {
        await execFileAsync('git', ['-C', this.agente.config.raizProjeto, 'pull', '--ff-only']).catch((e) =>
          this.log(`[Agente de Segurança] git pull falhou: ${(e as Error).message}`),
        );
      }
      const relatorio = await this.agente.analisar({
        gatilho: 'push',
        commit,
        // Push muito grande (o GitHub limita a lista) => análise completa
        arquivos: arquivos.length > 0 && commits.length < 20 ? arquivos : undefined,
      });
      this.log(resumoConsole(relatorio));
    })().catch((e) => this.log(`[Agente de Segurança] falha na análise do push: ${(e as Error).message}`));
    this.acompanhar(execucao);

    return ok({ mensagem: 'Análise de segurança iniciada.', commit, arquivos: arquivos.length, bloqueante: false }, 202);
  }

  listarRelatorios(req: RequisicaoAgente): RespostaAgente {
    const negado = this.autenticar(req);
    if (negado) return negado;
    return ok(this.agente.listarRelatorios());
  }

  obterRelatorio(req: RequisicaoAgente): RespostaAgente {
    const negado = this.autenticar(req);
    if (negado) return negado;
    const relatorio = this.agente.obterRelatorio(req.parametros?.id ?? '');
    return relatorio ? ok(relatorio) : erro(404, 'Relatório não encontrado.');
  }

  /** Aguarda análises em segundo plano (útil em testes e no desligamento do servidor). */
  async aguardarAnalises(): Promise<void> {
    await Promise.allSettled([...this.analisesEmAndamento]);
  }

  private acompanhar<T>(p: Promise<T>): Promise<T> {
    this.analisesEmAndamento.add(p);
    p.finally(() => this.analisesEmAndamento.delete(p)).catch(() => undefined);
    return p;
  }
}
