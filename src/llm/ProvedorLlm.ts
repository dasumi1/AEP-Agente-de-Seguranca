/**
 * Abstração do modelo de linguagem. O agente depende desta interface, não de
 * um fornecedor específico (OpenAI/ChatGPT hoje, outro amanhã).
 */
export interface ProvedorLlm {
  readonly nome: string;
  disponivel(): boolean;
  /** Envia mensagens e retorna o JSON (já parseado) produzido pelo modelo. */
  gerarJson(sistema: string, usuario: string): Promise<unknown>;
}

/** Provedor nulo: usado quando não há chave configurada (o agente segue só com regras). */
export class ProvedorLlmNulo implements ProvedorLlm {
  readonly nome = 'nenhum';
  disponivel(): boolean {
    return false;
  }
  async gerarJson(): Promise<unknown> {
    throw new Error('Nenhum LLM configurado');
  }
}

export interface ConfigOpenAi {
  apiKey: string;
  modelo: string;
  baseUrl: string;
  timeoutMs: number;
}

/**
 * Provedor compatível com a API de Chat Completions da OpenAI (ChatGPT).
 * Também funciona com serviços compatíveis (Azure OpenAI, OpenRouter, Ollama...)
 * trocando LLM_BASE_URL. Usa fetch nativo do Node — sem dependências extras.
 */
export class ProvedorOpenAiCompativel implements ProvedorLlm {
  readonly nome: string;

  constructor(private readonly config: ConfigOpenAi) {
    this.nome = `openai-compativel:${config.modelo}`;
  }

  static doAmbiente(env: NodeJS.ProcessEnv = process.env): ProvedorLlm {
    const apiKey = env.LLM_API_KEY ?? env.OPENAI_API_KEY;
    if (!apiKey) return new ProvedorLlmNulo();
    return new ProvedorOpenAiCompativel({
      apiKey,
      modelo: env.LLM_MODEL ?? 'gpt-4o-mini',
      baseUrl: (env.LLM_BASE_URL ?? 'https://api.openai.com/v1').replace(/\/$/, ''),
      timeoutMs: Number(env.LLM_TIMEOUT_MS ?? 60_000),
    });
  }

  disponivel(): boolean {
    return Boolean(this.config.apiKey);
  }

  async gerarJson(sistema: string, usuario: string): Promise<unknown> {
    const resposta = await fetch(`${this.config.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify({
        model: this.config.modelo,
        temperature: 0,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: sistema },
          { role: 'user', content: usuario },
        ],
      }),
      signal: AbortSignal.timeout(this.config.timeoutMs),
    });
    if (!resposta.ok) {
      const corpo = (await resposta.text()).slice(0, 300);
      throw new Error(`LLM respondeu HTTP ${resposta.status}: ${corpo}`);
    }
    const dados = (await resposta.json()) as { choices?: { message?: { content?: string } }[] };
    const texto = dados.choices?.[0]?.message?.content;
    if (!texto) throw new Error('Resposta do LLM sem conteúdo');
    return extrairJson(texto);
  }
}

/** Aceita JSON puro ou envolto em ```json ... ```. */
export function extrairJson(texto: string): unknown {
  const limpo = texto.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  try {
    return JSON.parse(limpo);
  } catch {
    const inicio = limpo.indexOf('{');
    const fim = limpo.lastIndexOf('}');
    if (inicio >= 0 && fim > inicio) return JSON.parse(limpo.slice(inicio, fim + 1));
    throw new Error('Resposta do LLM não é um JSON válido');
  }
}
