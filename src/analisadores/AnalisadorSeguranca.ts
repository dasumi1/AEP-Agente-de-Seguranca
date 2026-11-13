import type { ArquivoFonte, ContextoAnalise } from '../models/ContextoAnalise.js';
import type { Regra, Vulnerabilidade } from '../models/Vulnerabilidade.js';
import { idAchado } from '../utils/id.js';
import { mascararSegredos } from '../utils/mascarar.js';

/** Comentário que suprime um achado na linha (ou na linha seguinte). */
export const MARCADOR_IGNORAR = /seguranca-ignore|security-ignore/i;

/**
 * PADRÃO GoF COMPORTAMENTAL — Chain of Responsibility (Handler abstrato).
 *
 * Cada analisador especializado é um elo da cadeia. Ele decide se o artefato
 * é de sua responsabilidade (`suporta`), executa suas verificações e repassa
 * o artefato ao próximo elo. Novos analisadores entram na cadeia sem que os
 * existentes precisem ser alterados.
 */
export abstract class AnalisadorSeguranca {
  private proximo?: AnalisadorSeguranca;

  abstract readonly nome: string;

  /** Encadeia o próximo analisador e o retorna (permite a.definirProximo(b).definirProximo(c)). */
  definirProximo(analisador: AnalisadorSeguranca): AnalisadorSeguranca {
    this.proximo = analisador;
    return analisador;
  }

  /** Método da cadeia: processa e repassa. */
  analisar(arquivo: ArquivoFonte, ctx: ContextoAnalise): Vulnerabilidade[] {
    let achados: Vulnerabilidade[] = [];
    if (this.suporta(arquivo, ctx)) {
      try {
        achados = this.verificar(arquivo, ctx).filter((a) => !this.suprimido(arquivo, a.linha));
      } catch (e) {
        ctx.avisos.push(`Analisador ${this.nome} falhou em ${arquivo.caminho}: ${(e as Error).message}`);
      }
    }
    return this.proximo ? achados.concat(this.proximo.analisar(arquivo, ctx)) : achados;
  }

  /** Nomes dos analisadores a partir deste elo (útil para log/relatório). */
  nomesDaCadeia(): string[] {
    return [this.nome, ...(this.proximo ? this.proximo.nomesDaCadeia() : [])];
  }

  protected abstract suporta(arquivo: ArquivoFonte, ctx: ContextoAnalise): boolean;
  protected abstract verificar(arquivo: ArquivoFonte, ctx: ContextoAnalise): Vulnerabilidade[];

  // ---------- utilitários compartilhados pelos elos ----------

  protected criarAchado(regra: Regra, arquivo: ArquivoFonte, linha: number, extras: Partial<Vulnerabilidade> = {}): Vulnerabilidade {
    const textoLinha = arquivo.linhas[linha - 1] ?? '';
    return {
      id: idAchado(regra.id, arquivo.caminho, linha),
      regraId: regra.id,
      titulo: regra.titulo,
      categoria: regra.categoria,
      severidade: regra.severidade,
      arquivo: arquivo.caminho,
      linha,
      trecho: mascararSegredos(textoLinha.trim()).slice(0, 300),
      explicacao: regra.explicacao,
      impacto: regra.impacto,
      recomendacao: regra.recomendacao,
      exemploCorrecao: regra.exemploCorrecao,
      owasp: regra.owasp,
      origem: 'regra',
      confianca: regra.confianca,
      ...extras,
    };
  }

  /** Percorre as linhas ignorando comentários de linha inteira. Linha é 1-based. */
  protected paraCadaLinha(arquivo: ArquivoFonte, fn: (texto: string, linha: number) => void): void {
    arquivo.linhas.forEach((texto, i) => {
      const t = texto.trim();
      if (!t || t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('--')) return;
      if (t.startsWith('#') && arquivo.linguagem !== 'dotenv' && arquivo.linguagem !== 'sql') return;
      fn(texto, i + 1);
    });
  }

  /** Converte índice de caractere no conteúdo em número de linha (1-based). */
  protected linhaDoIndice(conteudo: string, indice: number): number {
    let n = 1;
    for (let i = 0; i < indice && i < conteudo.length; i++) if (conteudo.charCodeAt(i) === 10) n++;
    return n;
  }

  /**
   * Heurística: indica se a posição `indice` da linha está dentro de um literal de texto
   * (ex.: a menção "eval()" numa mensagem não é uma chamada real a eval).
   */
  protected dentroDeString(texto: string, indice: number): boolean {
    let aberta: string | undefined;
    for (let i = 0; i < indice && i < texto.length; i++) {
      const c = texto[i];
      if (c === '\\') {
        i++;
        continue;
      }
      if (aberta) {
        if (c === aberta) aberta = undefined;
        else if (aberta === '`' && c === '$' && texto[i + 1] === '{') return false; // dentro de ${...}
      } else if (c === '"' || c === "'" || c === '`') aberta = c;
    }
    return aberta !== undefined;
  }

  /** Testa a regex considerando apenas ocorrências fora de literais de texto. */
  protected casaForaDeString(regex: RegExp, texto: string): boolean {
    const global = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
    for (const m of texto.matchAll(global)) if (!this.dentroDeString(texto, m.index ?? 0)) return true;
    return false;
  }

  /** Retorna as próximas `n` linhas a partir de `linha` (inclusive), unidas. */
  protected janela(arquivo: ArquivoFonte, linha: number, n: number): string {
    return arquivo.linhas.slice(linha - 1, linha - 1 + n).join('\n');
  }

  private suprimido(arquivo: ArquivoFonte, linha: number): boolean {
    const atual = arquivo.linhas[linha - 1] ?? '';
    const anterior = arquivo.linhas[linha - 2] ?? '';
    // marcador na própria linha, ou numa linha anterior que seja só comentário
    const anteriorEhComentario = /^\s*(\/\/|#|--|\/\*|\*)/.test(anterior);
    return MARCADOR_IGNORAR.test(atual) || (anteriorEhComentario && MARCADOR_IGNORAR.test(anterior));
  }
}
