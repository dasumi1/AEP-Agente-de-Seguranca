import type { AnalisadorSeguranca } from '../analisadores/AnalisadorSeguranca.js';
import { AnalisadorSegredos } from '../analisadores/AnalisadorSegredos.js';
import { AnalisadorSqlInjection } from '../analisadores/AnalisadorSqlInjection.js';
import { AnalisadorValidacaoEntrada } from '../analisadores/AnalisadorValidacaoEntrada.js';
import { AnalisadorAutenticacao } from '../analisadores/AnalisadorAutenticacao.js';
import { AnalisadorAutorizacao } from '../analisadores/AnalisadorAutorizacao.js';
import { AnalisadorPermissoes } from '../analisadores/AnalisadorPermissoes.js';
import { AnalisadorApi } from '../analisadores/AnalisadorApi.js';
import { AnalisadorEsquemaBanco } from '../analisadores/AnalisadorEsquemaBanco.js';
import type { StackDetectada } from '../models/ContextoAnalise.js';

/**
 * PADRÃO GoF DE CRIAÇÃO — Factory Method (Creator abstrato).
 *
 * `criarAnalisadores()` é o factory method: cada fábrica concreta decide QUAIS
 * analisadores fazem sentido para a stack do projeto analisado. O método
 * `criarCadeia()` (comum a todas) apenas encadeia o que foi criado,
 * sem conhecer as classes concretas.
 */
export abstract class FabricaAnalisadores {
  abstract readonly nome: string;

  /** Indica se esta fábrica atende a stack detectada. */
  abstract atende(stack: StackDetectada): boolean;

  /** FACTORY METHOD. */
  protected abstract criarAnalisadores(): AnalisadorSeguranca[];

  /** Monta a Chain of Responsibility a partir dos analisadores criados. */
  criarCadeia(): AnalisadorSeguranca {
    const analisadores = this.criarAnalisadores();
    if (analisadores.length === 0) throw new Error(`Fábrica ${this.nome} não criou analisadores`);
    analisadores.reduce((anterior, atual) => anterior.definirProximo(atual));
    return analisadores[0];
  }
}

/** Fábrica concreta: ecossistema Node.js (Express, Next.js, NestJS...). */
export class FabricaNode extends FabricaAnalisadores {
  readonly nome = 'node';

  atende(stack: StackDetectada): boolean {
    return stack.ecossistemas.includes('node');
  }

  protected criarAnalisadores(): AnalisadorSeguranca[] {
    return [
      new AnalisadorSegredos(),
      new AnalisadorSqlInjection(),
      new AnalisadorValidacaoEntrada(),
      new AnalisadorAutenticacao(),
      new AnalisadorAutorizacao(),
      new AnalisadorPermissoes(),
      new AnalisadorApi(),
      new AnalisadorEsquemaBanco(),
    ];
  }
}

/**
 * Fábrica concreta: qualquer outra stack (Python, PHP, Java, Prolog...).
 * Usa apenas os analisadores independentes de framework.
 */
export class FabricaGenerica extends FabricaAnalisadores {
  readonly nome = 'generica';

  atende(): boolean {
    return true;
  }

  protected criarAnalisadores(): AnalisadorSeguranca[] {
    return [
      new AnalisadorSegredos(),
      new AnalisadorSqlInjection(),
      new AnalisadorValidacaoEntrada(),
      new AnalisadorAutenticacao(),
      new AnalisadorPermissoes(),
      new AnalisadorEsquemaBanco(),
    ];
  }
}

/**
 * Registro de fábricas: permite adicionar suporte a novas stacks
 * (ex.: FabricaPython com regras de Django/Flask) sem alterar o agente.
 */
export class RegistroFabricas {
  private readonly fabricas: FabricaAnalisadores[] = [];

  constructor(fabricas: FabricaAnalisadores[] = [new FabricaNode()]) {
    fabricas.forEach((f) => this.registrar(f));
  }

  registrar(fabrica: FabricaAnalisadores): this {
    this.fabricas.push(fabrica);
    return this;
  }

  /** Primeira fábrica que atende a stack; a genérica é sempre o fallback. */
  obter(stack: StackDetectada): FabricaAnalisadores {
    return this.fabricas.find((f) => f.atende(stack)) ?? new FabricaGenerica();
  }
}
