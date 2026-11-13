import { Severidade } from './Severidade.js';

/** MODEL — Categorias do escopo definido para o agente. */
export enum Categoria {
  SEGREDOS = 'Credenciais/Segredos',
  SQL_INJECTION = 'SQL Injection',
  VALIDACAO_ENTRADA = 'Validação de Entrada',
  AUTENTICACAO = 'Autenticação',
  AUTORIZACAO = 'Autorização',
  PERMISSOES = 'Permissões',
  API = 'API',
  BANCO_DADOS = 'Banco de Dados',
}

export const TODAS_CATEGORIAS = Object.values(Categoria) as Categoria[];

export type Origem = 'regra' | 'llm' | 'regra+llm';
export type Confianca = 'alta' | 'media' | 'baixa';

/**
 * Regra determinística: o "conhecimento" de cada verificação.
 * Os textos aqui são o fallback quando o LLM não está disponível.
 */
export interface Regra {
  id: string;
  titulo: string;
  categoria: Categoria;
  severidade: Severidade;
  /** Referência OWASP Top 10 (2021). */
  owasp: string;
  confianca: Confianca;
  explicacao: string;
  impacto: string;
  recomendacao: string;
  exemploCorrecao: string;
}

/** MODEL — Uma vulnerabilidade encontrada, com todos os campos exigidos no relatório. */
export interface Vulnerabilidade {
  id: string;
  regraId: string;
  titulo: string;
  categoria: Categoria;
  severidade: Severidade;
  arquivo: string;
  linha: number;
  /** Trecho do código (já com segredos mascarados). */
  trecho: string;
  explicacao: string;
  impacto: string;
  recomendacao: string;
  exemploCorrecao: string;
  owasp: string;
  origem: Origem;
  confianca: Confianca;
  /** Severidade sugerida pelo LLM (consolidada pelo filtro de classificação). */
  severidadeSugeridaLlm?: Severidade;
  /** LLM indicou provável falso positivo. */
  possivelFalsoPositivo?: boolean;
  observacao?: string;
}
