/**
 * API pública do Agente de Segurança.
 * O adaptador Express fica em "./http/rotasExpress" para que o núcleo não dependa do Express.
 */
export { AgenteSegurancaFacade, type SolicitacaoAnalise, type DependenciasAgente } from './facade/AgenteSegurancaFacade.js';
export { ControladorSeguranca, type RequisicaoAgente, type RespostaAgente } from './controllers/ControladorSeguranca.js';
export { criarServidorSeguranca } from './http/servidorHttp.js';
export { AnalisadorSeguranca } from './analisadores/AnalisadorSeguranca.js';
export { FabricaAnalisadores, FabricaNode, FabricaGenerica, RegistroFabricas } from './fabricas/FabricaAnalisadores.js';
export { ProvedorOpenAiCompativel, ProvedorLlmNulo, type ProvedorLlm } from './llm/ProvedorLlm.js';
export { relatorioParaMarkdown, resumoConsole } from './apresentacao/ApresentadorMarkdown.js';
export { Severidade } from './models/Severidade.js';
export { Categoria, type Vulnerabilidade, type Regra } from './models/Vulnerabilidade.js';
export type { RelatorioSeguranca } from './models/RelatorioSeguranca.js';
export type { ContextoAnalise, ArquivoFonte, StackDetectada, Gatilho } from './models/ContextoAnalise.js';
