import { carregarEnv } from './config.js';
import { AgenteSegurancaFacade } from './facade/AgenteSegurancaFacade.js';
import { criarServidorSeguranca } from './http/servidorHttp.js';

carregarEnv();

const agente = new AgenteSegurancaFacade();
const { servidor } = criarServidorSeguranca(agente);
const porta = Number(process.env.PORT ?? 4010);
const host = process.env.HOST ?? '127.0.0.1';

servidor.listen(porta, host, () => {
  console.log(`[Agente de Segurança] ouvindo em http://${host}:${porta}/api/seguranca`);
  console.log(`  Projeto analisado: ${agente.config.raizProjeto}`);
  console.log(`  LLM: ${agente.llmDisponivel ? 'configurado' : 'não configurado (somente regras)'}`);
  if (!agente.config.tokenApi) console.warn('  ⚠ SECURITY_AGENT_TOKEN não definido: rotas protegidas responderão 503.');
});
