import express, { type Request, type Response, type Router } from 'express';
import { AgenteSegurancaFacade } from '../facade/AgenteSegurancaFacade.js';
import { ControladorSeguranca, type RequisicaoAgente, type RespostaAgente } from '../controllers/ControladorSeguranca.js';

/**
 * Adaptador Express: integra o agente ao backend existente.
 *
 *   import { criarRotasSeguranca } from './agente-seguranca/src/http/rotasExpress';
 *   app.use('/api/seguranca', criarRotasSeguranca());
 *
 * Rotas:
 *   GET  /status                 (Bearer token)
 *   POST /analises               (Bearer token)  — sob demanda
 *   GET  /relatorios             (Bearer token)
 *   GET  /relatorios/:id         (Bearer token)
 *   POST /webhooks/github        (assinatura HMAC do GitHub) — a cada push
 */
export function criarRotasSeguranca(agente = new AgenteSegurancaFacade()): Router {
  const controlador = new ControladorSeguranca(agente);
  const router = express.Router();

  const adaptar = (req: Request, corpoBruto?: Buffer): RequisicaoAgente => ({
    cabecalhos: req.headers,
    corpo: corpoBruto ? undefined : req.body, // seguranca-ignore: validado no ControladorSeguranca
    corpoBruto,
    parametros: req.params as Record<string, string>,
  });
  const responder = (res: Response, r: RespostaAgente) => res.status(r.status).json(r.corpo);

  // O webhook precisa do corpo bruto para validar a assinatura HMAC
  router.post('/webhooks/github', express.raw({ type: '*/*', limit: '5mb' }), (req, res) => {
    responder(res, controlador.receberWebhookGithub(adaptar(req, Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0))));
  });

  // A autenticação (Bearer token) é feita dentro do ControladorSeguranca em cada ação.
  router.use(express.json({ limit: '1mb' }));
  router.get('/status', (req, res) => responder(res, controlador.status(adaptar(req)))); // seguranca-ignore
  router.post('/analises', async (req, res) => responder(res, await controlador.analisarSobDemanda(adaptar(req)))); // seguranca-ignore
  router.get('/relatorios', (req, res) => responder(res, controlador.listarRelatorios(adaptar(req)))); // seguranca-ignore
  router.get('/relatorios/:id', (req, res) => responder(res, controlador.obterRelatorio(adaptar(req)))); // seguranca-ignore

  return router;
}
