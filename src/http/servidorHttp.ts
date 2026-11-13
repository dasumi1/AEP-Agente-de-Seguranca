import { createServer, type IncomingMessage, type Server } from 'node:http';
import { AgenteSegurancaFacade } from '../facade/AgenteSegurancaFacade.js';
import { ControladorSeguranca, type RequisicaoAgente, type RespostaAgente } from '../controllers/ControladorSeguranca.js';

const LIMITE_CORPO = 5 * 1024 * 1024;

function lerCorpo(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const partes: Buffer[] = [];
    let total = 0;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > LIMITE_CORPO) {
        reject(new Error('Corpo muito grande'));
        req.destroy();
      } else partes.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(partes)));
    req.on('error', reject);
  });
}

/**
 * Servidor HTTP autônomo (sem dependências) com as mesmas rotas do adaptador Express.
 * Útil para rodar o agente como serviço separado do backend.
 */
export function criarServidorSeguranca(agente = new AgenteSegurancaFacade(), prefixo = '/api/seguranca'): { servidor: Server; controlador: ControladorSeguranca } {
  const controlador = new ControladorSeguranca(agente);

  const servidor = createServer(async (req, res) => {
    const enviar = (r: RespostaAgente) => {
      res.writeHead(r.status, {
        'Content-Type': 'application/json; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store',
      });
      res.end(JSON.stringify(r.corpo));
    };
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (!url.pathname.startsWith(prefixo)) return enviar({ status: 404, corpo: { erro: 'Rota não encontrada' } });
      const rota = url.pathname.slice(prefixo.length) || '/';
      const corpoBruto = req.method === 'POST' ? await lerCorpo(req) : undefined;
      const base: RequisicaoAgente = { cabecalhos: req.headers, corpoBruto };

      if (req.method === 'POST' && rota === '/webhooks/github') return enviar(controlador.receberWebhookGithub(base));
      if (req.method === 'GET' && rota === '/status') return enviar(controlador.status(base));
      if (req.method === 'GET' && rota === '/relatorios') return enviar(controlador.listarRelatorios(base));
      const m = /^\/relatorios\/([^/]+)$/.exec(rota);
      if (req.method === 'GET' && m) return enviar(controlador.obterRelatorio({ ...base, parametros: { id: decodeURIComponent(m[1]) } }));
      if (req.method === 'POST' && rota === '/analises') {
        let corpo: unknown = {};
        try {
          corpo = corpoBruto && corpoBruto.length ? JSON.parse(corpoBruto.toString('utf8')) : {};
        } catch {
          return enviar({ status: 400, corpo: { erro: 'JSON inválido' } });
        }
        return enviar(await controlador.analisarSobDemanda({ ...base, corpo }));
      }
      return enviar({ status: 404, corpo: { erro: 'Rota não encontrada' } });
    } catch (e) {
      return enviar({ status: 400, corpo: { erro: (e as Error).message } });
    }
  });
  return { servidor, controlador };
}
