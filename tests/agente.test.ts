import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';

import { AgenteSegurancaFacade } from '../src/facade/AgenteSegurancaFacade.js';
import { ControladorSeguranca } from '../src/controllers/ControladorSeguranca.js';
import { criarServidorSeguranca } from '../src/http/servidorHttp.js';
import { ProvedorLlmNulo, type ProvedorLlm } from '../src/llm/ProvedorLlm.js';
import { RegistroFabricas } from '../src/fabricas/FabricaAnalisadores.js';
import { Severidade } from '../src/models/Severidade.js';
import { mascararSegredos } from '../src/utils/mascarar.js';
import { relatorioParaMarkdown } from '../src/apresentacao/ApresentadorMarkdown.js';

const AQUI = path.dirname(fileURLToPath(import.meta.url));
const VULNERAVEL = path.join(AQUI, 'fixtures', 'app-vulneravel');
const SEGURO = path.join(AQUI, 'fixtures', 'app-seguro');

// O .env é criado em tempo de execução porque normalmente está no .gitignore do repositório.
before(() => writeFileSync(path.join(VULNERAVEL, '.env'), 'DB_PASSWORD=senhaReal123\nJWT_SECRET=abc\n'));

const temp = () => mkdtempSync(path.join(tmpdir(), 'agente-seg-'));

function criarAgente(provedorLlm: ProvedorLlm = new ProvedorLlmNulo(), extra: Record<string, unknown> = {}) {
  return new AgenteSegurancaFacade({
    provedorLlm,
    persistir: false,
    config: { raizProjeto: VULNERAVEL, diretorioRelatorios: temp(), ...extra },
  });
}

/** LLM falso que registra os prompts recebidos. */
class LlmFalso implements ProvedorLlm {
  readonly nome = 'falso';
  readonly prompts: string[] = [];
  constructor(private readonly responder: (prompt: string) => unknown) {}
  disponivel() {
    return true;
  }
  async gerarJson(_s: string, u: string) {
    this.prompts.push(u);
    return this.responder(u);
  }
}

describe('Regras determinísticas', () => {
  test('detecta as vulnerabilidades esperadas no projeto vulnerável', async () => {
    const r = await criarAgente().analisar({ raiz: VULNERAVEL, usarLlm: false });
    const regras = new Set(r.vulnerabilidades.map((v) => v.regraId));
    const esperadas = [
      'SEG-003', 'SEG-004', 'SEG-005', 'SEG-006', // segredos
      'SQL-002', 'SQL-004', // SQL injection
      'ENT-003', 'ENT-004', // validação de entrada
      'AUT-001', 'AUT-003', 'AUT-004', 'AUT-007', // autenticação
      'AUZ-001', 'AUZ-002', 'AUZ-003', // autorização
      'PER-001', 'PER-002', 'PER-003', // permissões
      'API-001', 'API-002', 'API-003', 'API-004', // API
      'BD-001', 'BD-002', 'BD-003', 'BD-004', // banco de dados
    ];
    for (const id of esperadas) assert.ok(regras.has(id), `regra ${id} deveria ter sido acionada`);
    assert.equal(r.bloqueante, false);
    assert.ok(r.stack.frameworks.includes('express'));
    assert.ok(r.stack.bancos.includes('mysql'));
  });

  test('não gera achados no projeto que segue boas práticas', async () => {
    const r = await criarAgente().analisar({ raiz: SEGURO, usarLlm: false });
    assert.deepEqual(
      r.vulnerabilidades.map((v) => `${v.regraId} ${v.arquivo}:${v.linha}`),
      [],
    );
  });

  test('todo achado tem os campos exigidos no relatório', async () => {
    const r = await criarAgente().analisar({ raiz: VULNERAVEL, usarLlm: false });
    for (const v of r.vulnerabilidades) {
      assert.ok(v.titulo && v.arquivo && v.linha > 0 && v.explicacao && v.impacto && v.recomendacao && v.exemploCorrecao, v.regraId);
      assert.ok(Object.values(Severidade).includes(v.severidade));
    }
    const md = relatorioParaMarkdown(r);
    for (const campo of ['Vulnerabilidade', 'Arquivo/linha', 'Nível de risco', 'Explicação', 'Impacto', 'Recomendação', 'Exemplo de correção']) {
      assert.ok(md.includes(campo), `markdown sem o campo ${campo}`);
    }
  });

  test('ordena por severidade (Crítico primeiro)', async () => {
    const r = await criarAgente().analisar({ raiz: VULNERAVEL, usarLlm: false });
    assert.equal(r.vulnerabilidades[0].severidade, Severidade.CRITICO);
    assert.equal(r.vulnerabilidades.at(-1)!.severidade, Severidade.BAIXO);
  });

  test('o relatório nunca contém os segredos encontrados', async () => {
    const r = await criarAgente().analisar({ raiz: VULNERAVEL, usarLlm: false });
    const texto = JSON.stringify(r) + relatorioParaMarkdown(r);
    for (const segredo of ['Sup3rSecreta', 'root123', 'senhaReal123', 'segredo-padrao', 'app123']) {
      assert.ok(!texto.includes(segredo), `segredo "${segredo}" vazou no relatório`);
    }
  });

  test('detecta tokens de provedores conhecidos e chave privada', async () => {
    const dir = temp();
    // montados em tempo de execução para não parecerem tokens reais no repositório
    const tokenGh = 'gh' + 'p_' + 'A1b2C3d4'.repeat(5);
    const chave = '-----BEGIN ' + 'RSA PRIVATE KEY-----';
    writeFileSync(path.join(dir, 'config.js'), `const t = "${tokenGh}";\nconst k = \`${chave}\nMIIE...\`;\n`);
    const r = await criarAgente().analisar({ raiz: dir, usarLlm: false });
    const regras = r.vulnerabilidades.map((v) => v.regraId);
    assert.ok(regras.includes('SEG-002'));
    assert.ok(regras.includes('SEG-001'));
    assert.ok(!JSON.stringify(r).includes(tokenGh));
  });

  test('funciona em outras stacks (Python/PHP) com a fábrica genérica', async () => {
    const dir = temp();
    writeFileSync(path.join(dir, 'app.py'), 'def buscar(request, cursor):\n    cursor.execute(f"SELECT * FROM users WHERE id = {request.args[\'id\']}")\n    senha = "minhaSenhaForte9"\n');
    writeFileSync(path.join(dir, 'index.php'), '<?php\n$r = mysqli_query($c, "SELECT * FROM users WHERE id = $_GET[id]");\n');
    const r = await criarAgente().analisar({ raiz: dir, usarLlm: false });
    assert.ok(r.stack.ecossistemas.includes('python'));
    const porArquivo = (a: string) => r.vulnerabilidades.filter((v) => v.arquivo === a).map((v) => v.regraId);
    assert.ok(porArquivo('app.py').includes('SQL-002'));
    assert.ok(porArquivo('app.py').includes('SEG-004'));
    assert.ok(porArquivo('index.php').includes('SQL-002'));
  });

  test('aceita novas fábricas registradas (extensível)', () => {
    const registro = new RegistroFabricas();
    assert.equal(registro.obter({ ecossistemas: ['node'], frameworks: [], bancos: [], dependencias: [] }).nome, 'node');
    assert.equal(registro.obter({ ecossistemas: ['java'], frameworks: [], bancos: [], dependencias: [] }).nome, 'generica');
  });

  test('comentário seguranca-ignore suprime o achado', async () => {
    const dir = temp();
    writeFileSync(path.join(dir, 'rotas.js'), "router.get('/publico/catalogo', listar); // seguranca-ignore\nrouter.get('/notas', listar);\n");
    const r = await criarAgente().analisar({ raiz: dir, usarLlm: false });
    assert.deepEqual(r.vulnerabilidades.map((v) => v.linha), [2]);
  });
});

describe('Modo incremental (commit/push)', () => {
  test('analisa apenas os arquivos alterados e ignora caminhos fora do projeto', async () => {
    const r = await criarAgente().analisar({
      raiz: VULNERAVEL,
      usarLlm: false,
      arquivos: ['src/server.ts', '../../../etc/passwd', 'nao-existe.ts'],
    });
    assert.equal(r.modo, 'incremental');
    assert.equal(r.arquivosAnalisados, 1);
    assert.ok(r.vulnerabilidades.every((v) => v.arquivo === 'src/server.ts'));
    assert.ok(r.avisos.some((a) => a.includes('fora do projeto')));
  });
});

describe('Análise contextual via LLM', () => {
  test('enriquece achados, adiciona novos e trata falso positivo', async () => {
    const llm = new LlmFalso((prompt) => {
      const dados = JSON.parse(prompt);
      if (dados.arquivo !== 'src/routes/alunos.ts') return { enriquecimentos: [], novosAchados: [] };
      const delecao = dados.achadosRegras.find((a: { regra: string }) => a.regra === 'AUZ-001');
      const idor = dados.achadosRegras.find((a: { regra: string }) => a.regra === 'PER-003');
      return {
        enriquecimentos: [
          { id: delecao.id, explicacao: 'Explicação contextual.', exemploCorrecao: "router.delete('/:id', autenticar, exigirPerfil('admin'), excluir);", severidadeSugerida: 'Crítico' },
          { id: idor.id, falsoPositivo: true },
          { id: 'inexistente', explicacao: 'ignorar' },
        ],
        novosAchados: [
          { titulo: 'Listagem expõe CPF de todos os alunos', categoria: 'Permissões', severidade: 'Alto', linha: 8, explicacao: 'SELECT * retorna dados pessoais.' },
          { titulo: 'Linha inválida deve ser descartada', categoria: 'API', severidade: 'Alto', linha: 9999 },
        ],
      };
    });
    const r = await criarAgente(llm).analisar({ raiz: VULNERAVEL });

    assert.equal(r.llmUtilizado, true);
    const delecao = r.vulnerabilidades.find((v) => v.regraId === 'AUZ-001')!;
    assert.equal(delecao.origem, 'regra+llm');
    assert.equal(delecao.explicacao, 'Explicação contextual.');
    assert.equal(delecao.severidade, Severidade.CRITICO); // confiança média: prevalece o LLM

    const idor = r.vulnerabilidades.find((v) => v.regraId === 'PER-003')!;
    assert.equal(idor.severidade, Severidade.BAIXO);
    assert.ok(idor.observacao?.includes('falso positivo'));

    assert.ok(r.vulnerabilidades.some((v) => v.origem === 'llm' && v.titulo.includes('CPF') && v.linha === 8));
    assert.ok(!r.vulnerabilidades.some((v) => v.titulo.includes('Linha inválida')));
  });

  test('regra de confiança alta não é rebaixada pelo LLM', async () => {
    const llm = new LlmFalso((prompt) => {
      const dados = JSON.parse(prompt);
      return { enriquecimentos: dados.achadosRegras.map((a: { id: string }) => ({ id: a.id, severidadeSugerida: 'Baixo', falsoPositivo: true })) };
    });
    const r = await criarAgente(llm).analisar({ raiz: VULNERAVEL, arquivos: ['src/db/conexao.ts'] });
    const conexao = r.vulnerabilidades.find((v) => v.regraId === 'SEG-003')!;
    assert.equal(conexao.severidade, Severidade.CRITICO);
  });

  test('o código enviado ao LLM tem os segredos mascarados e o .env não é enviado', async () => {
    const llm = new LlmFalso(() => ({ enriquecimentos: [], novosAchados: [] }));
    await criarAgente(llm).analisar({ raiz: VULNERAVEL });
    const enviado = llm.prompts.join('\n');
    assert.ok(llm.prompts.length > 0);
    for (const segredo of ['Sup3rSecreta', 'root123', 'senhaReal123']) assert.ok(!enviado.includes(segredo), segredo);
    assert.ok(!llm.prompts.some((p) => JSON.parse(p).arquivo === '.env'));
  });

  test('falha do LLM não interrompe a análise', async () => {
    const llm = new LlmFalso(() => {
      throw new Error('timeout');
    });
    const r = await criarAgente(llm).analisar({ raiz: VULNERAVEL });
    assert.ok(r.vulnerabilidades.length > 20);
    assert.equal(r.llmUtilizado, false);
    assert.ok(r.avisos.some((a) => a.includes('LLM falhou')));
  });

  test('sem chave configurada, segue apenas com as regras', async () => {
    const r = await criarAgente(new ProvedorLlmNulo()).analisar({ raiz: VULNERAVEL });
    assert.ok(r.avisos.some((a) => a.includes('LLM não configurado')));
    assert.ok(r.vulnerabilidades.length > 20);
  });
});

describe('Mascaramento', () => {
  test('mascara credenciais comuns', () => {
    assert.ok(!mascararSegredos("password: 'root123'").includes('root123'));
    assert.ok(!mascararSegredos('DB_PASSWORD=senhaReal123').includes('senhaReal123'));
    assert.ok(!mascararSegredos('mysql://admin:Sup3r@host/db').includes('Sup3r'));
    assert.equal(mascararSegredos('password: process.env.DB_PASSWORD'), 'password: process.env.DB_PASSWORD');
    assert.equal(mascararSegredos('const token = jwt.sign(payload, segredo);'), 'const token = jwt.sign(payload, segredo);');
  });
});

describe('Controller (GRASP) e API', () => {
  const TOKEN = 'token-de-teste';
  const SEGREDO = 'segredo-webhook';

  test('protege as rotas com token e falha fechada sem configuração', async () => {
    const semToken = new ControladorSeguranca(criarAgente(), () => undefined);
    assert.equal((await semToken.analisarSobDemanda({ cabecalhos: {} })).status, 503);

    const c = new ControladorSeguranca(criarAgente(new ProvedorLlmNulo(), { tokenApi: TOKEN }), () => undefined);
    assert.equal((await c.analisarSobDemanda({ cabecalhos: { authorization: 'Bearer errado' } })).status, 401);
    const ok = await c.analisarSobDemanda({ cabecalhos: { authorization: `Bearer ${TOKEN}` }, corpo: { usarLlm: false } });
    assert.equal(ok.status, 200);
    assert.ok((ok.corpo as { resumo: { total: number } }).resumo.total > 20);
    assert.equal((await c.analisarSobDemanda({ cabecalhos: { authorization: `Bearer ${TOKEN}` }, corpo: { arquivos: 'x' } })).status, 400);
  });

  test('webhook do GitHub valida assinatura e analisa em segundo plano', async () => {
    const dirRel = temp();
    const agente = new AgenteSegurancaFacade({
      provedorLlm: new ProvedorLlmNulo(),
      config: { raizProjeto: VULNERAVEL, diretorioRelatorios: dirRel, segredoWebhook: SEGREDO, tokenApi: TOKEN },
    });
    const c = new ControladorSeguranca(agente, () => undefined);
    const corpo = Buffer.from(JSON.stringify({ after: 'a'.repeat(40), commits: [{ added: ['src/server.ts'], modified: ['src/routes/auth.ts'] }] }));
    const assinatura = 'sha256=' + createHmac('sha256', SEGREDO).update(corpo).digest('hex');

    assert.equal(c.receberWebhookGithub({ cabecalhos: { 'x-github-event': 'push', 'x-hub-signature-256': 'sha256=00' }, corpoBruto: corpo }).status, 401);
    const resp = c.receberWebhookGithub({ cabecalhos: { 'x-github-event': 'push', 'x-hub-signature-256': assinatura }, corpoBruto: corpo });
    assert.equal(resp.status, 202);
    await c.aguardarAnalises();

    const lista = agente.listarRelatorios();
    assert.equal(lista.length, 1);
    const rel = agente.obterRelatorio(lista[0].id)!;
    assert.equal(rel.gatilho, 'push');
    assert.equal(rel.modo, 'incremental');
    assert.equal(rel.arquivosAnalisados, 2);
    assert.ok(readdirSync(dirRel).some((n) => n.endsWith('.md')));
    assert.equal(c.obterRelatorio({ cabecalhos: { authorization: `Bearer ${TOKEN}` }, parametros: { id: '../../etc/passwd' } }).status, 404);
  });

  test('servidor HTTP autônomo responde ponta a ponta', async () => {
    const agente = new AgenteSegurancaFacade({
      provedorLlm: new ProvedorLlmNulo(),
      config: { raizProjeto: SEGURO, diretorioRelatorios: temp(), tokenApi: TOKEN },
    });
    const { servidor } = criarServidorSeguranca(agente);
    await new Promise<void>((ok) => servidor.listen(0, '127.0.0.1', ok));
    const base = `http://127.0.0.1:${(servidor.address() as AddressInfo).port}/api/seguranca`;
    try {
      const h = { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' };
      assert.equal((await fetch(`${base}/status`)).status, 401);
      const analise = await fetch(`${base}/analises`, { method: 'POST', headers: h, body: JSON.stringify({ usarLlm: false }) });
      assert.equal(analise.status, 200);
      const rel = (await analise.json()) as { id: string; resumo: { total: number } };
      assert.equal(rel.resumo.total, 0);
      const obtido = await fetch(`${base}/relatorios/${rel.id}`, { headers: h });
      assert.equal(obtido.status, 200);
    } finally {
      servidor.close();
    }
  });
});

describe('Persistência', () => {
  test('salva JSON e Markdown do relatório', async () => {
    const dir = temp();
    const agente = new AgenteSegurancaFacade({ provedorLlm: new ProvedorLlmNulo(), config: { raizProjeto: VULNERAVEL, diretorioRelatorios: dir } });
    const r = await agente.analisar({ usarLlm: false });
    const md = readFileSync(path.join(dir, `relatorio-${r.id}.md`), 'utf8');
    assert.ok(md.includes('Relatório do Agente de Segurança'));
    assert.ok(md.includes('consultivo'));
    mkdirSync(path.join(dir, 'sub'), { recursive: true });
  });
});
