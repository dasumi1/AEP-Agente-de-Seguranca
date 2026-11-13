import { AnalisadorSeguranca } from './AnalisadorSeguranca.js';
import type { ArquivoFonte, ContextoAnalise } from '../models/ContextoAnalise.js';
import { Categoria, type Regra, type Vulnerabilidade } from '../models/Vulnerabilidade.js';
import { Severidade } from '../models/Severidade.js';
import { ehArquivoDeCodigo } from '../utils/arquivos.js';

const OWASP = 'A01:2021 – Broken Access Control';

export const REGRAS_PERMISSOES = {
  perfilDoCliente: {
    id: 'PER-001',
    titulo: 'Perfil/permissão do usuário obtido de dados enviados pelo cliente',
    categoria: Categoria.PERMISSOES,
    severidade: Severidade.ALTO,
    owasp: OWASP,
    confianca: 'media',
    explicacao:
      'O perfil ou nível de acesso (role, perfil, isAdmin, tipo...) é lido de req.body/query/headers/params, ou seja, de um valor que o próprio usuário controla.',
    impacto: 'Escalonamento de privilégio: um aluno pode enviar "perfil": "admin" e obter acesso administrativo.',
    recomendacao:
      'Obtenha o perfil sempre de uma fonte confiável no servidor (token verificado ou banco de dados). Se um administrador puder definir perfis, valide o perfil de quem faz a requisição e restrinja os valores a uma lista permitida.',
    exemploCorrecao: `// perfil vem do token verificado pelo middleware, nunca do corpo da requisição
const perfil = req.usuario.perfil;
if (perfil !== 'admin') return res.status(403).json({ erro: 'Acesso negado' });`,
  },
  atribuicaoEmMassa: {
    id: 'PER-002',
    titulo: 'Atribuição em massa (mass assignment) a partir de req.body',
    categoria: Categoria.PERMISSOES,
    severidade: Severidade.MEDIO,
    owasp: OWASP,
    confianca: 'media',
    explicacao: 'O objeto inteiro da requisição é repassado para criação/atualização de registros.',
    impacto: 'O usuário pode incluir campos que não deveria controlar (perfil, ativo, notas, id de outro usuário) e alterá-los.',
    recomendacao: 'Selecione explicitamente os campos permitidos (allowlist) antes de gravar.',
    exemploCorrecao: `const { nome, email, telefone } = req.body;   // apenas campos permitidos
await Usuario.update({ nome, email, telefone }, { where: { id: req.usuario.id } });`,
  },
  idorPorParametro: {
    id: 'PER-003',
    titulo: 'Acesso a registro pelo id da URL sem verificar o dono (possível IDOR)',
    categoria: Categoria.PERMISSOES,
    severidade: Severidade.MEDIO,
    owasp: OWASP,
    confianca: 'baixa',
    explicacao:
      'Um registro é buscado/alterado usando apenas req.params.id, e o arquivo não compara esse registro com o usuário autenticado (req.usuario/req.user).',
    impacto: 'Trocando o id na URL, um usuário pode ver ou alterar dados de outro (ex.: notas e faltas de outro aluno).',
    recomendacao: 'Inclua o usuário autenticado no filtro da consulta ou verifique a propriedade do registro antes de retorná-lo; administradores podem ter regra própria.',
    exemploCorrecao: `const [linhas] = await pool.execute(
  'SELECT * FROM notas WHERE id = ? AND aluno_id = ?',
  [req.params.id, req.usuario.id],
);
if (linhas.length === 0) return res.status(404).json({ erro: 'Não encontrado' });`,
  },
} satisfies Record<string, Regra>;

const CAMPO_PERFIL = /\b(req|request|ctx\.request)\.(body|query|headers|params|cookies)(\.|\[['"])(role|roles|perfil|papel|isAdmin|is_admin|admin|tipo|tipoUsuario|tipo_usuario|nivel|nivelAcesso|permiss\w*|grupo|scope)\b/;

/** Elo da cadeia: permissões de usuários (escalonamento de privilégio, mass assignment, IDOR). */
export class AnalisadorPermissoes extends AnalisadorSeguranca {
  readonly nome = 'Permissões';

  protected suporta(arquivo: ArquivoFonte): boolean {
    return ehArquivoDeCodigo(arquivo.linguagem);
  }

  protected verificar(arquivo: ArquivoFonte, _ctx: ContextoAnalise): Vulnerabilidade[] {
    const achados: Vulnerabilidade[] = [];
    const verificaDono = /req\.(usuario|user|auth|session)\b|res\.locals\.(usuario|user)/.test(arquivo.conteudo);
    let idorReportado = false;

    this.paraCadaLinha(arquivo, (texto, linha) => {
      if (CAMPO_PERFIL.test(texto)) {
        achados.push(this.criarAchado(REGRAS_PERMISSOES.perfilDoCliente, arquivo, linha));
        return;
      }
      if (/\.(create|update|insert|save|upsert|findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|build|merge)\s*\(\s*(\{\s*\.\.\.req\.body\s*\}|req\.body)\s*[,)]/.test(texto) ||
          /(SET|VALUES)\s*\?[^\n]*req\.body\s*[\],)]/i.test(texto)) {
        achados.push(this.criarAchado(REGRAS_PERMISSOES.atribuicaoEmMassa, arquivo, linha));
        return;
      }
      if (!verificaDono && !idorReportado && /req\.params\.(id|\w+Id)\b/.test(texto) && /(find|select|where|update|delete|execute|query)/i.test(texto)) {
        achados.push(this.criarAchado(REGRAS_PERMISSOES.idorPorParametro, arquivo, linha));
        idorReportado = true; // um aviso por arquivo
      }
    });
    return achados;
  }
}
