import { AnalisadorSeguranca } from './AnalisadorSeguranca.js';
import type { ArquivoFonte, ContextoAnalise } from '../models/ContextoAnalise.js';
import { Categoria, type Regra, type Vulnerabilidade } from '../models/Vulnerabilidade.js';
import { Severidade } from '../models/Severidade.js';

export const REGRAS_BANCO = {
  colunaSenhaCurta: {
    id: 'BD-001',
    titulo: 'Coluna de senha com tamanho incompatível com hash seguro',
    categoria: Categoria.BANCO_DADOS,
    severidade: Severidade.ALTO,
    owasp: 'A02:2021 – Cryptographic Failures',
    confianca: 'media',
    explicacao: 'A coluna de senha tem menos de 60 caracteres — tamanho mínimo de um hash bcrypt. Isso indica armazenamento em texto puro ou com hash fraco.',
    impacto: 'Se o banco vazar, as senhas de alunos, professores e administradores ficam expostas e podem ser reutilizadas em outros serviços.',
    recomendacao: 'Armazene apenas o hash (bcrypt/Argon2) em uma coluna de pelo menos VARCHAR(255) e nunca a senha original.',
    exemploCorrecao: `ALTER TABLE usuarios
  CHANGE COLUMN senha senha_hash VARCHAR(255) NOT NULL;`,
  },
  grantAmplo: {
    id: 'BD-002',
    titulo: 'Privilégios excessivos concedidos no banco de dados',
    categoria: Categoria.BANCO_DADOS,
    severidade: Severidade.ALTO,
    owasp: 'A01:2021 – Broken Access Control',
    confianca: 'alta',
    explicacao: 'O script concede ALL PRIVILEGES e/ou libera o acesso a partir de qualquer host ("%").',
    impacto: 'Se a aplicação for comprometida (ex.: via SQL Injection), o atacante herda privilégios totais: apagar tabelas, criar usuários, ler outros bancos.',
    recomendacao: 'Crie um usuário específico da aplicação com o mínimo necessário (SELECT, INSERT, UPDATE, DELETE no schema da aplicação) e restrito ao host do backend.',
    exemploCorrecao: `CREATE USER 'app_escola'@'10.0.0.%' IDENTIFIED BY '<definida no cofre de segredos>';
GRANT SELECT, INSERT, UPDATE, DELETE ON escola.* TO 'app_escola'@'10.0.0.%';`,
  },
  senhaNoScript: {
    id: 'BD-003',
    titulo: 'Senha de usuário do banco escrita no script SQL',
    categoria: Categoria.SEGREDOS,
    severidade: Severidade.ALTO,
    owasp: 'A07:2021 – Identification and Authentication Failures',
    confianca: 'alta',
    explicacao: 'CREATE USER / ALTER USER / SET PASSWORD contém a senha literal no arquivo versionado.',
    impacto: 'Qualquer pessoa com acesso ao repositório conhece a senha do usuário do banco.',
    recomendacao: 'Remova a senha do script; gere-a no momento do provisionamento a partir de uma variável de ambiente ou cofre de segredos.',
    exemploCorrecao: `-- provisionamento (shell), senha vinda do ambiente:
-- mysql -e "CREATE USER 'app'@'%' IDENTIFIED BY '$DB_APP_PASSWORD';"`,
  },
  dadosPessoais: {
    id: 'BD-004',
    titulo: 'Tabela com dados pessoais sem indicação de proteção (LGPD)',
    categoria: Categoria.BANCO_DADOS,
    severidade: Severidade.BAIXO,
    owasp: 'A02:2021 – Cryptographic Failures',
    confianca: 'baixa',
    explicacao: 'A tabela contém colunas de dados pessoais (CPF, RG, nascimento, endereço, telefone etc.).',
    impacto: 'Dados pessoais exigem controles adicionais pela LGPD; um vazamento gera dano aos titulares e responsabilização da instituição.',
    recomendacao: 'Colete apenas o necessário, restrinja quem pode consultar esses campos, considere criptografia em repouso para documentos e nunca retorne esses campos em listagens.',
    exemploCorrecao: `-- exemplo: expor somente o necessário por meio de uma view
CREATE VIEW vw_alunos_publico AS
  SELECT id, nome, turma_id FROM alunos;`,
  },
} satisfies Record<string, Regra>;

const COLUNA_SENHA = /^\s*[`"[]?(senha|password|passwd|pass|pwd|senha_usuario|user_password)[`"\]]?\s+(VAR)?CHAR\s*\(\s*(\d+)\s*\)/i;
const DADOS_PESSOAIS = /^\s*[`"[]?(cpf|rg|cnh|nis|data_nascimento|dt_nascimento|nascimento|endereco|logradouro|telefone|celular|nome_mae|nome_pai|ssn|birth_date|address|phone)[`"\]]?\s+/i;

/** Elo da cadeia: esquema do banco de dados (arquivos .sql e migrations). */
export class AnalisadorEsquemaBanco extends AnalisadorSeguranca {
  readonly nome = 'Banco de Dados';

  protected suporta(arquivo: ArquivoFonte): boolean {
    return arquivo.linguagem === 'sql';
  }

  protected verificar(arquivo: ArquivoFonte, _ctx: ContextoAnalise): Vulnerabilidade[] {
    const achados: Vulnerabilidade[] = [];
    let tabelaAtual: { nome: string; linha: number; pessoais: string[] } | undefined;

    const fecharTabela = () => {
      if (tabelaAtual && tabelaAtual.pessoais.length > 0) {
        achados.push(
          this.criarAchado(REGRAS_BANCO.dadosPessoais, arquivo, tabelaAtual.linha, {
            titulo: `${REGRAS_BANCO.dadosPessoais.titulo}: ${tabelaAtual.nome}`,
            observacao: `Colunas: ${tabelaAtual.pessoais.join(', ')}`,
          }),
        );
      }
      tabelaAtual = undefined;
    };

    this.paraCadaLinha(arquivo, (texto, linha) => {
      const criar = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"[]?([\w.]+)/i.exec(texto);
      if (criar) {
        fecharTabela();
        tabelaAtual = { nome: criar[1], linha, pessoais: [] };
      }
      const senha = COLUNA_SENHA.exec(texto);
      if (senha && Number(senha[3]) < 60) achados.push(this.criarAchado(REGRAS_BANCO.colunaSenhaCurta, arquivo, linha));

      const pessoal = DADOS_PESSOAIS.exec(texto);
      if (pessoal && tabelaAtual) tabelaAtual.pessoais.push(pessoal[1].toLowerCase());

      if (/GRANT\s+ALL(\s+PRIVILEGES)?\b/i.test(texto) || /GRANT\s+.+\s+TO\s+\S+@\s*['"`]%['"`]/i.test(texto)) {
        achados.push(this.criarAchado(REGRAS_BANCO.grantAmplo, arquivo, linha));
      }
      if (/(CREATE|ALTER)\s+USER\b.*IDENTIFIED\s+(WITH\s+\w+\s+)?BY\s+['"][^'"$<]{3,}['"]|SET\s+PASSWORD\b.*=\s*['"][^'"]+['"]/i.test(texto)) {
        achados.push(this.criarAchado(REGRAS_BANCO.senhaNoScript, arquivo, linha));
      }
      if (/^\s*\)/.test(texto) && tabelaAtual && !criar) fecharTabela();
    });
    fecharTabela();
    return achados;
  }
}
