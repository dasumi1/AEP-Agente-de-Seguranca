import { AnalisadorSeguranca } from './AnalisadorSeguranca.js';
import type { ArquivoFonte, ContextoAnalise } from '../models/ContextoAnalise.js';
import { Categoria, type Regra, type Vulnerabilidade } from '../models/Vulnerabilidade.js';
import { Severidade } from '../models/Severidade.js';
import { ehArquivoDeCodigo, ehJsTs } from '../utils/arquivos.js';

const OWASP_AUTH = 'A07:2021 – Identification and Authentication Failures';
const OWASP_CRIPTO = 'A02:2021 – Cryptographic Failures';

const base = { categoria: Categoria.AUTENTICACAO };

export const REGRAS_AUTENTICACAO = {
  hashFraco: {
    ...base,
    id: 'AUT-001',
    titulo: 'Algoritmo de hash inadequado para senhas (MD5/SHA-1/SHA-256 simples)',
    severidade: Severidade.ALTO,
    owasp: OWASP_CRIPTO,
    confianca: 'media',
    explicacao: 'Foi identificado um hash rápido (MD5, SHA-1 ou SHA-256 sem fator de custo) em código que lida com senhas.',
    impacto: 'Em caso de vazamento do banco, as senhas podem ser quebradas em minutos por força bruta ou tabelas pré-computadas.',
    recomendacao: 'Use um algoritmo próprio para senhas, com salt e fator de custo: bcrypt (custo ≥ 10), scrypt ou Argon2id.',
    exemploCorrecao: `import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(senha, 12);          // ao cadastrar
const confere = await bcrypt.compare(senha, hash);  // ao autenticar`,
  },
  custoBaixo: {
    ...base,
    id: 'AUT-002',
    titulo: 'Fator de custo do bcrypt abaixo do recomendado',
    severidade: Severidade.MEDIO,
    owasp: OWASP_CRIPTO,
    confianca: 'alta',
    explicacao: 'O número de rounds informado ao bcrypt é menor que 10.',
    impacto: 'Hashes com custo baixo são calculados muito rápido, reduzindo o esforço necessário para quebrar senhas vazadas.',
    recomendacao: 'Use custo entre 10 e 12 (ajuste conforme o desempenho do servidor).',
    exemploCorrecao: `const SALT_ROUNDS = 12;
const hash = await bcrypt.hash(senha, SALT_ROUNDS);`,
  },
  comparacaoDireta: {
    ...base,
    id: 'AUT-003',
    titulo: 'Senha comparada diretamente (provável armazenamento em texto puro)',
    severidade: Severidade.ALTO,
    owasp: OWASP_CRIPTO,
    confianca: 'media',
    explicacao: 'A senha informada é comparada com ===/== em vez de uma função de verificação de hash.',
    impacto: 'Indica que as senhas estão salvas sem hash; um vazamento do banco expõe a senha de todos os usuários. A comparação direta também é sujeita a ataques de tempo.',
    recomendacao: 'Armazene apenas o hash da senha e verifique com bcrypt.compare / argon2.verify.',
    exemploCorrecao: `const usuario = await buscarPorEmail(email);
const ok = usuario && (await bcrypt.compare(senha, usuario.senhaHash));
if (!ok) return res.status(401).json({ erro: 'Credenciais inválidas' });`,
  },
  jwtSemExpiracao: {
    ...base,
    id: 'AUT-004',
    titulo: 'Token JWT emitido sem tempo de expiração',
    severidade: Severidade.MEDIO,
    owasp: OWASP_AUTH,
    confianca: 'media',
    explicacao: 'jwt.sign() é chamado sem a opção expiresIn (nem claim exp).',
    impacto: 'Um token roubado continua válido para sempre, mesmo após troca de senha ou desligamento do usuário.',
    recomendacao: 'Defina expiresIn curto (ex.: 15min–8h) e, se necessário, use refresh tokens.',
    exemploCorrecao: `const token = jwt.sign({ sub: usuario.id, perfil: usuario.perfil }, process.env.JWT_SECRET!, {
  expiresIn: '1h',
  algorithm: 'HS256',
});`,
  },
  jwtDecode: {
    ...base,
    id: 'AUT-005',
    titulo: 'jwt.decode() usado sem verificar assinatura',
    severidade: Severidade.ALTO,
    owasp: OWASP_AUTH,
    confianca: 'media',
    explicacao: 'jwt.decode() apenas lê o conteúdo do token, sem validar a assinatura nem a expiração.',
    impacto: 'Se o resultado for usado para identificar o usuário, qualquer um pode forjar um token e se passar por outra pessoa.',
    recomendacao: 'Use jwt.verify() com o segredo e a lista de algoritmos permitidos.',
    exemploCorrecao: `const payload = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });`,
  },
  jwtAlgNone: {
    ...base,
    id: 'AUT-006',
    titulo: 'Validação de token aceita algoritmo "none" ou ignora expiração',
    severidade: Severidade.CRITICO,
    owasp: OWASP_AUTH,
    confianca: 'alta',
    explicacao: 'A configuração de verificação do token permite o algoritmo "none" ou desativa a checagem de expiração.',
    impacto: 'Tokens sem assinatura (ou expirados) são aceitos, permitindo se autenticar sem credenciais.',
    recomendacao: 'Liste explicitamente os algoritmos aceitos e mantenha a verificação de expiração ativa.',
    exemploCorrecao: `jwt.verify(token, segredo, { algorithms: ['HS256'] }); // sem 'none' e sem ignoreExpiration`,
  },
  cookieInseguro: {
    ...base,
    id: 'AUT-007',
    titulo: 'Cookie de sessão/token sem flags de segurança',
    severidade: Severidade.MEDIO,
    owasp: OWASP_AUTH,
    confianca: 'media',
    explicacao: 'Um cookie é definido sem httpOnly (ou com secure: false / httpOnly: false).',
    impacto: 'Sem httpOnly o token pode ser lido por scripts injetados (XSS); sem secure pode trafegar sem criptografia; sem sameSite fica exposto a CSRF.',
    recomendacao: 'Defina httpOnly: true, secure: true (em produção), sameSite: "strict" ou "lax" e um maxAge.',
    exemploCorrecao: `res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 60 * 60 * 1000,
});`,
  },
} satisfies Record<string, Regra>;

const CONTEXTO_SENHA = /senha|password|passwd|pwd|credencia/i;

/** Elo da cadeia: autenticação (hash de senhas, JWT, cookies). */
export class AnalisadorAutenticacao extends AnalisadorSeguranca {
  readonly nome = 'Autenticação';

  protected suporta(arquivo: ArquivoFonte): boolean {
    return ehArquivoDeCodigo(arquivo.linguagem);
  }

  protected verificar(arquivo: ArquivoFonte, _ctx: ContextoAnalise): Vulnerabilidade[] {
    const achados: Vulnerabilidade[] = [];
    const jsts = ehJsTs(arquivo.linguagem);

    this.paraCadaLinha(arquivo, (texto, linha) => {
      const contexto = arquivo.linhas.slice(Math.max(0, linha - 4), linha + 3).join('\n');

      if (/createHash\(\s*['"](md5|sha1|sha256)['"]|hashlib\.(md5|sha1|sha256)\(|\b(md5|sha1)\s*\(/i.test(texto) && CONTEXTO_SENHA.test(contexto)) {
        achados.push(this.criarAchado(REGRAS_AUTENTICACAO.hashFraco, arquivo, linha));
        return;
      }

      const rounds = /\b(?:bcrypt\w*\.)?(?:hash|hashSync|genSalt|genSaltSync)\s*\([^)]*?(?:,\s*|\()([1-9])\s*\)/.exec(texto);
      if (rounds && Number(rounds[1]) < 10 && /bcrypt|genSalt/i.test(contexto)) {
        achados.push(this.criarAchado(REGRAS_AUTENTICACAO.custoBaixo, arquivo, linha));
        return;
      }

      if (/\b\w*(senha|password)\w*\s*(===|!==|==|!=)\s*[\w.[\]'"]*(senha|password|req\.body)/i.test(texto) && !/confirm|repet|nova|new|length|null|undefined|''/i.test(texto)) {
        achados.push(this.criarAchado(REGRAS_AUTENTICACAO.comparacaoDireta, arquivo, linha));
        return;
      }

      if (jsts && /\bjwt\.sign\s*\(/.test(texto)) {
        const chamada = this.janela(arquivo, linha, 8);
        if (!/expiresIn|\bexp\s*:/.test(chamada)) achados.push(this.criarAchado(REGRAS_AUTENTICACAO.jwtSemExpiracao, arquivo, linha));
        return;
      }

      if (jsts && /\bjwt\.decode\s*\(/.test(texto) && !/\bjwt\.verify\s*\(/.test(arquivo.conteudo)) {
        achados.push(this.criarAchado(REGRAS_AUTENTICACAO.jwtDecode, arquivo, linha));
        return;
      }

      if (/algorithms?\s*[:=]\s*\[?[^\]\n]*['"]none['"]|ignoreExpiration\s*:\s*true|verify_signature['"]?\s*:\s*False/i.test(texto)) {
        achados.push(this.criarAchado(REGRAS_AUTENTICACAO.jwtAlgNone, arquivo, linha));
        return;
      }

      if (jsts && /\.cookie\s*\(/.test(texto) && /token|sess|auth|jwt/i.test(texto)) {
        const chamada = this.janela(arquivo, linha, 8);
        if (!/httpOnly\s*:\s*true/.test(chamada) || /secure\s*:\s*false/.test(chamada)) {
          achados.push(this.criarAchado(REGRAS_AUTENTICACAO.cookieInseguro, arquivo, linha));
        }
      }
    });

    return achados;
  }
}
