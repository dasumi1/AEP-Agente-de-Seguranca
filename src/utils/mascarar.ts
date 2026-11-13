/**
 * Mascara segredos em trechos de código.
 * Aplicado a TODO trecho que vai para o relatório e a TODO conteúdo enviado ao LLM,
 * para que o próprio agente não vaze as credenciais que encontrou.
 */

function ocultar(valor: string): string {
  if (valor.length <= 4) return '****';
  return `${valor.slice(0, 2)}${'*'.repeat(Math.min(8, valor.length - 2))}`;
}

const PADROES_TOKEN: RegExp[] = [
  /AKIA[0-9A-Z]{16}/g, // AWS Access Key
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, // GitHub
  /\bsk-[A-Za-z0-9_-]{20,}\b/g, // OpenAI / Anthropic e similares
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, // Slack
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, // JWT
];

export function mascararSegredos(texto: string): string {
  let r = texto;

  for (const p of PADROES_TOKEN) r = r.replace(p, (m) => ocultar(m));

  // Strings de conexão: proto://usuario:SENHA@host
  r = r.replace(
    /\b([a-z][a-z0-9+.-]*:\/\/[^:\s'"`/]+:)([^@\s'"`]+)(@)/gi,
    (_m, a: string, senha: string, c: string) =>
      senha.startsWith('${') ? `${a}${senha}${c}` : `${a}${ocultar(senha)}${c}`,
  );

  // Atribuições com literal: senha = "valor", apiKey: 'valor'
  r = r.replace(
    /((?:pass(?:word|wd)?|pwd|senha|secret|segredo|token|api[_-]?key|apikey|private[_-]?key|client[_-]?secret|credencial)[A-Za-z0-9_]*["']?\s*[:=]\s*)(["'`])([^"'`\n]{3,}?)(\2)/gi,
    (m, pre: string, q: string, val: string, q2: string) => {
      if (/^(process\.env|import\.meta|os\.environ|getenv|env\(|\$\{)/i.test(val) || /[^\x21-\x7e]/.test(val)) return m;
      return `${pre}${q}${ocultar(val)}${q2}`;
    },
  );

  // Valor padrão de segredo: process.env.JWT_SECRET || 'valor'
  r = r.replace(
    /((?:process\.env|os\.environ(?:\.get)?|getenv)[.[('"]*[A-Z0-9_]*(?:SECRET|PASS|PWD|TOKEN|KEY|SENHA|SEGREDO)[A-Z0-9_]*['")\]]*\s*(?:\|\||\?\?|,|or)\s*)(["'`])([^"'`]{3,})(\2)/gi,
    (_m, pre: string, q: string, val: string, q2: string) => `${pre}${q}${ocultar(val)}${q2}`,
  );

  // SQL: IDENTIFIED BY 'senha' / SET PASSWORD = 'senha'
  r = r.replace(
    /(IDENTIFIED\s+(?:WITH\s+\w+\s+)?BY\s+|PASSWORD\s*(?:\(\s*)?=?\s*)(['"])([^'"]{3,})(\2)/gi,
    (_m, pre: string, q: string, val: string, q2: string) => `${pre}${q}${ocultar(val)}${q2}`,
  );

  // Estilo .env / properties: DB_PASSWORD=valor (início da linha, sem aspas)
  r = r.replace(
    /^(\s*(?:export\s+)?[A-Za-z0-9_.]*(?:pass(?:word|wd)?|pwd|senha|secret|segredo|token|api[_-]?key|apikey|private[_-]?key|credencial)[A-Za-z0-9_.]*\s*=\s*)([^\s"'`]{3,})\s*$/gim,
    (m, pre: string, val: string) => (/^\$\{|^\$[A-Z_]/.test(val) ? m : `${pre}${ocultar(val)}`),
  );

  // Blocos de chave privada
  r = r.replace(
    /(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
    '$1 ****',
  );

  return r;
}
