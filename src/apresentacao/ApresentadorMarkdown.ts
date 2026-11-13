import type { RelatorioSeguranca } from '../models/RelatorioSeguranca.js';
import { TODAS_SEVERIDADES, Severidade } from '../models/Severidade.js';

const ICONE: Record<Severidade, string> = {
  [Severidade.CRITICO]: '🔴',
  [Severidade.ALTO]: '🟠',
  [Severidade.MEDIO]: '🟡',
  [Severidade.BAIXO]: '🔵',
};

const LINGUAGEM_BLOCO: Record<string, string> = {
  ts: 'ts', tsx: 'tsx', js: 'js', jsx: 'jsx', mjs: 'js', cjs: 'js', py: 'python', php: 'php',
  java: 'java', sql: 'sql', env: 'bash', json: 'json', yml: 'yaml', yaml: 'yaml',
};

/**
 * Formata o relatório em Markdown (legível no GitHub, no terminal ou anexado a issues).
 * Não é uma "View" de interface gráfica: é apenas uma representação textual do Model.
 */
export function relatorioParaMarkdown(r: RelatorioSeguranca): string {
  const l: string[] = [];
  l.push(`# Relatório do Agente de Segurança`);
  l.push('');
  l.push(`- **Projeto:** \`${r.projeto}\``);
  l.push(`- **Gerado em:** ${new Date(r.geradoEm).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })}`);
  l.push(`- **Gatilho:** ${r.gatilho}${r.commit ? ` (commit \`${r.commit.slice(0, 10)}\`)` : ''} · **Modo:** ${r.modo}`);
  l.push(`- **Stack detectada:** ${[...r.stack.ecossistemas, ...r.stack.frameworks, ...r.stack.bancos].join(', ') || 'não identificada'}`);
  l.push(`- **Arquivos analisados:** ${r.arquivosAnalisados} · **Análise contextual (LLM):** ${r.llmUtilizado ? 'sim' : 'não'} · **Duração:** ${(r.duracaoMs / 1000).toFixed(1)}s`);
  l.push('');
  l.push('> ℹ️ Este relatório é **consultivo**: o agente não bloqueia commits, pushes ou merges. Todas as vulnerabilidades — inclusive as de risco baixo — devem ser registradas e corrigidas.');
  l.push('');
  l.push('## Resumo');
  l.push('');
  l.push('| Severidade | Quantidade |');
  l.push('|---|---|');
  for (const s of TODAS_SEVERIDADES) l.push(`| ${ICONE[s]} ${s} | ${r.resumo.porSeveridade[s]} |`);
  l.push(`| **Total** | **${r.resumo.total}** |`);
  l.push('');

  if (r.avisos.length) {
    l.push('### Avisos da execução');
    l.push('');
    r.avisos.forEach((a) => l.push(`- ${a}`));
    l.push('');
  }

  if (r.vulnerabilidades.length === 0) {
    l.push('## ✅ Nenhuma vulnerabilidade encontrada');
    l.push('');
    l.push('Nenhum problema foi identificado no escopo analisado. Isso não garante ausência total de falhas; mantenha revisões periódicas.');
    return l.join('\n');
  }

  l.push('## Vulnerabilidades');
  l.push('');
  r.vulnerabilidades.forEach((v, i) => {
    const ext = v.arquivo.split('.').pop()?.toLowerCase() ?? '';
    l.push(`### ${i + 1}. ${ICONE[v.severidade]} ${v.titulo}`);
    l.push('');
    l.push(`| Campo | Valor |`);
    l.push(`|---|---|`);
    l.push(`| **Vulnerabilidade** | ${v.titulo} (\`${v.regraId}\`) |`);
    l.push(`| **Arquivo/linha** | \`${v.arquivo}:${v.linha}\` |`);
    l.push(`| **Nível de risco** | ${ICONE[v.severidade]} **${v.severidade}** |`);
    l.push(`| **Categoria** | ${v.categoria} |`);
    l.push(`| **OWASP** | ${v.owasp} |`);
    l.push(`| **Origem / confiança** | ${v.origem} / ${v.confianca} |`);
    l.push('');
    if (v.trecho) {
      l.push('**Trecho:**');
      l.push('```' + (LINGUAGEM_BLOCO[ext] ?? ''));
      l.push(v.trecho);
      l.push('```');
    }
    l.push(`**Explicação:** ${v.explicacao}`);
    l.push('');
    l.push(`**Impacto:** ${v.impacto}`);
    l.push('');
    l.push(`**Recomendação:** ${v.recomendacao}`);
    l.push('');
    if (v.observacao) {
      l.push(`**Observação:** ${v.observacao}`);
      l.push('');
    }
    if (v.exemploCorrecao) {
      l.push('**Exemplo de correção:**');
      l.push('```' + (LINGUAGEM_BLOCO[ext] ?? ''));
      l.push(v.exemploCorrecao);
      l.push('```');
    }
    l.push('');
  });
  return l.join('\n');
}

/** Resumo curto para terminal/console. */
export function resumoConsole(r: RelatorioSeguranca): string {
  const partes = TODAS_SEVERIDADES.map((s) => `${s}: ${r.resumo.porSeveridade[s]}`).join(' | ');
  const linhas = [`[Agente de Segurança] ${r.resumo.total} vulnerabilidade(s) em ${r.arquivosAnalisados} arquivo(s) — ${partes}`];
  for (const v of r.vulnerabilidades.slice(0, 15)) {
    linhas.push(`  ${ICONE[v.severidade]} [${v.severidade}] ${v.arquivo}:${v.linha} — ${v.titulo}`);
  }
  if (r.vulnerabilidades.length > 15) linhas.push(`  ... e mais ${r.vulnerabilidades.length - 15}`);
  return linhas.join('\n');
}
