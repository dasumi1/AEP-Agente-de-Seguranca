import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { RelatorioSeguranca } from '../models/RelatorioSeguranca.js';
import { REGEX_ID_RELATORIO } from '../utils/id.js';
import { relatorioParaMarkdown } from './ApresentadorMarkdown.js';

export interface ResumoRelatorio {
  id: string;
  geradoEm: string;
  gatilho: string;
  commit?: string;
  total: number;
  porSeveridade: RelatorioSeguranca['resumo']['porSeveridade'];
}

/** Persiste relatórios como JSON + Markdown (histórico consultável pela API). */
export class RepositorioRelatorios {
  constructor(readonly diretorio: string) {}

  salvar(r: RelatorioSeguranca): { json: string; markdown: string } {
    mkdirSync(this.diretorio, { recursive: true });
    const json = path.join(this.diretorio, `relatorio-${r.id}.json`);
    const markdown = path.join(this.diretorio, `relatorio-${r.id}.md`);
    writeFileSync(json, JSON.stringify(r, null, 2), 'utf8');
    writeFileSync(markdown, relatorioParaMarkdown(r), 'utf8');
    writeFileSync(path.join(this.diretorio, 'ultimo.md'), relatorioParaMarkdown(r), 'utf8');
    return { json, markdown };
  }

  listar(limite = 50): ResumoRelatorio[] {
    let nomes: string[];
    try {
      nomes = readdirSync(this.diretorio);
    } catch {
      return [];
    }
    return nomes
      .filter((n) => /^relatorio-.+\.json$/.test(n))
      .sort()
      .reverse()
      .slice(0, limite)
      .flatMap((n) => {
        try {
          const r = JSON.parse(readFileSync(path.join(this.diretorio, n), 'utf8')) as RelatorioSeguranca;
          return [{ id: r.id, geradoEm: r.geradoEm, gatilho: r.gatilho, commit: r.commit, total: r.resumo.total, porSeveridade: r.resumo.porSeveridade }];
        } catch {
          return [];
        }
      });
  }

  /** Busca por id; o formato do id é validado para impedir path traversal. */
  obter(id: string): RelatorioSeguranca | undefined {
    if (!REGEX_ID_RELATORIO.test(id)) return undefined;
    try {
      return JSON.parse(readFileSync(path.join(this.diretorio, `relatorio-${id}.json`), 'utf8')) as RelatorioSeguranca;
    } catch {
      return undefined;
    }
  }
}
