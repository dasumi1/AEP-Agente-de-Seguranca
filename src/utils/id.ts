import { createHash, randomBytes } from 'node:crypto';

/** Id estável para um achado (mesma regra + arquivo + linha => mesmo id). */
export function idAchado(regraId: string, arquivo: string, linha: number): string {
  return createHash('sha256').update(`${regraId}|${arquivo}|${linha}`).digest('hex').slice(0, 12);
}

/** Id de relatório: ordenável por data e seguro para nome de arquivo. */
export function idRelatorio(data = new Date()): string {
  const carimbo = data.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  return `${carimbo}-${randomBytes(3).toString('hex')}`;
}

export const REGEX_ID_RELATORIO = /^\d{8}T\d{6}Z-[0-9a-f]{6}$/;
