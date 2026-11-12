/**
 * Local dictionary and wordlist library.
 *
 * Pentest tool binaries and the skill library are not part of this project.
 * This module only reads the vendored dictionaries under assets/arsenal.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { invalid } from './util.js';

const ASSET_ROOT = fileURLToPath(new URL('../assets/arsenal/', import.meta.url));
let cachedIndex;

export function arsenalAssetRoot() {
  return ASSET_ROOT;
}

export async function loadArsenalIndex() {
  if (cachedIndex !== undefined) return cachedIndex;
  const text = await fs.readFile(path.join(ASSET_ROOT, 'index.json'), 'utf8');
  const index = JSON.parse(text);
  if (!Array.isArray(index.dicts)) throw new Error('arsenal index is malformed; dictionaries are missing');
  index.skills = [];
  index.resources = [];
  index.tools = [];
  index.scripts = [];
  index.counts = {
    ...(index.counts ?? {}),
    skills: 0,
    resources: 0,
    tools: 0,
    categories: {},
    dicts: index.dicts.length,
    wordlists: Array.isArray(index.wordlists) ? index.wordlists.length : 0,
  };
  cachedIndex = index;
  return index;
}

function assetPath(relative) {
  const raw = String(relative ?? '').replaceAll('\\', '/');
  if (!raw || raw.startsWith('/') || raw.split('/').includes('..')) invalid(`invalid arsenal path: ${relative}`);
  const absolute = path.resolve(ASSET_ROOT, raw);
  const rel = path.relative(ASSET_ROOT, absolute);
  if (rel.startsWith('..') || path.isAbsolute(rel)) invalid(`arsenal path escapes the library: ${relative}`);
  return absolute;
}

async function readAsset(relative, maxBytes = 2 * 1024 * 1024) {
  const absolute = assetPath(relative);
  const stat = await fs.stat(absolute);
  if (!stat.isFile()) invalid(`arsenal path is not a file: ${relative}`);
  if (stat.size > maxBytes) invalid(`arsenal file is too large to read (${stat.size} > ${maxBytes}): ${relative}`);
  return await fs.readFile(absolute, 'utf8');
}

function tokens(value) {
  return String(value ?? '').toLowerCase().split(/[\s,;/|_+.-]+/u).map((token) => token.trim()).filter((token) => token.length > 1);
}

function scoreText(haystack, query) {
  const text = String(haystack ?? '').toLowerCase();
  const words = tokens(query);
  if (words.length === 0) return 1;
  let score = 0;
  for (const word of words) {
    if (!word) continue;
    if (text.includes(word)) score += 8 + Math.min(8, word.length);
    for (const part of tokens(text)) {
      if (part === word) score += 4;
      else if (part.startsWith(word)) score += 2;
    }
  }
  return score;
}

export async function dictSearch(query, { limit = 12 } = {}) {
  const index = await loadArsenalIndex();
  const cap = Math.max(1, Math.min(Number(limit) || 12, 40));
  const rows = [];
  for (const dict of index.dicts) {
    const score = scoreText(`${dict.path} ${dict.note} ${dict.tags.join(' ')}`, query);
    if (score > 0) rows.push({ ...dict, score });
  }
  rows.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
  return rows.slice(0, cap).map(({ sha256, ...row }) => row);
}

export async function dictRead(relative, { lines = 80 } = {}) {
  const cap = Math.max(1, Math.min(Number(lines) || 80, 400));
  if (/\.(?:xlsx?|docx?|pptx?|pdf|zip|gz|tar|7z)$/iu.test(String(relative))) {
    return { path: String(relative), binary: true, lines: [], totalLines: 0, truncated: false, note: 'binary dictionary document; use dict_path and an Office/archive reader' };
  }
  const content = await readAsset(relative, 8 * 1024 * 1024);
  return {
    path: String(relative),
    lines: content.split('\n').slice(0, cap),
    totalLines: content.split('\n').length,
    truncated: content.split('\n').length > cap,
  };
}

export function dictPath(relative) {
  return assetPath(relative);
}

export async function arsenalCatalog() {
  const index = await loadArsenalIndex();
  return {
    counts: index.counts,
    source: index.source,
    skills: [],
    scripts: [],
    wordlists: index.wordlists,
    tools: [],
  };
}
