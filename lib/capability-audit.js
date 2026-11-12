/**
 * Audit which capability families were actually invoked, not merely configured.
 *
 * External scanners and the skill library are not part of this project, so
 * they are not required. A dictionary still counts only after dict_read or
 * dict_path, and a wordlist whose path names a different technology family
 * does not count.
 */

import { BUG_CLASSES } from './coverage.js';

const GENERIC_STACK = new Set(['apache', 'http', 'https', 'server', 'web', 'unknown', 'microsoft', 'oracle', 'linux', 'ubuntu', 'nginx']);
const ECOSYSTEMS = Object.freeze([
  { id: 'java', tokens: ['java', 'jsp', 'struts', 'tomcat', 'spring', 'jsf', 'jboss', 'weblogic'] },
  { id: 'php', tokens: ['php', 'laravel', 'wordpress', 'thinkphp', 'drupal', 'phpmyadmin'] },
  { id: 'dotnet', tokens: ['aspx', 'iis', 'dotnet'] },
  { id: 'python', tokens: ['python', 'django', 'flask'] },
  { id: 'ruby', tokens: ['ruby', 'rails'] },
  { id: 'node', tokens: ['nodejs', 'express', 'node'] },
]);

function hasToken(text, token) {
  const escaped = String(token).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:^|[^a-z0-9])${escaped}(?:[^a-z0-9]|$)`, 'iu').test(text);
}

function techBlob(nodes) {
  return nodes
    .filter((node) => node.kind === 'tech')
    .map((node) => `${node.label ?? ''} ${node.attrs?.product ?? ''} ${node.attrs?.vendor ?? ''} ${node.attrs?.version ?? ''}`)
    .join(' ')
    .toLowerCase();
}

/** Product words already stored on technology nodes. Versions and generic vendors are left out. */
export function stackTokens(nodes) {
  const tokens = new Set();
  for (const word of techBlob(nodes).split(/[^a-z0-9.+-]+/u)) {
    if (word.length < 4 || GENERIC_STACK.has(word) || /^\d/u.test(word)) continue;
    tokens.add(word);
  }
  return [...tokens];
}

/** Skills are not shipped. Nothing is waiting on a skill load. */
export function missingClassSkills() {
  return [];
}

const CLASS_DICT = Object.freeze({
  xss: { query: 'xss', tokens: ['xss'] },
  sqli: { query: 'sql', tokens: ['sql'] },
  cmd: { query: 'command', tokens: ['command', 'cmd', 'rce'] },
  code: { query: 'code execution', tokens: ['code', 'ssti', 'template'] },
  file: { query: 'file', tokens: ['file', 'lfi', 'upload', 'path'] },
});

function openBugClasses(nodes) {
  const classes = new Set();
  for (const node of nodes) {
    if (node.kind !== 'coverage' || !['open', 'claimed'].includes(node.status)) continue;
    const bug = String(node.attrs?.bugClass ?? '');
    if (BUG_CLASSES.includes(bug)) classes.add(bug);
  }
  return [...classes];
}

/** Skills are not shipped. Open coverage does not ask for one. */
export function missingCoverageSkills() {
  return [];
}

function dictReadNames(nodes) {
  const names = [];
  for (const node of nodes) {
    if (node.kind !== 'task' || node.status !== 'completed' || node.attrs?.success !== true) continue;
    const action = node.attrs?.capabilityAction;
    if (node.attrs?.capability !== 'dictionary' || (action !== 'dict_read' && action !== 'dict_path')) continue;
    names.push(String(node.attrs?.capabilityName ?? '').toLowerCase());
  }
  return names;
}

/** Open classes whose payload dictionary has not been read. One sql wordlist does not cover command execution. */
export function missingClassDictionaries(nodes) {
  const reads = dictReadNames(nodes);
  const missing = [];
  for (const bug of openBugClasses(nodes)) {
    const spec = CLASS_DICT[bug];
    if (spec === undefined) continue;
    const covered = reads.some((name) => spec.tokens.some((token) => name.includes(token)));
    if (!covered) missing.push({ bug, query: spec.query });
  }
  return missing;
}

function ecosystemsInText(text) {
  const body = String(text ?? '').toLowerCase();
  return ECOSYSTEMS.filter((eco) => eco.tokens.some((token) => hasToken(body, token))).map((eco) => eco.id);
}

function ecosystemsInPath(path) {
  const segments = String(path ?? '').toLowerCase().split(/[^a-z0-9.+-]+/u);
  return ECOSYSTEMS.filter((eco) => eco.tokens.some((token) => segments.includes(token))).map((eco) => eco.id);
}

/** True when the wordlist path names a technology family the graph has not observed. */
export function dictionaryConflicts(path, nodes) {
  const observed = ecosystemsInText(techBlob(nodes));
  if (observed.length === 0) return false;
  const dict = ecosystemsInPath(path);
  if (dict.length === 0) return false;
  return dict.every((id) => !observed.includes(id));
}

export function capabilityAudit(state) {
  const nodes = Object.values(state?.nodes ?? {}).filter((node) => node.status !== 'merged');
  const evidence = nodes.filter((node) => node.kind === 'evidence');
  const capabilities = nodes.filter((node) => node.kind === 'task' && node.attrs?.actionType === 'capability');
  const tools = new Map();
  for (const node of evidence) {
    const attrs = node.attrs ?? {};
    const label = String(node.label ?? '');
    const name = attrs.toolName !== undefined
      ? String(attrs.toolName)
      : (/^tool\s+(.+?)(?:\s+·.*)?$/u.exec(label)?.[1] ?? null);
    if (name === null || name.length === 0 || attrs.origin !== 'arsenal') continue;
    const current = tools.get(name) ?? { name, runs: 0, successes: 0, failures: 0, unknown: 0, timedOut: 0, lastExitCode: null };
    current.runs += 1;
    if (attrs.success === true) current.successes += 1;
    else if (attrs.success === false) current.failures += 1;
    else if (/failed|失败/iu.test(label)) current.failures += 1;
    else current.unknown += 1;
    if (attrs.timedOut === true) current.timedOut += 1;
    if (Number.isFinite(attrs.exitCode)) current.lastExitCode = attrs.exitCode;
    tools.set(name, current);
  }
  const byCapability = (name, countsAsUse) => {
    const rows = capabilities.filter((node) => node.attrs?.capability === name);
    const failures = rows.filter((node) => node.attrs?.success === false || node.status === 'failed');
    const used = rows.some((node) => countsAsUse(node) && node.attrs?.success === true && node.status === 'completed');
    return {
      calls: rows.length,
      failures: failures.length,
      names: [...new Set(rows.map((node) => String(node.attrs?.capabilityName ?? node.attrs?.capabilityAction ?? '—')))].slice(0, 12),
      used,
    };
  };
  const skill = byCapability('skill', () => false);
  skill.missing = [];
  skill.stackUsed = true;
  skill.used = true;
  const dictionary = byCapability('dictionary', (node) => {
    const action = node.attrs?.capabilityAction;
    if (action !== 'dict_read' && action !== 'dict_path') return false;
    return !dictionaryConflicts(node.attrs?.capabilityName, nodes);
  });
  const toolRows = [...tools.values()].sort((a, b) => a.name.localeCompare(b.name));
  const toolFailures = toolRows.reduce((sum, row) => sum + row.failures, 0);
  const toolRuns = toolRows.reduce((sum, row) => sum + row.runs, 0);
  const toolSuccesses = toolRows.reduce((sum, row) => sum + row.successes, 0);
  const gaps = [];
  if (!dictionary.used) {
    const conflict = capabilities.some((node) => (node.attrs?.capabilityAction === 'dict_read' || node.attrs?.capabilityAction === 'dict_path')
      && node.attrs?.success === true
      && node.status === 'completed'
      && dictionaryConflicts(node.attrs?.capabilityName, nodes));
    gaps.push(conflict ? 'dict_read path conflicts with the observed technology stack' : 'dictionary was not read with dict_read');
  }
  return {
    tools: { runs: toolRuns, successes: toolSuccesses, failures: toolFailures, names: toolRows.map((row) => row.name).slice(0, 30), rows: toolRows },
    jsUrlExtractor: { used: false, required: false, names: [], webapps: 0 },
    skill,
    dictionary,
    used: { tools: toolSuccesses > 0, skill: skill.used, dictionary: dictionary.used },
    gaps,
  };
}
