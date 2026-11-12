/**
 * Per-task scope assignments.
 *
 * The router writes one file per dispatched task. A worker or subagent must
 * present that token when it sets scope, and the allow list must stay inside
 * the assignment. Tokens are unguessable short hashes, not a channel between
 * sibling workers.
 */
import { readFile } from 'node:fs/promises';

import { evaluateScope, normalizeScopeEntry } from './scope.js';
import { artifactAbsolute, invalid } from './util.js';

function assignmentPath(token) {
  return `.atkbrain/team/assignments/${token}.json`;
}

function assertToken(token) {
  const text = String(token ?? '').trim();
  if (!/^[a-z0-9]{8,40}$/iu.test(text)) invalid('assignmentToken is missing or invalid');
  return text;
}

/** Persist one assignment under the session workspace. */
export async function saveAssignment(runtime, agent, token, body) {
  const safe = assertToken(token);
  const relative = assignmentPath(safe);
  await runtime.writeReportAt(agent, relative, JSON.stringify({ ...body, token: safe }));
  return relative;
}

/** Load one assignment. Missing files are an input error, not a wider scope. */
export async function loadAssignment(agent, token) {
  const safe = assertToken(token);
  const absolute = artifactAbsolute(agent, assignmentPath(safe));
  let text;
  try {
    text = await readFile(absolute, 'utf8');
  } catch {
    invalid('assignmentToken does not match a router assignment. Use the token in your task prompt; do not invent or reuse another task.');
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    invalid('assignment file is not valid JSON');
  }
  if (!Array.isArray(body?.allow)) invalid('assignment is missing an allow list');
  return body;
}

function entryTarget(entry) {
  if (entry.type === 'ip') return { type: 'ip', ip: entry.canonical };
  if (entry.type === 'cidr') return { type: 'cidr', cidr: entry.canonical };
  if (entry.type === 'url') return { type: 'url', url: entry.canonical };
  return { type: entry.type === 'domain' ? 'domain' : 'host', host: entry.canonical };
}

function portsWithin(requested, grantedAllow) {
  if (!Array.isArray(requested.ports) || requested.ports.length === 0) {
    const limited = grantedAllow.find((entry) => entry.type === requested.type && entry.canonical === requested.canonical && Array.isArray(entry.ports) && entry.ports.length > 0);
    if (limited !== undefined) {
      invalid(`allow ${requested.type}:${requested.canonical} drops the assignment port limit (${limited.ports.join(',')})`);
    }
    return;
  }
  const same = grantedAllow.find((entry) => entry.type === requested.type && entry.canonical === requested.canonical);
  if (same === undefined || !Array.isArray(same.ports) || same.ports.length === 0) return;
  const extra = requested.ports.filter((port) => !same.ports.includes(port));
  if (extra.length > 0) invalid(`allow ${requested.type}:${requested.canonical} adds ports outside the assignment: ${extra.join(',')}`);
}

/**
 * Reject a worker scope that is wider than the assignment.
 * Extra deny entries are allowed. Dropping an assignment deny is not.
 */
export function scopeWithinAssignment(requestedAllow, requestedDeny, assignment) {
  const grantedAllow = (Array.isArray(assignment?.allow) ? assignment.allow : []).map((entry) => normalizeScopeEntry(entry));
  const grantedDeny = (Array.isArray(assignment?.deny) ? assignment.deny : []).map((entry) => normalizeScopeEntry(entry));
  const nextAllow = (Array.isArray(requestedAllow) ? requestedAllow : []).map((entry) => normalizeScopeEntry(entry));
  const nextDeny = (Array.isArray(requestedDeny) ? requestedDeny : []).map((entry) => normalizeScopeEntry(entry));
  if (nextAllow.length === 0) invalid('worker scope set must repeat the assignment allow list');
  const granted = { allow: grantedAllow, deny: grantedDeny };
  for (const entry of nextAllow) {
    const verdict = evaluateScope(granted, entryTarget(entry));
    if (!verdict.allowed) {
      invalid(`allow ${entry.type}:${entry.canonical} is outside this assignment: ${verdict.reason}`);
    }
    portsWithin(entry, grantedAllow);
  }
  const requestedDenyKeys = new Set(nextDeny.map((entry) => `${entry.type}:${entry.canonical}`));
  for (const entry of grantedDeny) {
    const key = `${entry.type}:${entry.canonical}`;
    if (!requestedDenyKeys.has(key)) invalid(`deny ${key} is part of this assignment and cannot be removed`);
  }
}
