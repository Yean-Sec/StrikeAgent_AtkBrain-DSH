/**
 * Tasks the router may dispatch.
 *
 * Target testing, secondary verification, harm escalation, reporting and a
 * one-shot stall review are separate tasks. They are not a standing roster.
 */
import { pendingEscalations } from './escalation-queue.js';
import { projectCompletion } from './project-completion.js';
import { concreteAllowTargets } from './targets.js';
import { pendingFindings } from './verify-queue.js';
import { shortHash, stableStringify } from './util.js';

export const TASK_KINDS = Object.freeze(['targets', 'verify', 'report', 'review']);

function activeBatches(state) {
  return Object.values(state?.nodes ?? {}).filter((node) => node.kind === 'task'
    && node.attrs?.actionType === 'subagent_batch'
    && ['planned', 'dispatched', 'artifact_ready'].includes(node.status));
}

function findingAllow(state, finding) {
  const url = finding?.attrs?.url;
  const host = finding?.attrs?.host ?? finding?.attrs?.endpoint;
  if (typeof url === 'string' && url.includes('://')) return [{ type: 'url', value: url }];
  if (typeof host === 'string' && host.length > 0 && !host.includes('/')) return [{ type: 'host', value: host }];
  return Array.isArray(state?.scope?.allow) ? state.scope.allow : [];
}

/** Task kinds that still need a worker. Order is dispatch order. */
export function dueRouterTasks(state, config = {}) {
  const due = [];
  const active = activeBatches(state);
  const activeKinds = new Set(active.map((node) => node.attrs?.taskKind ?? 'targets'));
  const covered = new Set();
  for (const node of Object.values(state?.nodes ?? {})) {
    if (node.kind !== 'task' || node.attrs?.actionType !== 'subagent_batch') continue;
    if ((node.attrs?.taskKind ?? 'targets') !== 'targets') continue;
    if (!['planned', 'dispatched', 'artifact_ready', 'completed', 'merged'].includes(node.status)) continue;
    for (const key of [...(node.attrs?.assetKeys ?? []), ...(node.attrs?.assetIds ?? [])]) covered.add(String(key));
  }
  const tracks = concreteAllowTargets(state).filter((track) => !covered.has(track.canonical) && !covered.has(track.key));
  const assets = Object.values(state?.nodes ?? {}).filter((node) => ['host', 'ip', 'webapp'].includes(node.kind)
    && node.status !== 'merged'
    && !covered.has(node.key)
    && !covered.has(node.id));
  if ((tracks.length > 0 || assets.length > 0) && !activeKinds.has('targets')) due.push('targets');
  const unverified = pendingFindings(Object.values(state?.nodes ?? {}));
  if (unverified.length > 0 && !activeKinds.has('verify')) due.push('verify');
  const completion = projectCompletion(state);
  const hasImpact = Object.values(state?.nodes ?? {}).some((node) => node.kind === 'finding' && node.status !== 'merged');
  if (unverified.length === 0 && hasImpact && completion.reportComplete !== true && !activeKinds.has('report')) due.push('report');
  const loop = Object.values(state?.nodes ?? {}).find((node) => node.kind === 'loop');
  const stalled = (Number(loop?.attrs?.noProgressRounds) || 0) >= (Number(config.loopStallRounds) || 3);
  if (stalled && !activeKinds.has('review')) due.push('review');
  return due;
}

function assetOf(node) {
  return {
    id: node.id,
    key: node.key,
    kind: node.kind,
    label: node.label ?? node.attrs?.title ?? node.key,
  };
}

/**
 * One batch per finding or a single report/review batch.
 * Target batches stay in the team planner.
 */
export function roleTaskSpecs({ state, task, maxBatches = 4, findingId, reportType }) {
  const deny = Array.isArray(state?.scope?.deny) ? state.scope.deny : [];
  const limit = Math.max(1, Math.min(8, Number(maxBatches) || 4));
  if (task === 'verify' || task === 'escalate') {
    const queued = task === 'verify'
      ? pendingFindings(Object.values(state?.nodes ?? {}))
      : pendingEscalations(state);
    const selected = findingId === undefined
      ? queued.slice(0, limit)
      : queued.filter((node) => node.id === findingId || node.key === findingId || node.label === findingId).slice(0, 1);
    return selected.map((node) => {
      const batchId = `${task}-${shortHash(node.key, 8)}`;
      return {
        batchId,
        taskKind: task,
        allowDelegate: false,
        findingId: node.id,
        assets: [assetOf(node)],
        allow: findingAllow(state, node),
        deny,
        reportType: null,
        inputDocument: {
          schema: 'atkbrain/1',
          engagement: state.engagement ?? null,
          nodes: [node],
          edges: [],
        },
      };
    });
  }
  if (task === 'report') {
    const kind = reportType === 'finding' ? 'finding' : 'project';
    const node = kind === 'finding'
      ? Object.values(state?.nodes ?? {}).find((entry) => entry.kind === 'finding' && (entry.id === findingId || entry.key === findingId))
      : null;
    const batchId = kind === 'finding' && node !== undefined && node !== null
      ? `report-${shortHash(node.key, 8)}`
      : 'report-project';
    return [{
      batchId,
      taskKind: 'report',
      allowDelegate: false,
      findingId: node?.id ?? null,
      reportType: kind,
      assets: node ? [assetOf(node)] : [{ id: 'project', key: 'project', kind: 'report', label: 'project report' }],
      allow: Array.isArray(state?.scope?.allow) ? state.scope.allow : [],
      deny,
      inputDocument: {
        schema: 'atkbrain/1',
        engagement: state.engagement ?? null,
        nodes: node ? [node] : [],
        edges: [],
      },
    }];
  }
  if (task === 'review') {
    return [{
      batchId: `review-${shortHash(stableStringify(state?.seq ?? 0), 8)}`,
      taskKind: 'review',
      allowDelegate: false,
      findingId: null,
      reportType: null,
      assets: [{ id: 'review', key: 'review', kind: 'review', label: 'stall review' }],
      allow: Array.isArray(state?.scope?.allow) ? state.scope.allow : [],
      deny,
      inputDocument: null,
    }];
  }
  return [];
}
