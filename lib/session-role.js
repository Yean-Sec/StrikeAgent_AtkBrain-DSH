/**
 * Session plane for the router / worker / subagent split.
 *
 * Depth follows the parentSession chain.
 * 0 is the lead, the only session the operator talks to.
 * 1 is a router shard. The lead opens one router per target: one target, one
 * router; many targets, many routers. Routers share the lead graph.
 * 2 is a worker that router dispatched.
 * 3 or more is a subagent and cannot dispatch again.
 * `routerMode: false` keeps the previous single-executor behavior.
 */
import { TOOL_NAMES } from './constants.js';

function agentsOf(ctx) {
  try {
    if (ctx?.agents !== undefined && ctx.agents !== null && typeof ctx.agents.get === 'function') return ctx.agents;
  } catch {
    /* service getter unavailable */
  }
  try {
    const agents = ctx?.get?.('agents');
    if (agents !== undefined && agents !== null && typeof agents.get === 'function') return agents;
  } catch {
    /* agents service is not provided */
  }
  return undefined;
}

function parentIdOf(agent) {
  const parentId = agent?.session?.header?.parentSession;
  return typeof parentId === 'string' && parentId.length > 0 ? parentId : undefined;
}

/** How many parent sessions sit above this agent. 0 is the operator session. */
export function sessionDepth(ctx, agent) {
  // DSH records the delegation depth on the session header when a session is
  // spawned (lead 0, teammate/router 1, worker 2, subagent 3). Prefer it: the
  // parentSession walk below needs the parent agent in this registry and
  // silently collapses to depth 1 when a teammate session is not registered,
  // which misclassifies every worker as a router.
  const declared = agent?.session?.header?.delegationDepth;
  if (typeof declared === 'number' && Number.isFinite(declared) && declared >= 0) return declared;
  const agents = agentsOf(ctx);
  const seen = new Set();
  let depth = 0;
  let current = agent;
  while (current !== undefined && current !== null) {
    const parentId = parentIdOf(current);
    if (parentId === undefined || seen.has(parentId)) break;
    seen.add(parentId);
    depth += 1;
    if (agents === undefined) break;
    let parent;
    try {
      parent = agents.get(parentId);
    } catch {
      parent = undefined;
    }
    if (parent?.session === undefined) break;
    current = parent;
    if (depth > 8) break;
  }
  return depth;
}

/**
 * `legacy` when the router split is off.
 * Otherwise `lead`, `router`, `worker`, or `subagent`.
 */
export function sessionPlane(ctx, agent, config) {
  if (config?.routerMode !== true) return 'legacy';
  const depth = sessionDepth(ctx, agent);
  if (depth <= 0) return 'lead';
  if (depth === 1) return 'router';
  if (depth === 2) return 'worker';
  return 'subagent';
}

const EXECUTION_TOOLS = new Set([
  TOOL_NAMES.probe,
  TOOL_NAMES.tunnel,
  TOOL_NAMES.record,
  TOOL_NAMES.arsenal,
  TOOL_NAMES.coverage,
  TOOL_NAMES.hypothesis,
  TOOL_NAMES.survey,
  TOOL_NAMES.supervise,
  TOOL_NAMES.report,
]);

const ROUTER_SELF_DENY = new Set(['native', 'brief', 'detail', 'verify', 'report', 'escalate']);

function dispatchFor(plane, name, action) {
  if (plane === 'lead') return 'atkbrain_team action=plan task=targets mode=teammates，然后 action=dispatch。一个目标开一个 Router，多个目标开多个 Router。验证、提权和报告不要再开 Router';
  if (name === TOOL_NAMES.supervise || action === 'verify' || action === 'detail') return 'atkbrain_team action=plan task=verify mode=subagents，然后 action=dispatch';
  if (action === 'escalate') return '危害提升已关闭。把发现记在当前漏洞上，不要再派提权任务';
  if (name === TOOL_NAMES.report || action === 'report') return 'atkbrain_team action=plan task=report mode=subagents，然后 action=dispatch';
  if (action === 'brief' || action === 'native') return 'atkbrain_query action=frontier。只有连续空转时才 atkbrain_team action=plan task=review mode=subagents，然后 action=dispatch';
  if (name === TOOL_NAMES.survey) return 'atkbrain_team action=plan task=targets mode=subagents，然后 action=dispatch';
  return 'atkbrain_team action=plan task=targets mode=subagents，然后 action=dispatch';
}

/**
 * Refusal summary for a tool call, or null when the plane may run it.
 * The summary is returned to the model as a normal tool result.
 */
export function planeRefusal(name, input, plane) {
  if (plane === 'legacy') return null;
  const action = typeof input?.action === 'string' ? input.action : '';
  if (plane === 'router') {
    if (name === TOOL_NAMES.team || name === TOOL_NAMES.query || name === TOOL_NAMES.scope) return null;
    return `REFUSED: Router 只用插件派 Worker，不调用 ${name}。atkbrain_team action=plan task=targets mode=subagents，然后 action=dispatch。Worker 用 action=delegate 派 Subagent。两边的结果直接进 Router 的图，然后 Router 再派下一轮。`;
  }
  if (plane === 'lead') {
    if (EXECUTION_TOOLS.has(name)) {
      return `REFUSED: 当前会话是 Lead，只拆 Router、派发 Worker，不执行 ${name}。下一步：${dispatchFor(plane, name, action)}。`;
    }
    if (name === TOOL_NAMES.team && action === 'delegate') {
      return 'REFUSED: delegate 只属于 Worker。Lead 先拆 Router，再按 Router 的指令派发 Worker。';
    }
    if (name === TOOL_NAMES.selftteam && ROUTER_SELF_DENY.has(action)) {
      return `REFUSED: Lead 不亲自执行 ${action}。下一步：${dispatchFor(plane, name, action)}。`;
    }
    return null;
  }
  if (plane === 'worker' || plane === 'subagent') return null;
  return null;
}
