/**
 * Router instructions and worker facts land on the lead as they are produced.
 *
 * Worker tool ops are mirrored by the tool runtime. A router has no tools, so
 * its finished instruction is recorded on the lead graph and handed to the lead.
 */
import { STATE_SCHEMA } from './constants.js';
import { commitLeadLedger } from './ledger-host.js';
import { sessionDepth, sessionPlane } from './session-role.js';

function agentsOf(ctx) {
  try {
    if (ctx?.agents && typeof ctx.agents.get === 'function') return ctx.agents;
    return ctx.get('agents');
  } catch {
    return undefined;
  }
}

function leadOf(ctx, agent) {
  const agents = agentsOf(ctx);
  if (agents === undefined) return undefined;
  const seen = new Set();
  let current = agent;
  while (typeof current?.session?.header?.parentSession === 'string' && current.session.header.parentSession.length > 0) {
    const parentId = current.session.header.parentSession;
    if (seen.has(parentId)) break;
    seen.add(parentId);
    let parent;
    try { parent = agents.get(parentId); } catch { parent = undefined; }
    if (parent?.session === undefined) break;
    current = parent;
  }
  return current === agent ? undefined : current;
}

function messageText(event) {
  const data = event?.data ?? {};
  const content = data.content ?? data.message?.content ?? data.text;
  if (typeof content === 'string') return content.trim();
  if (!Array.isArray(content)) return '';
  return content
    .filter((block) => block?.type === 'text' && typeof block.text === 'string')
    .map((block) => block.text.trim())
    .filter(Boolean)
    .join('\n')
    .trim();
}

function instructionOp(sessionId, messageId, text) {
  const key = `router-instruction/${sessionId}/${messageId}`;
  return {
    op: 'node.upsert',
    kind: 'task',
    key,
    label: 'Router 指令',
    status: 'recorded',
    attrs: {
      actionType: 'router_instruction',
      from: sessionId,
      text: text.slice(0, 4000),
    },
  };
}

/** Record each finished router instruction on the lead and pass the text upward. */
export function installLeadUplink(ctx, config = {}) {
  if (config.routerMode !== true || typeof ctx?.on !== 'function') return;
  const seen = new Set();
  ctx.on('session/event', (session, event) => {
    if (event?.type !== 'assistant/message') return;
    const messageId = String(event.id ?? event.data?.id ?? event.data?.message?.id ?? '');
    if (messageId.length === 0 || seen.has(messageId)) return;
    const text = messageText(event);
    if (text.length < 8) return;
    const agents = agentsOf(ctx);
    const agent = agents?.get?.(session?.id);
    if (agent === undefined || sessionPlane(ctx, agent, config) !== 'router') return;
    if (sessionDepth(ctx, agent) !== 1) return;
    const lead = leadOf(ctx, agent);
    if (lead?.session === undefined) return;
    seen.add(messageId);
    const note = `Router 指令：\n${text.slice(0, 4000)}`;
    void commitLeadLedger(ctx, lead.session, {
      schema: STATE_SCHEMA,
      at: new Date().toISOString(),
      ops: [instructionOp(session.id, messageId, text)],
    }).catch((error) => {
      ctx.logger?.warn?.(`atk-brain: router instruction was not copied to the lead: ${error instanceof Error ? error.message : String(error)}`);
    });
    void (async () => {
      try {
        const subagents = ctx.get('subagents');
        if (typeof subagents?.sendMessage === 'function') {
          await subagents.sendMessage(agent, lead.session.id, [{ type: 'text', text: note }], { signal: AbortSignal.timeout(8000) });
          return;
        }
      } catch {
        /* team delivery is the other channel */
      }
      try {
        const teams = ctx.get('agentTeams');
        if (typeof teams?.sendMessage === 'function') {
          await teams.sendMessage(agent, {
            target: 'lead',
            content: [{ type: 'text', text: note }],
            signal: AbortSignal.timeout(8000),
          });
        }
      } catch (error) {
        ctx.logger?.warn?.(`atk-brain: router instruction was not delivered to the lead: ${error instanceof Error ? error.message : String(error)}`);
      }
    })();
  });
}
