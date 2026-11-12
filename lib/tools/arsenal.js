/**
 * `atkbrain_arsenal` — dictionaries, wordlists, and in-process endpoint inventory.
 *
 * External scanner binaries and the skill library are not shipped or executed.
 */
import { TOOL_NAMES } from '../constants.js';
import { arsenalCatalog, dictPath, dictRead, dictSearch } from '../arsenal.js';
import { invalid } from '../util.js';
import { endpointInventory, harvest, mergeLedgerAttrs, pageTextSupplied, parameterNames, surfaceLedger, synthesize } from '../endpoint-vocab.js';
import { coverageKey, seedCoverage } from '../coverage.js';
import { capabilityNodeOp, coverageNodeOp } from './build.js';
import {
  assertArgs,
  audit,
  optionalInteger,
  optionalString,
  registerAtkTool,
  requireEnum,
  requireString,
} from './common.js';

const ACTIONS = ['catalog', 'dict_search', 'dict_read', 'dict_path', 'endpoint_vocab'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'Browse dictionaries and wordlists, or inventory endpoints from already saved HTML/JS. External scanners and skills are not available.' },
    query: { type: 'string', description: 'Search text for dict_search.' },
    path: { type: 'string', description: 'Dictionary path for dict_read/dict_path.' },
    lines: { type: 'integer', description: 'Preview line count for dict_read (1-400).' },
    target: { type: 'string', description: 'Host or URL for endpoint_vocab coverage seeding.' },
    limit: { type: 'integer', description: 'Result limit (1-40).' },
    text: { type: 'string', description: 'HTML/JS/response text for endpoint_vocab (max 200 KB).' },
  },
};

export function registerArsenalTool(ctx, config, runtime) {
  registerAtkTool(ctx, config, runtime, {
    name: TOOL_NAMES.arsenal,
    callTitle: 'Dictionaries and endpoint inventory',
    description: 'Search and read vendored dictionaries and wordlists, and inventory endpoints from saved HTML/JS. External pentest tools and skills are not available.',
    parameters: PARAMETERS,
    timeoutMs: 60000,
    concurrencySafe: false,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (action === 'dict_search' && typeof args.query !== 'string') invalid(`${action} requires query`);
      if (['dict_read', 'dict_path'].includes(action)) requireString(args, 'path', { max: 1000 });
      if (action === 'endpoint_vocab') requireString(args, 'text', { max: 200000 });
      if (args.lines !== undefined) optionalInteger(args, 'lines', { min: 1, max: 400 });
      if (args.limit !== undefined) optionalInteger(args, 'limit', { min: 1, max: 40 });
      if (args.target !== undefined) optionalString(args, 'target', { max: 2000 });
      return action;
    },
    async run({ args, state }) {
      if (args.action === 'catalog') {
        const catalog = await arsenalCatalog();
        return {
          summary: `Dictionaries: ${catalog.counts.dicts} file(s), ${catalog.counts.wordlists} wordlist(s). Skills and external pentest tools are not included.`,
          ops: [audit(TOOL_NAMES.arsenal, 'arsenal.catalog', 'catalog', `${catalog.counts.dicts} dictionaries`, [])],
          details: { counts: catalog.counts, source: catalog.source },
        };
      }

      if (args.action === 'dict_search') {
        const rows = await dictSearch(args.query, { limit: args.limit });
        const next = rows[0];
        const summary = `${rows.length} dictionary file(s) matched "${args.query}".${next ? ` Next: dict_read path="${next.path}".` : ''}${rows.length > 0 ? ` ${rows.map((row) => row.path).join('; ')}` : ''}`;
        return {
          summary,
          ops: [
            capabilityNodeOp(state, { capability: 'dictionary', action: 'dict_search', name: String(args.query ?? '').slice(0, 120), success: rows.length > 0, summary: `${rows.length} match(es)` }),
            audit(TOOL_NAMES.arsenal, 'arsenal.dict_search', String(args.query ?? '').slice(0, 120), `${rows.length} match(es)`, []),
          ],
          details: { rows, next: next ? { action: 'dict_read', path: next.path } : null },
        };
      }

      if (args.action === 'dict_read') {
        const result = await dictRead(args.path, { lines: args.lines });
        const summary = `Dictionary ${result.path}: ${result.totalLines} line(s), showing ${result.lines.length}.`;
        return {
          summary,
          ops: [
            capabilityNodeOp(state, { capability: 'dictionary', action: 'dict_read', name: result.path, success: result.lines.length > 0, summary: `${result.lines.length}/${result.totalLines} line(s)` }),
            audit(TOOL_NAMES.arsenal, 'arsenal.dict_read', result.path, `${result.lines.length}/${result.totalLines} line(s)`, []),
          ],
          details: result,
        };
      }

      if (args.action === 'dict_path') {
        const resolved = dictPath(args.path);
        return {
          summary: `Dictionary path: ${resolved}`,
          ops: [
            capabilityNodeOp(state, { capability: 'dictionary', action: 'dict_path', name: args.path, success: true, summary: resolved }),
            audit(TOOL_NAMES.arsenal, 'arsenal.dict_path', args.path, resolved, []),
          ],
          details: { path: resolved },
        };
      }

      const candidates = synthesize(args.text, { limit: 400 });
      const parameters = parameterNames(args.text, { limit: 100 });
      const known = harvest(args.text).known.length;
      const inventory = endpointInventory(args.text, { limit: 200 });
      const ledger = surfaceLedger(args.text);
      const coverageOps = [];
      if (args.target && ledger.endpoints.length > 0) {
        const existing = new Set(Object.values(state.nodes).filter((node) => node.kind === 'coverage').map((node) => `${node.attrs?.path}#${node.attrs?.bugClass}`));
        const paths = ledger.endpoints.slice(0, 80);
        const cells = seedCoverage(paths, { role: 'lead', limit: 500 })
          .map((cell) => ({ ...cell, key: cell.key ?? coverageKey(cell.path, cell.bugClass), targetKey: args.target }));
        for (const cell of cells) {
          if (existing.has(`${cell.path}#${cell.bugClass}`)) continue;
          existing.add(`${cell.path}#${cell.bugClass}`);
          coverageOps.push(coverageNodeOp(state, cell));
        }
      }
      const surfaceOps = [];
      if (args.target && (ledger.parameters.length > 0 || ledger.contexts.length > 0 || ledger.endpoints.length > 0)) {
        const needle = String(args.target).toLowerCase();
        const webapp = Object.values(state.nodes).find((node) => node.kind === 'webapp'
          && `${node.key} ${node.label} ${node.attrs?.url ?? ''} ${node.attrs?.host ?? ''}`.toLowerCase().includes(needle));
        if (webapp !== undefined) {
          surfaceOps.push({
            op: 'node.upsert',
            kind: 'webapp',
            key: webapp.key,
            label: webapp.label,
            attrs: mergeLedgerAttrs(webapp.attrs ?? {}, args.text, { inventoried: pageTextSupplied(args.text) }),
          });
        }
      }
      return {
        summary: `Endpoint surface: ${inventory.endpoints.length} concrete endpoint(s) (${inventory.endpoints.slice(0, 8).join(', ') || 'none'}), ${inventory.parameters.length} parameter name(s), contexts: ${inventory.contexts.join(', ') || 'none'}; ${candidates.length} candidate path(s) from ${known} known path(s). Seeded ${coverageOps.length} coverage cell(s)${args.target ? '' : ' (pass target to seed coverage)'}.`,
        ops: [...coverageOps, ...surfaceOps],
        details: {
          endpoints: inventory.endpoints,
          queryParams: inventory.queryParams,
          contexts: inventory.contexts,
          parameters: inventory.parameters,
          candidates,
          known,
          coverageSeeded: coverageOps.length,
        },
      };
    },
  });
}
