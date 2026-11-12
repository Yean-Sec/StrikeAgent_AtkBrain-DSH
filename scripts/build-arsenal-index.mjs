#!/usr/bin/env node
/**
 * Build assets/arsenal/index.json from the vendored A-U text assets.
 *
 * The A-U skill frontmatter is YAML-ish but uses nested `metadata:` and folded
 * `description: >` blocks. Only the handful of scalars the workbench needs are
 * parsed here, so no YAML dependency is added to the plugin.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../assets/arsenal/', import.meta.url));
const SOURCE_ROOT = process.env.ATKBRAIN_AU_ROOT || '';

const TOOL_VERSION_ARGS = {
  nmap: ['--version'], masscan: ['--version'], hping3: ['--version'], naabu: ['-version'], rustscan: ['--version'],
  nc: ['-h'], ncat: ['--version'], netcat: ['-h'], openssl: ['version'], socat: ['-V'], telnet: ['-h'],
  curl: ['--version'], dig: ['-v'], ssh: ['-V'],
  ffuf: ['-version'], gobuster: ['version'], whatweb: ['--version'], wafw00f: ['--version'], nuclei: ['-version'],
  httpx: ['-version'], nikto: ['-Version'], sqlmap: ['--version'], hydra: ['-h'], dalfox: ['--version'],
  dnsx: ['-version'], gau: ['--version'], katana: ['-version'], mapcidr: ['-version'], subfinder: ['-version'],
  tlsx: ['-version'], uncover: ['-version'], dirsearch: ['--version'], JSFinder: ['-h'], 'bypass-403': [],
  ccupp: ['--help'], padbuster: ['-h'], githacker: ['--help'],
};

const TOOL_CATEGORIES = {
  nmap: 'recon', masscan: 'recon', hping3: 'recon', naabu: 'recon', rustscan: 'recon',
  nc: 'network', ncat: 'network', netcat: 'network', openssl: 'network', socat: 'network', telnet: 'network',
  curl: 'web', dig: 'dns', ssh: 'network',
  ffuf: 'web', gobuster: 'web', whatweb: 'web', wafw00f: 'web', nuclei: 'web', httpx: 'web',
  nikto: 'web', sqlmap: 'web', hydra: 'auth', dalfox: 'web',
  dnsx: 'dns', gau: 'web', katana: 'web', mapcidr: 'network', subfinder: 'dns', tlsx: 'tls',
  uncover: 'recon', dirsearch: 'web', JSFinder: 'web', 'bypass-403': 'web', ccupp: 'auth',
  padbuster: 'web', githacker: 'web',
};

const TOOL_DESCRIPTIONS = {
  nmap: 'Port/service scanner. Use read-only scan profiles inside the engagement scope.',
  ffuf: 'HTTP content/parameter fuzzer. Wordlists under assets/arsenal/wordlists.',
  httpx: 'HTTP probe and fingerprinting.',
  nuclei: 'Template-based vulnerability scanner.',
  dalfox: 'XSS scanner.',
  sqlmap: 'SQL injection verification (only after an injection point is confirmed).',
  dnsx: 'DNS resolver/probe.',
  gau: 'Fetch known URLs from public archives.',
  katana: 'Web crawler for endpoints and JavaScript routes.',
  mapcidr: 'CIDR expansion/aggregation.',
  subfinder: 'Passive subdomain enumeration.',
  tlsx: 'TLS certificate and SAN inspection.',
  uncover: 'Query public exposure search engines.',
  dirsearch: 'Directory brute force; small/medium wordlists only.',
  whatweb: 'Web fingerprinting.',
  wafw00f: 'WAF fingerprinting.',
  nikto: 'Legacy web server scanner.',
  hydra: 'Credential testing; only use credentials already observed or explicitly supplied.',
  curl: 'Raw HTTP client.',
  dig: 'DNS lookup.',
  ssh: 'SSH client for authorized pivots.',
  nc: 'TCP client for authorized checks.',
  JSFinder: 'Extract URLs and subdomains from JavaScript.',
  'bypass-403': '401/403 bypass checks.',
  ccupp: 'Credential/password profiling helper.',
  padbuster: 'Padding-oracle helper.',
  githacker: 'Git leak reconstruction helper.',
};

function stripQuotes(value) {
  const s = String(value ?? '').trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) return s.slice(1, -1);
  return s;
}

function parseFrontmatter(text) {
  if (!text.startsWith('---')) return {};
  const end = text.indexOf('\n---', 3);
  if (end < 0) return {};
  const head = text.slice(3, end);
  const out = {};
  const lines = head.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const top = /^([A-Za-z0-9_-]+):\s*(.*)$/u.exec(line);
    if (top) {
      const key = top[1];
      let raw = top[2].trim();
      if (['>', '>-', '>+', '|', '|-', '|+'].includes(raw)) {
        const folded = raw.startsWith('>');
        const block = [];
        for (let j = i + 1; j < lines.length; j += 1) {
          const next = lines[j];
          if (next.startsWith(' ') || next.startsWith('\t')) block.push(next.trim());
          else if (next.trim() === '') block.push('');
          else break;
        }
        raw = folded ? block.join(' ').replace(/\s+/gu, ' ').trim() : block.join('\n').trim();
        i += block.length;
      } else {
        raw = stripQuotes(raw);
      }
      out[key] = raw;
      continue;
    }
    const nested = /^\s{2}([A-Za-z0-9_-]+):\s*(.*)$/u.exec(line);
    if (nested) {
      const key = nested[1];
      const value = stripQuotes(nested[2]);
      if (!out.metadata || typeof out.metadata !== 'object') out.metadata = {};
      out.metadata[key] = value;
    }
  }
  return out;
}

async function walk(dir, base = dir) {
  const out = [];
  let entries;
  try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    if (entry.name === '.DS_Store') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await walk(full, base));
    else if (entry.isFile()) out.push({ full, rel: path.relative(base, full).split(path.sep).join('/') });
  }
  return out;
}

async function fileMeta(full) {
  const stat = await fs.stat(full);
  const data = await fs.readFile(full);
  return { bytes: stat.size, sha256: crypto.createHash('sha256').update(data).digest('hex'), lines: data.toString('utf8').split('\n').length };
}

function defaultCategory(name) {
  if (name === 'finding-review') return 'review';
  if (name === 'tool-kit' || name === 'waf-bypass-methodology') return 'shared';
  if (name === 'redteam-hunt' || name === 'recon-spiral') return 'playbook';
  return 'general';
}

async function buildSkills() {
  const root = path.join(ROOT, 'skills');
  const dirs = await fs.readdir(root, { withFileTypes: true });
  const skills = [];
  for (const dir of dirs.filter((entry) => entry.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
    const skillFile = path.join(root, dir.name, 'SKILL.md');
    let text;
    try { text = await fs.readFile(skillFile, 'utf8'); } catch { continue; }
    const fm = parseFrontmatter(text);
    const meta = fm.metadata && typeof fm.metadata === 'object' ? fm.metadata : {};
    const category = String(meta.category ?? fm.category ?? defaultCategory(dir.name)).split('/')[0] || defaultCategory(dir.name);
    const tags = String(meta.tags ?? fm.tags ?? '').split(',').map((tag) => tag.trim()).filter(Boolean);
    const refs = [];
    const dirFiles = await walk(path.join(root, dir.name));
    for (const file of dirFiles) {
      if (file.rel === 'SKILL.md') continue;
      const info = await fileMeta(file.full);
      refs.push({ path: `skills/${dir.name}/${file.rel}`, bytes: info.bytes, sha256: info.sha256 });
    }
    const info = await fileMeta(skillFile);
    skills.push({
      name: dir.name,
      description: String(fm.description ?? '').trim().slice(0, 1200),
      category,
      tags,
      path: `skills/${dir.name}/SKILL.md`,
      refs: refs.sort((a, b) => a.path.localeCompare(b.path)).slice(0, 80),
      bytes: info.bytes,
      lines: info.lines,
      sha256: info.sha256,
    });
  }
  return skills;
}

function inferDictTags(rel) {
  const tags = [];
  if (rel.includes('口令')) tags.push('口令', '默认口令');
  if (rel.includes('目录')) tags.push('目录', '路径');
  if (rel.includes('子域名')) tags.push('子域名', 'dns');
  if (rel.includes('探测')) tags.push('探测', 'payload');
  if (/华为/.test(rel)) tags.push('华为');
  if (/ssh/i.test(rel)) tags.push('ssh');
  return tags;
}

async function buildDicts() {
  const entries = new Map();
  let catalog = { items: {} };
  try { catalog = JSON.parse(await fs.readFile(path.join(ROOT, 'dicts/catalog.json'), 'utf8')); } catch { /* optional */ }
  for (const [rel, meta] of Object.entries(catalog.items ?? {})) {
    const full = path.join(ROOT, 'dicts', rel);
    let info;
    try { info = await fileMeta(full); } catch { continue; }
    entries.set(`dicts/${rel}`, {
      path: `dicts/${rel}`,
      source: 'tools/dicts',
      note: String(meta.note ?? '').trim(),
      tags: Array.isArray(meta.tags) ? meta.tags.map(String) : [],
      bytes: info.bytes,
      lines: info.lines,
      sha256: info.sha256,
    });
  }
  const roots = [
    { dir: path.join(ROOT, 'dicts'), prefix: 'dicts', source: 'dicts' },
  ];
  for (const root of roots) {
    for (const file of await walk(root.dir)) {
      const key = `${root.prefix}/${file.rel}`;
      if (entries.has(key)) continue;
      const info = await fileMeta(file.full);
      entries.set(key, {
        path: key,
        source: root.source,
        note: '',
        tags: inferDictTags(file.rel),
        bytes: info.bytes,
        lines: info.lines,
        sha256: info.sha256,
      });
    }
  }
  return [...entries.values()].sort((a, b) => a.path.localeCompare(b.path));
}

async function buildWordlists() {
  const root = path.join(ROOT, 'wordlists');
  const out = [];
  for (const file of await walk(root)) {
    const info = await fileMeta(file.full);
    out.push({
      path: `wordlists/${file.rel}`,
      bytes: info.bytes,
      lines: info.lines,
      sha256: info.sha256,
      note: file.rel === 'common.txt' ? 'Small directory wordlist: use first.'
        : file.rel === 'directory-list-2.3-small.txt' ? 'Medium directory wordlist: use after common.'
          : file.rel === 'dnsmap.txt' ? 'Subdomain wordlist: the only bundled DNS list.' : '',
    });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

async function buildResources() {
  const out = [];
  for (const dir of ['Vuln', 'Doc', 'Payload']) {
    const root = path.join(ROOT, 'skills', dir);
    for (const file of await walk(root)) {
      const info = await fileMeta(file.full);
      out.push({ path: `skills/${dir}/${file.rel}`, bytes: info.bytes, sha256: info.sha256 });
    }
  }
  return out;
}

async function buildTools() {
  const binDir = path.join(SOURCE_ROOT, 'tools/bin');
  let names = [];
  try { names = (await fs.readdir(binDir)).sort(); } catch { /* unavailable */ }
  const tools = [];
  for (const name of names) {
    let status = 'unknown';
    let target = '';
    try {
      const full = path.join(binDir, name);
      const stat = await fs.lstat(full);
      if (stat.isSymbolicLink()) {
        const link = await fs.readlink(full);
        target = link;
        try { await fs.stat(full); status = 'candidate'; } catch { status = 'broken'; }
      } else if (stat.isFile()) {
        status = (stat.mode & 0o111) === 0 ? 'not-executable' : 'candidate';
      }
    } catch { status = 'missing'; }
    tools.push({
      name,
      binary: `tools/bin/${name}`,
      category: TOOL_CATEGORIES[name] ?? 'other',
      description: TOOL_DESCRIPTIONS[name] ?? '',
      versionArgs: TOOL_VERSION_ARGS[name] ?? ['--version'],
      proxyAware: ['curl', 'httpx', 'ffuf', 'nuclei', 'katana', 'gobuster', 'sqlmap', 'nmap', 'hydra', 'httpx'].includes(name),
      status,
      sourceTarget: target || undefined,
    });
  }
  const extra = [
    { name: 'JSFinder', binary: 'scripts/JSFinder/JSFinder.py', category: 'web', description: TOOL_DESCRIPTIONS.JSFinder, versionArgs: ['-h'], status: 'vendored' },
    { name: 'bypass-403', binary: 'scripts/bypass-403/bypass-403.sh', category: 'web', description: TOOL_DESCRIPTIONS['bypass-403'], versionArgs: [], status: 'vendored' },
    { name: 'endpoint_vocab', binary: 'scripts/endpoint_vocab.py', category: 'recon', description: 'Synthesize endpoint candidates from text using words the target already emitted.', versionArgs: ['-h'], status: 'vendored' },
  ];
  return [...tools, ...extra].sort((a, b) => a.name.localeCompare(b.name));
}

const skills = [];
const dicts = await buildDicts();
const wordlists = await buildWordlists();
const resources = [];
const tools = [];
const categories = {};
for (const skill of skills) categories[skill.category] = (categories[skill.category] ?? 0) + 1;
const index = {
  version: 1,
  generatedAt: new Date().toISOString(),
  source: {
    name: 'StrikeAgent_AtkBrain-Ultra',
    root: SOURCE_ROOT,
    commit: process.env.ATKBRAIN_AU_COMMIT || 'a57cdb7',
    license: 'AGPL-3.0-only',
  },
  counts: {
    skills: skills.length,
    resources: resources.length,
    dicts: dicts.length,
    wordlists: wordlists.length,
    tools: tools.length,
    categories,
  },
  skills,
  resources,
  dicts,
  wordlists,
  scripts: [],
  tools,
};
await fs.writeFile(path.join(ROOT, 'index.json'), `${JSON.stringify(index, null, 2)}\n`, 'utf8');
await fs.writeFile(path.join(ROOT, 'tools.manifest.json'), `${JSON.stringify({ version: 1, source: index.source, tools }, null, 2)}\n`, 'utf8');
console.log(JSON.stringify({ counts: index.counts, tools: tools.length }, null, 2));
