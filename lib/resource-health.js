/**
 * Resource inventory/health for the Settings page.
 *
 * Dictionaries are the remaining vendored resource. Skills and external
 * pentest tools are not shipped.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { arsenalAssetRoot, loadArsenalIndex } from './arsenal.js';
import { publicSettings, surveyStatus } from './settings.js';

const EXPECTED = Object.freeze({
  skills: 0,
  dicts: 397,
  wordlists: 3,
  tools: 0,
});

async function exists(relative) {
  try { await fs.access(path.join(arsenalAssetRoot(), relative)); return true; } catch { return false; }
}

async function inventory() {
  const index = await loadArsenalIndex();
  const missingSkills = [];
  const missingDicts = [];
  const missingWordlists = [];
  for (const skill of index.skills) if (!(await exists(skill.path))) missingSkills.push(skill.name);
  for (const dict of index.dicts) if (!(await exists(dict.path))) missingDicts.push(dict.path);
  for (const wordlist of index.wordlists) if (!(await exists(wordlist.path))) missingWordlists.push(wordlist.path);
  return { index, missingSkills, missingDicts, missingWordlists };
}

function statusFor(ok, warn = false) {
  return ok ? 'ok' : (warn ? 'warn' : 'error');
}

/**
 * @param {{checkTools?:boolean, settings?:object}} options
 */
export async function checkResourceHealth({ checkTools = false, settings } = {}) {
  const { index, missingSkills, missingDicts, missingWordlists } = await inventory();
  const skillsOk = index.skills.length === EXPECTED.skills && missingSkills.length === 0;
  const dictsOk = index.dicts.length === EXPECTED.dicts && missingDicts.length === 0;
  const wordlistsOk = index.wordlists.length === EXPECTED.wordlists && missingWordlists.length === 0;
  void checkTools;

  const survey = surveyStatus(settings ?? {});
  return {
    checkedAt: new Date().toISOString(),
    resources: {
      skills: {
        status: statusFor(skillsOk),
        total: index.skills.length,
        expected: EXPECTED.skills,
        missing: missingSkills.slice(0, 20),
        missingCount: missingSkills.length,
        categories: index.counts?.categories ?? {},
      },
      tools: {
        status: 'ok',
        total: 0,
        expected: EXPECTED.tools,
        available: 0,
        usable: 0,
        checkMode: 'removed',
        failed: [],
        rows: [],
      },
      dictionaries: {
        status: statusFor(dictsOk && wordlistsOk),
        total: index.dicts.length,
        expected: EXPECTED.dicts,
        missing: missingDicts.slice(0, 20),
        missingCount: missingDicts.length,
        wordlists: index.wordlists.length,
        wordlistsExpected: EXPECTED.wordlists,
        missingWordlists: missingWordlists.slice(0, 20),
      },
    },
    survey,
  };
}

export { EXPECTED as EXPECTED_RESOURCES, publicSettings };
