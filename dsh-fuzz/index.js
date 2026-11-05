import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Stable loader identity. */
export const name = 'dsh-fuzz';
/** Services used by this plugin. */
export const inject = ['tools'];

const PLUGIN_ROOT = dirname(fileURLToPath(import.meta.url));

const DEFAULTS = {
  workspaceDir: process.env.DSH_FUZZ_WORKSPACE || process.cwd(),
  pythonPath: process.platform === 'win32' ? 'python' : 'python3',
  enginePath: join(PLUGIN_ROOT, 'engine', 'fuzz', 'fuzz_ops.py'),
  evidenceRoot: '漏洞记录',
  timeoutMs: 300000,
};

const ACTIONS = ['harvest', 'plan', 'run', 'verdict', 'bizmap', 'doctor'];
const KINDS = [
  'idor', 'chain', 'massassign', 'role', 'tenant', 'amount', 'param', 'bypass',
  'sqli', 'xss', 'ssrf', 'lfi', 'ssti', 'cmdi', 'xxe',
];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: {
      type: 'string',
      enum: ACTIONS,
      description:
        'harvest: extract typed values/field names from a captured response; ' +
        'plan: build diffprobe plan(s) for idor/chain/massassign/role/tenant/amount/param and the classic payload classes; ' +
        'run: execute plan(s) through diffprobe within its rate limits and stop-on-block; ' +
        'verdict: classify diffs.csv/state.csv; doctor: check engine and payload sets; bizmap: read/write target map.',
    },
    kind: {
      type: 'string',
      enum: KINDS,
    },
    target: { type: 'string', description: 'Target name; evidence is written under <workspace>/<evidenceRoot>/<target>/evidence/fuzz.' },
    request: { type: 'string', description: 'Raw HTTP request text, or @path relative to the workspace.' },
    response: { type: 'string', description: 'Captured response text, or @path. Used by harvest.' },
    seeds: { type: 'string', description: '@seeds.json from harvest.' },
    params: { type: 'array', items: { type: 'string' }, description: 'Candidate parameter names.' },
    verify: { type: 'object', description: 'State check: {request, paths:[], delayMs}, supplied on the plan action.' },
    planPath: { type: 'string', description: 'Plan file or directory for run.' },
    planDir: { type: 'string', description: 'Plan directory for run; executes up to 10 plans.' },
    runPath: { type: 'string', description: 'Run directory for verdict.' },
    data: { type: 'object', description: 'JSON object for bizmap write.' },
    limit: { type: 'integer', minimum: 1, maximum: 20, description: 'Max plans/candidates. Default 6.' },
    concurrency: { type: 'integer', minimum: 1, maximum: 16, description: 'Race concurrency. Default 8.' },
    allowWrite: { type: 'boolean', description: 'Allow POST/PUT/PATCH/DELETE plans. Default false.' },
    allowRace: { type: 'boolean', description: 'Allow race plans. Default false.' },
    dryRun: { type: 'boolean', description: 'Validate plans without sending packets.' },
  },
};

const OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: true,
    required: ['ok', 'action', 'summary'],
    properties: {
      ok: { type: 'boolean' },
      action: { type: 'string' },
      summary: { type: 'string' },
      data: { type: 'object' },
    },
  },
  render(_args, value) {
    const text = JSON.stringify(value, null, 2);
    return [{ type: 'text', text: text.length > 12000 ? text.slice(0, 12000) + '\n…[truncated]' : text }];
  },
};

/** Run the engine and collect stdout/stderr, honouring the exec abort signal. */
function runCli(script, args, settings, signal, timeoutMs) {
  return new Promise((resolvePromise, reject) => {
    let child;
    try {
      child = spawn(settings.pythonPath, [script, ...args], {
        cwd: settings.workspaceDir,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          PYTHONIOENCODING: 'utf-8',
          DSH_FUZZ_WORKSPACE: settings.workspaceDir,
          DSH_FUZZ_EVIDENCE_DIR: settings.evidenceRoot,
          DSH_FUZZ_STATE: join(settings.workspaceDir, '.dsh-fuzz'),
        },
      });
    } catch (error) {
      reject(error);
      return;
    }
    let stdout = '';
    let stderr = '';
    let settled = false;
    const kill = () => { try { child.kill(); } catch { /* already gone */ } };
    const timer = setTimeout(kill, timeoutMs);
    const onAbort = () => kill();
    signal?.addEventListener('abort', onAbort, { once: true });
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      fn(value);
    };
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => finish(reject, error));
    child.on('close', (code) => finish(resolvePromise, { code: code ?? -1, stdout, stderr }));
  });
}

/** Parse the engine's JSON report, tolerating a trailing human line. */
function parseJson(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) return null;
  try { return JSON.parse(trimmed); } catch { /* fall through */ }
  const start = trimmed.indexOf('{');
  const end = trimmed.lastIndexOf('}');
  if (start >= 0 && end > start) {
    try { return JSON.parse(trimmed.slice(start, end + 1)); } catch { /* ignore */ }
  }
  return null;
}

async function runFuzz(args, settings, signal) {
  const target = isAbsolute(settings.enginePath) || /^[A-Za-z]:[\\/]/.test(settings.enginePath)
    ? settings.enginePath
    : join(settings.workspaceDir, settings.enginePath);
  if (!existsSync(target)) throw new Error(`fuzz engine not found: ${target}`);
  if (!existsSync(settings.workspaceDir)) {
    throw new Error(`fuzz workspace not found: ${settings.workspaceDir} (set workspaceDir in the dsh-fuzz plugin config)`);
  }

  const specPath = join(mkdtempSync(join(tmpdir(), 'dsh-fuzz-')), 'spec.json');
  const spec = {
    action: args.action,
    target: args.target,
    kind: args.kind,
    request: args.request,
    response: args.response,
    seeds: args.seeds,
    params: args.params,
    verify: args.verify,
    planPath: args.planPath,
    planDir: args.planDir,
    runPath: args.runPath,
    data: args.data,
    limit: args.limit,
    concurrency: args.concurrency,
    allowWrite: args.allowWrite === true,
    allowRace: args.allowRace === true,
    dryRun: args.dryRun === true,
  };
  writeFileSync(specPath, JSON.stringify(spec), 'utf8');
  try {
    const res = await runCli(target, ['--spec', specPath], settings, signal, settings.timeoutMs);
    const data = parseJson(res.stdout);
    if (!data) {
      return {
        ok: false,
        action: args.action,
        summary: `fuzz ${args.action} failed (exit ${res.code})`,
        data: { stdout: res.stdout.slice(-4000), stderr: res.stderr.slice(-4000) },
      };
    }
    const normalized = { ...data, action: args.action };
    if (!normalized.data) normalized.data = {};
    if (args.action === 'doctor') {
      normalized.summary = normalized.ok ? 'fuzz doctor ok' : 'fuzz doctor failed';
      normalized.data = { checks: data.checks ?? [] };
    } else if (args.action === 'run') {
      const runs = normalized.data.runs ?? [];
      const rows = runs.reduce((n, r) => n + (r.requests || 0), 0);
      const skipped = runs.filter((r) => r.skipped).length;
      normalized.summary = `run ${runs.length} plan(s), ${rows} rows, ${skipped} skipped`;
    }
    if (!normalized.summary) {
      normalized.summary = args.action === 'bizmap' ? 'fuzz bizmap' : `fuzz ${args.action}`;
    }
    return normalized;
  } finally {
    try { rmSync(dirname(specPath), { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

export function apply(ctx, config = {}) {
  const settings = { ...DEFAULTS, ...(config || {}) };

  ctx.tools.register({
    name: 'fuzz',
    description:
      'Differential fuzzing and logic-test planner over the bundled diffprobe engine. ' +
      'harvest extracts typed values/field names from captured responses; plan builds idor/chain/massassign/role/tenant/amount/param/bypass and classic payload-class plans ' +
      'with baseline, same-type control and optional state verification; run executes plans within diffprobe rate limits and stop-on-block; ' +
      'verdict classifies diffs.csv/state.csv. Read-only by default: allowWrite for write methods, allowRace for concurrency. ' +
      'One call = one plan or one batch; raw evidence stays on disk. A response difference is not a vulnerability until the state or authorization change is confirmed.',
    parameters: PARAMETERS,
    output: OUTPUT,
    timeoutMs: Number(settings.timeoutMs) + 5000,
    async execute(args, exec) {
      return runFuzz(args, settings, exec?.signal);
    },
  });
}