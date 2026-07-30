// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { spawn } from 'child_process';
import { resolveBinaryAndCommonArgs } from './helper.js';
import { mxcErrorFromCode } from './errors.js';
import { diagLog } from './diagnostic.js';
export const STATE_AWARE_VERSION = '0.6.0-alpha';
// Wire-format cross-cutting fields that live at the envelope's top level.
// Anything else on a per-(backend, phase) Config is backend-specific and is
// nested under `experimental.<backend>.<phase>`.
export const CROSS_CUTTING_FIELDS = ['containerId', 'filesystem', 'network', 'ui', 'process'];
// Per-backend wire-format prefix. Each value mirrors the corresponding
// Rust `<Backend>Runner::ID_PREFIX` const and is the leading segment of a
// `sandboxId` produced by that backend. Each future state-aware backend
// declares its own `<BACKEND>_ID_PREFIX` const here.
export const ISOLATION_SESSION_ID_PREFIX = 'iso';
export const LXC_ID_PREFIX = 'lxc';
// Mapping from a sandboxId's leading prefix segment to the wire-format
// backend key. Extended as more state-aware backends opt in.
export const PREFIX_TO_BACKEND = {
    [ISOLATION_SESSION_ID_PREFIX]: 'isolation_session',
    [LXC_ID_PREFIX]: 'lxc',
};
/**
 * Resolves the wire-format backend key for a sandbox id by reading its
 * leading prefix segment. Throws an `MxcError` with `code: 'malformed_id'`
 * when the id has no recognised prefix.
 */
export function backendForSandboxId(sandboxId) {
    const colon = sandboxId.indexOf(':');
    if (colon < 0) {
        throw mxcErrorFromCode('malformed_id', `sandboxId must carry a backend prefix: ${sandboxId}`);
    }
    const prefix = sandboxId.slice(0, colon);
    const backend = PREFIX_TO_BACKEND[prefix];
    if (!backend) {
        throw mxcErrorFromCode('malformed_id', `sandboxId prefix '${prefix}' does not match a known state-aware backend`);
    }
    return backend;
}
/**
 * Constructs the wire-format JSON-shaped envelope for a state-aware request
 * from a per-(backend, phase) Config. Lifts cross-cutting fields
 * (filesystem, network, ui, process) to envelope top-level; nests any
 * remaining backend-specific fields under `experimental.<backend>.<phase>`.
 */
export function buildStateAwareEnvelope(args) {
    const { phase, backendKey, containment, sandboxId, config } = args;
    // Copy of config; fields are removed as they are lifted into the envelope.
    // Anything left becomes experimental.<backend>.<phase>.
    const backendSpecific = { ...(config ?? {}) };
    const version = (typeof backendSpecific.version === 'string' && backendSpecific.version) || STATE_AWARE_VERSION;
    delete backendSpecific.version;
    const envelope = { version, phase };
    if (containment) {
        envelope.containment = containment;
    }
    if (sandboxId) {
        envelope.sandboxId = sandboxId;
    }
    for (const field of CROSS_CUTTING_FIELDS) {
        if (backendSpecific[field] !== undefined) {
            envelope[field] = backendSpecific[field];
            delete backendSpecific[field];
        }
    }
    if (Object.keys(backendSpecific).length > 0) {
        envelope.experimental = { [backendKey]: { [phase]: backendSpecific } };
    }
    return envelope;
}
/**
 * Parses the single-envelope JSON stdout produced by non-exec state-aware
 * phases. Throws the corresponding `MxcError` on `{error}`, returns the
 * unwrapped `result` on `{result}`.
 */
export function parseNonExecResponse(stdout) {
    let parsed;
    try {
        parsed = JSON.parse(stdout.trim());
    }
    catch (e) {
        throw new Error(`Failed to parse state-aware response envelope: ${e.message}`);
    }
    if (parsed && typeof parsed === 'object') {
        if ('error' in parsed) {
            const env = parsed.error;
            throw mxcErrorFromCode(env.code, env.message, env.details);
        }
        if ('result' in parsed) {
            return parsed.result;
        }
    }
    throw new Error(`Unexpected state-aware response envelope shape: ${stdout}`);
}
/**
 * Attempts to parse stdout as an `{error}` envelope. Returns the parsed
 * envelope when stdout is exactly that, or `null` otherwise (script output
 * mistaken for an envelope is suppressed). Used by exec to discriminate
 * dispatch failure from script failure.
 */
export function tryParseErrorEnvelope(stdout) {
    try {
        const parsed = JSON.parse(stdout.trim());
        if (parsed && typeof parsed === 'object' && 'error' in parsed &&
            parsed.error?.code) {
            return parsed;
        }
    }
    catch {
        // Not JSON. Definitely script output.
    }
    return null;
}
let spawnImpl = spawn;
/**
 * Test-only hook: replace the `child_process.spawn` implementation used by
 * non-exec state-aware calls and the buffered `execInSandboxAsync`. Not
 * exported from `index.ts` — production code uses the real `spawn`.
 */
export function _setSpawnImpl(fn) {
    spawnImpl = fn;
}
/** Test-only hook: restore the default `child_process.spawn`. */
export function _resetSpawnImpl() {
    spawnImpl = spawn;
}
/**
 * Spawns the executor with the given envelope, captures stdout/stderr,
 * and resolves on close. Honors `options.signal` for cancellation.
 */
export function spawnAndCollect(envelope, options) {
    return new Promise((resolve, reject) => {
        const signal = options.signal;
        if (signal?.aborted) {
            reject(signal.reason ?? new Error('Aborted'));
            return;
        }
        let executablePath;
        let args;
        try {
            ({ executablePath, args } = resolveBinaryAndCommonArgs(JSON.stringify(envelope), options));
        }
        catch (err) {
            reject(err);
            return;
        }
        diagLog(`state-aware: spawning phase=${envelope.phase}`);
        const child = spawnImpl(executablePath, args, {
            stdio: ['pipe', 'pipe', 'pipe'],
        });
        let stdoutData = '';
        let stderrData = '';
        child.stdout?.on('data', (d) => {
            stdoutData += typeof d === 'string' ? d : d.toString('utf-8');
        });
        child.stderr?.on('data', (d) => {
            stderrData += typeof d === 'string' ? d : d.toString('utf-8');
        });
        const onAbort = () => {
            child.kill();
        };
        if (signal) {
            signal.addEventListener('abort', onAbort, { once: true });
        }
        child.on('close', (...a) => {
            const code = a[0];
            if (signal) {
                signal.removeEventListener('abort', onAbort);
            }
            if (signal?.aborted) {
                reject(signal.reason ?? new Error('Aborted'));
                return;
            }
            resolve({ stdout: stdoutData, stderr: stderrData, exitCode: code ?? -1 });
        });
        child.on('error', (...a) => {
            reject(a[0]);
        });
    });
}
export async function nonExecCall(envelope, options) {
    const { stdout } = await spawnAndCollect(envelope, options);
    return parseNonExecResponse(stdout);
}
