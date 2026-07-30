// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import pty from 'node-pty';
import { resolveBinaryAndCommonArgs } from './helper.js';
import { mxcErrorFromCode } from './errors.js';
import { diagLog } from './diagnostic.js';
import { backendForSandboxId, buildStateAwareEnvelope, nonExecCall, spawnAndCollect, tryParseErrorEnvelope, } from './state-aware-helper.js';
/**
 * Provisions a state-aware sandbox of the requested backend. Returns a
 * branded sandbox id and any provision-time metadata the backend produces.
 */
export async function provisionSandbox(containment, config, options = {}) {
    const envelope = buildStateAwareEnvelope({
        phase: 'provision',
        backendKey: containment,
        containment,
        config: config,
    });
    const result = await nonExecCall(envelope, options);
    return {
        sandboxId: result.sandboxId,
        metadata: result.metadata,
    };
}
/**
 * Starts a previously provisioned sandbox. The backend is inferred from
 * the `sandboxId` prefix.
 */
export async function startSandbox(sandboxId, config, options = {}) {
    const backendKey = backendForSandboxId(sandboxId);
    const envelope = buildStateAwareEnvelope({
        phase: 'start',
        backendKey,
        sandboxId,
        config: config,
    });
    return nonExecCall(envelope, options);
}
/**
 * Streams a script execution inside a started sandbox. Returns an
 * `IPty` for live stdout/stderr/exit handling, mirroring `spawnSandbox`.
 * On dispatch failure the executor emits a single error envelope on stdout;
 * the SDK does not parse it here — callers consuming `IPty.onData` see the
 * raw bytes. Use `execInSandboxAsync` when typed-error throwing is needed.
 */
export function execInSandbox(sandboxId, config, options = {}) {
    const backendKey = backendForSandboxId(sandboxId);
    const envelope = buildStateAwareEnvelope({
        phase: 'exec',
        backendKey,
        sandboxId,
        config: config,
    });
    const { executablePath, args } = resolveBinaryAndCommonArgs(JSON.stringify(envelope), options);
    diagLog(`state-aware: spawning exec via PTY`);
    const ptyProcess = pty.spawn(executablePath, args, {
        name: 'xterm-color',
        cols: 120,
        rows: 80,
        cwd: process.cwd(),
        ...options.ptyOptions,
    });
    const signal = options.signal;
    if (signal) {
        if (signal.aborted) {
            ptyProcess.kill();
        }
        else {
            const onAbort = () => ptyProcess.kill();
            signal.addEventListener('abort', onAbort, { once: true });
            ptyProcess.onExit(() => signal.removeEventListener('abort', onAbort));
        }
    }
    return ptyProcess;
}
/**
 * Buffered exec convenience. Resolves with `{stdout, stderr, exitCode}`
 * on script completion. Throws an `MxcError` (with the wire-format `code`
 * field set) when the executor reports a dispatch failure (recognised by
 * exit != 0 and stdout being a complete `{error}` envelope).
 */
export async function execInSandboxAsync(sandboxId, config, options = {}) {
    const backendKey = backendForSandboxId(sandboxId);
    const envelope = buildStateAwareEnvelope({
        phase: 'exec',
        backendKey,
        sandboxId,
        config: config,
    });
    const { stdout, stderr, exitCode } = await spawnAndCollect(envelope, options);
    if (exitCode !== 0) {
        const errorEnvelope = tryParseErrorEnvelope(stdout);
        if (errorEnvelope) {
            const e = errorEnvelope.error;
            throw mxcErrorFromCode(e.code, e.message, e.details);
        }
    }
    return { stdout, stderr, exitCode };
}
/**
 * Stops a started sandbox without releasing its provision-side resources.
 * The same sandbox can be started again via `startSandbox`.
 */
export async function stopSandbox(sandboxId, config, options = {}) {
    const backendKey = backendForSandboxId(sandboxId);
    const envelope = buildStateAwareEnvelope({
        phase: 'stop',
        backendKey,
        sandboxId,
        config: config,
    });
    return nonExecCall(envelope, options);
}
/**
 * Releases all backend resources associated with a provisioned sandbox.
 * The id becomes invalid after this call returns successfully.
 */
export async function deprovisionSandbox(sandboxId, config, options = {}) {
    const backendKey = backendForSandboxId(sandboxId);
    const envelope = buildStateAwareEnvelope({
        phase: 'deprovision',
        backendKey,
        sandboxId,
        config: config,
    });
    return nonExecCall(envelope, options);
}
//# sourceMappingURL=state-aware.js.map