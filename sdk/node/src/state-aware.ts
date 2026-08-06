// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import pty from 'node-pty';
import { resolveBinaryAndCommonArgs } from './helper.js';
import { SandboxSpawnOptions } from './sandbox.js';
import { mxcErrorFromCode } from './errors.js';
import { diagLog } from './diagnostic.js';
import {
  DeprovisionConfigFor,
  DeprovisionResult,
  ExecConfigFor,
  ExecResult,
  ProvisionConfigFor,
  ProvisionMetadataFor,
  ProvisionResult,
  SandboxId,
  StartConfigFor,
  StartResult,
  StateAwareContainmentBackend,
  StopConfigFor,
  StopResult,
} from './state-aware-types.js';
import {
  backendForSandboxId,
  buildStateAwareEnvelope,
  nonExecCall,
  spawnAndCollect,
  tryParseErrorEnvelope,
  tryParseErrorEnvelopeFromLines,
} from './state-aware-helper.js';

/**
 * Provisions a state-aware sandbox of the requested backend. Returns a
 * branded sandbox id and any provision-time metadata the backend produces.
 */
export async function provisionSandbox<C extends StateAwareContainmentBackend>(
  containment: C,
  config?: ProvisionConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<ProvisionResult<C>> {
  const envelope = buildStateAwareEnvelope({
    phase: 'provision',
    backendKey: containment,
    containment,
    config: config as Record<string, unknown> | undefined,
  });
  const result = await nonExecCall<{
    sandboxId: string;
    metadata?: ProvisionMetadataFor<C>;
    correlationVector?: string;
  }>(envelope, options);
  return {
    sandboxId: result.sandboxId as SandboxId<C>,
    metadata: result.metadata,
    correlationVector: result.correlationVector,
  };
}

/**
 * Starts a previously provisioned sandbox. The backend is inferred from
 * the `sandboxId` prefix.
 */
export async function startSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config?: StartConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<StartResult<C>> {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'start',
    backendKey,
    sandboxId,
    correlationVector: options.correlationVector,
    config: config as Record<string, unknown> | undefined,
  });
  return nonExecCall<StartResult<C>>(envelope, options);
}

/**
 * Streams a script execution inside a started sandbox. Returns an
 * `IPty` for live stdout/stderr/exit handling, mirroring `spawnSandbox`.
 * On dispatch failure the executor emits a single error envelope on stderr,
 * because stdout is carrying the container's raw output; the SDK does not
 * parse it here — callers consuming `IPty.onData` see the raw bytes. Use
 * `execInSandboxAsync` when typed-error throwing is needed.
 */
export function execInSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options: SandboxSpawnOptions = {},
): pty.IPty {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'exec',
    backendKey,
    sandboxId,
    correlationVector: options.correlationVector,
    config: config as unknown as Record<string, unknown>,
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
    } else {
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
 * field set) when the executor reports a dispatch failure, recognised by
 * exit != 0 together with a complete `{error}` envelope on either stdout
 * (non-streaming) or stderr (streaming, where stdout holds script output).
 */
export async function execInSandboxAsync<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config: ExecConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<ExecResult> {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'exec',
    backendKey,
    sandboxId,
    correlationVector: options.correlationVector,
    config: config as unknown as Record<string, unknown>,
  });
  const { stdout, stderr, exitCode } = await spawnAndCollect(envelope, options);

  if (exitCode !== 0) {
    // A dispatch failure can land on either channel. A non-streaming exec (dry
    // run) keeps stdout as its single client-facing channel; a streaming one has
    // already written the container's raw output there, so its envelope goes to
    // stderr instead.
    //
    // The stderr fallback is additionally gated on stdout being empty. A
    // dispatch failure happens before the script runs, so it never produces
    // stdout; requiring that keeps a script that both wrote output and ended its
    // stderr with something envelope-shaped from being reported as a sandbox
    // that never started.
    const errorEnvelope =
      tryParseErrorEnvelope(stdout) ??
      (stdout === '' ? tryParseErrorEnvelopeFromLines(stderr) : null);
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
export async function stopSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config?: StopConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<StopResult<C>> {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'stop',
    backendKey,
    sandboxId,
    correlationVector: options.correlationVector,
    config: config as Record<string, unknown> | undefined,
  });
  return nonExecCall<StopResult<C>>(envelope, options);
}

/**
 * Releases all backend resources associated with a provisioned sandbox.
 * The id becomes invalid after this call returns successfully.
 */
export async function deprovisionSandbox<C extends StateAwareContainmentBackend>(
  sandboxId: SandboxId<C>,
  config?: DeprovisionConfigFor<C>,
  options: SandboxSpawnOptions = {},
): Promise<DeprovisionResult<C>> {
  const backendKey = backendForSandboxId(sandboxId) as C;
  const envelope = buildStateAwareEnvelope({
    phase: 'deprovision',
    backendKey,
    sandboxId,
    correlationVector: options.correlationVector,
    config: config as Record<string, unknown> | undefined,
  });
  return nonExecCall<DeprovisionResult<C>>(envelope, options);
}
