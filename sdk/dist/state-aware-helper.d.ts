import { SandboxSpawnOptions } from './sandbox.js';
import { Phase, StateAwareContainmentBackend } from './state-aware-types.js';
export declare const STATE_AWARE_VERSION = "0.6.0-alpha";
export declare const CROSS_CUTTING_FIELDS: readonly ["containerId", "filesystem", "network", "ui", "process"];
export declare const ISOLATION_SESSION_ID_PREFIX = "iso";
export declare const LXC_ID_PREFIX = "lxc";
export declare const PREFIX_TO_BACKEND: Record<string, StateAwareContainmentBackend>;
/**
 * Resolves the wire-format backend key for a sandbox id by reading its
 * leading prefix segment. Throws an `MxcError` with `code: 'malformed_id'`
 * when the id has no recognised prefix.
 */
export declare function backendForSandboxId(sandboxId: string): StateAwareContainmentBackend;
export interface BuildEnvelopeArgs {
    phase: Phase;
    backendKey: StateAwareContainmentBackend;
    containment?: StateAwareContainmentBackend;
    sandboxId?: string;
    config?: Record<string, unknown>;
}
/**
 * Constructs the wire-format JSON-shaped envelope for a state-aware request
 * from a per-(backend, phase) Config. Lifts cross-cutting fields
 * (filesystem, network, ui, process) to envelope top-level; nests any
 * remaining backend-specific fields under `experimental.<backend>.<phase>`.
 */
export declare function buildStateAwareEnvelope(args: BuildEnvelopeArgs): Record<string, unknown>;
export interface WireErrorEnvelope {
    error: {
        code: string;
        message: string;
        details?: Record<string, unknown>;
    };
}
export interface WireResultEnvelope<T> {
    result: T;
}
/**
 * Parses the single-envelope JSON stdout produced by non-exec state-aware
 * phases. Throws the corresponding `MxcError` on `{error}`, returns the
 * unwrapped `result` on `{result}`.
 */
export declare function parseNonExecResponse<T>(stdout: string): T;
/**
 * Attempts to parse stdout as an `{error}` envelope. Returns the parsed
 * envelope when stdout is exactly that, or `null` otherwise (script output
 * mistaken for an envelope is suppressed). Used by exec to discriminate
 * dispatch failure from script failure.
 */
export declare function tryParseErrorEnvelope(stdout: string): WireErrorEnvelope | null;
export type SpawnImpl = (cmd: string, args: string[], opts: unknown) => unknown;
/**
 * Test-only hook: replace the `child_process.spawn` implementation used by
 * non-exec state-aware calls and the buffered `execInSandboxAsync`. Not
 * exported from `index.ts` — production code uses the real `spawn`.
 */
export declare function _setSpawnImpl(fn: SpawnImpl): void;
/** Test-only hook: restore the default `child_process.spawn`. */
export declare function _resetSpawnImpl(): void;
export interface CollectedOutput {
    stdout: string;
    stderr: string;
    exitCode: number;
}
/**
 * Spawns the executor with the given envelope, captures stdout/stderr,
 * and resolves on close. Honors `options.signal` for cancellation.
 */
export declare function spawnAndCollect(envelope: Record<string, unknown>, options: SandboxSpawnOptions): Promise<CollectedOutput>;
export declare function nonExecCall<T>(envelope: Record<string, unknown>, options: SandboxSpawnOptions): Promise<T>;
//# sourceMappingURL=state-aware-helper.d.ts.map