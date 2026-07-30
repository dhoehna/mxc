import pty from 'node-pty';
import { SandboxSpawnOptions } from './sandbox.js';
import { DeprovisionConfigFor, DeprovisionResult, ExecConfigFor, ExecResult, ProvisionConfigFor, ProvisionResult, SandboxId, StartConfigFor, StartResult, StateAwareContainmentBackend, StopConfigFor, StopResult } from './state-aware-types.js';
/**
 * Provisions a state-aware sandbox of the requested backend. Returns a
 * branded sandbox id and any provision-time metadata the backend produces.
 */
export declare function provisionSandbox<C extends StateAwareContainmentBackend>(containment: C, config?: ProvisionConfigFor<C>, options?: SandboxSpawnOptions): Promise<ProvisionResult<C>>;
/**
 * Starts a previously provisioned sandbox. The backend is inferred from
 * the `sandboxId` prefix.
 */
export declare function startSandbox<C extends StateAwareContainmentBackend>(sandboxId: SandboxId<C>, config?: StartConfigFor<C>, options?: SandboxSpawnOptions): Promise<StartResult<C>>;
/**
 * Streams a script execution inside a started sandbox. Returns an
 * `IPty` for live stdout/stderr/exit handling, mirroring `spawnSandbox`.
 * On dispatch failure the executor emits a single error envelope on stdout;
 * the SDK does not parse it here — callers consuming `IPty.onData` see the
 * raw bytes. Use `execInSandboxAsync` when typed-error throwing is needed.
 */
export declare function execInSandbox<C extends StateAwareContainmentBackend>(sandboxId: SandboxId<C>, config: ExecConfigFor<C>, options?: SandboxSpawnOptions): pty.IPty;
/**
 * Buffered exec convenience. Resolves with `{stdout, stderr, exitCode}`
 * on script completion. Throws an `MxcError` (with the wire-format `code`
 * field set) when the executor reports a dispatch failure (recognised by
 * exit != 0 and stdout being a complete `{error}` envelope).
 */
export declare function execInSandboxAsync<C extends StateAwareContainmentBackend>(sandboxId: SandboxId<C>, config: ExecConfigFor<C>, options?: SandboxSpawnOptions): Promise<ExecResult>;
/**
 * Stops a started sandbox without releasing its provision-side resources.
 * The same sandbox can be started again via `startSandbox`.
 */
export declare function stopSandbox<C extends StateAwareContainmentBackend>(sandboxId: SandboxId<C>, config?: StopConfigFor<C>, options?: SandboxSpawnOptions): Promise<StopResult<C>>;
/**
 * Releases all backend resources associated with a provisioned sandbox.
 * The id becomes invalid after this call returns successfully.
 */
export declare function deprovisionSandbox<C extends StateAwareContainmentBackend>(sandboxId: SandboxId<C>, config?: DeprovisionConfigFor<C>, options?: SandboxSpawnOptions): Promise<DeprovisionResult<C>>;
//# sourceMappingURL=state-aware.d.ts.map