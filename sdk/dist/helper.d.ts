import { FileLogger } from './logger.js';
import { ContainerConfig } from './types.js';
import { SandboxSpawnOptions } from './sandbox.js';
/** SDK version read from package.json at module load time. */
export declare const SDK_VERSION: string;
/** Log the SDK version to the diagnostic console (once per process). */
export declare function diagLogVersion(): void;
/**
 * Emit a one-shot deprecation hint via the diagnostic console when a caller
 * uses a legacy containment wire value. Dedup'd per legacy value per process
 * so the message doesn't flood the diag stream on repeated spawns.
 *
 * Exposed for tests so the latch can be reset between describes.
 */
export declare function warnLegacyContainmentOnce(legacy: string, canonical: string): void;
/** @internal Reset the legacy-containment dedup latch. Intended for unit tests. */
export declare function _resetLegacyContainmentWarnedForTesting(): void;
/**
 * Result of preparing a sandbox spawn — includes the resolved binary,
 * CLI arguments, and optional diagnostic logger.
 */
export interface PrepareSpawnResult {
    /** Absolute path to the wxc-exec or lxc-exec binary. */
    executablePath: string;
    /** CLI arguments to pass to the binary. */
    args: string[];
    /** Diagnostic logger, created when logDir is set or debug is enabled. */
    logger?: FileLogger;
    /** Path to the diagnostic log file (if logger is active). */
    logFile?: string;
    /** Timestamp when spawn preparation started (for duration tracking). */
    startTime: number;
}
/**
 * Generate a timestamped log file path in the given directory.
 */
export declare function makeLogFilePath(dir: string): string;
/**
 * Apply Linux network-policy defaults to a `ContainerConfig`.
 *
 * Linux enforces per-host filtering in one of two ways:
 *   1. **iptables firewall** (`enforcementMode: 'firewall'`) — LXC's
 *      privileged enforcement path. Requires root / CAP_NET_ADMIN.
 *   2. **Cooperative HTTP proxy** (`network.proxy` set) — Bubblewrap's
 *      unprivileged enforcement path. The proxy applies the host policy
 *      for cooperating HTTP clients; raw-socket clients bypass it.
 *
 * This helper auto-promotes `enforcementMode` to `'firewall'` when host
 * lists are present without a proxy — without it, the parser would leave
 * the mode unset and the runtime would silently ignore `allowedHosts` /
 * `blockedHosts`.
 *
 * If the caller explicitly passes `enforcementMode: 'capabilities'` we
 * warn: `'capabilities'` is a Windows/AppContainer concept (a token
 * capability mask) and has no Linux equivalent — the Linux runner will
 * not enforce anything and the field is silently dropped.
 *
 * Shared between the explicit `'bubblewrap'` / `'lxc'` builders and the
 * abstract `'process'` branch on Linux (which resolves to Bubblewrap
 * server-side).
 *
 * NOTE: when `network.proxy` is configured on Bubblewrap, host filtering
 * is enforced at the proxy layer (unprivileged, no CAP_NET_ADMIN). The
 * Rust config parser explicitly rejects `bubblewrap + proxy + firewall`
 * since the iptables path requires privilege the bwrap backend
 * deliberately avoids. Callers in that mode must leave enforcementMode
 * at its default.
 */
export declare function applyLinuxNetworkPolicy(config: ContainerConfig): void;
/**
 * Resolves the executor binary and builds the common CLI arguments for any
 * MXC request envelope (one-shot or state-aware). Performs platform support
 * and binary-presence checks; does not validate envelope contents — callers
 * apply request-specific validation before delegating to this helper.
 */
export declare function resolveBinaryAndCommonArgs(envelopeJson: string, options: SandboxSpawnOptions): {
    executablePath: string;
    args: string[];
};
/**
 * Resolves the executable path and builds CLI arguments for a one-shot
 * sandbox invocation. Validates one-shot-specific invariants (commandLine
 * required, experimental gating, containment-vs-platform compatibility)
 * before delegating to the shared `resolveBinaryAndCommonArgs`.
 */
export declare function resolveExecutableAndArgs(config: ContainerConfig, options?: SandboxSpawnOptions): {
    executablePath: string;
    args: string[];
};
/**
 * Sets up logging and resolves the executable path + args.
 * Shared by both PTY and non-PTY spawn paths.
 *
 * If resolveExecutableAndArgs throws, any open logger is closed
 * before the error propagates.
 *
 * @param config - The container configuration
 * @param options - Spawn options (debug, logDir, etc.)
 */
export declare function prepareSpawn(config: ContainerConfig, options: SandboxSpawnOptions): PrepareSpawnResult;
//# sourceMappingURL=helper.d.ts.map