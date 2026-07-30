import pty from 'node-pty';
import { ChildProcess } from 'child_process';
import { SandboxPolicy, ContainerConfig, ContainmentType, ContainmentBackend } from './types.js';
/**
 * Creates a ContainerConfig from a SandboxPolicy and optional containment type.
 *
 * This is the primary API for translating user-facing security intent (SandboxPolicy)
 * into a backend-specific configuration (ContainerConfig). The returned config
 * can be modified before passing to spawnSandboxFromConfig().
 *
 * @param policy - The sandbox policy expressing security intent
 * @param containment - Containment backend type (default: "process")
 * @param containerName - Optional container name; auto-generated if omitted
 * @returns A fully populated ContainerConfig ready for modification or spawning
 *
 * @example
 * ```typescript
 * const policy: SandboxPolicy = {
 *   version: '0.5.0-alpha',
 *   network: { allowOutbound: true },
 *   ui: { allowWindows: true, clipboard: 'read' },
 * };
 *
 * // Simple: use defaults
 * const config = createConfigFromPolicy(policy);
 *
 * // Advanced: tweak backend-specific settings
 * const config = createConfigFromPolicy(policy, "process");
 * config.processContainer!.ui!.isolation = "atoms";
 * ```
 */
export declare function createConfigFromPolicy(policy: SandboxPolicy, containment?: ContainmentType | ContainmentBackend, containerName?: string): ContainerConfig;
/**
 * Builds a sandbox payload JSON object from the sandbox policy.
 * @param script The command line script to execute
 * @param policy The sandbox policy configuration
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * @param containment Optional containment backend type
 * @returns The sandbox payload object
 */
export declare function buildSandboxPayload(script: string, policy: SandboxPolicy, workingDirectory?: string, containerName?: string, containment?: ContainmentType | ContainmentBackend): ContainerConfig;
/**
 * Options for spawning a sandboxed process
 */
export interface SandboxSpawnOptions {
    /**
     * Enable debug output from wxc-exec
     */
    debug?: boolean;
    /**
     * Enable experimental features
     */
    experimental?: boolean;
    /**
     * Allow testing-only, deliberately-permissive features that must never run
     * in production — currently `network.proxy.builtinTestServer` (a bundled
     * test HTTP proxy with no auth, no body limits, minimal hop-by-hop header
     * handling). This is a distinct axis from {@link experimental}: a policy
     * that requests such a feature is rejected unless this is explicitly set,
     * keeping the gate fail-closed at the SDK boundary (it maps to the native
     * `--allow-testing-features` flag).
     */
    allowTestingFeatures?: boolean;
    /**
     * Explicit path to the wxc-exec (or lxc-exec) binary.
     * When set, the SDK uses this path directly instead of searching.
     * Useful for packaged apps (e.g., Electron) where the binary
     * is bundled in a known location.
     */
    executablePath?: string;
    /**
     * Skip platform support check. Use when you know the platform
     * is compatible and want to bypass build version validation.
     */
    skipPlatformCheck?: boolean;
    /**
     * PTY options to pass to node-pty (only used by spawnSandbox)
     */
    ptyOptions?: pty.IPtyForkOptions;
    /**
     * Dry run mode: parse and validate config without executing.
     * The native binary validates the config then exits.
     */
    dryRun?: boolean;
    /**
     * Directory for diagnostic log files
     */
    logDir?: string;
    /**
     * When false, uses child_process.spawn instead of node-pty.
     * Provides reliable exit codes and separate stdout/stderr streams.
     * Defaults to true (uses PTY).
     */
    usePty?: boolean;
    /**
     * Optional cancellation signal. When it aborts, the SDK kills the
     * spawned executor process and rejects any pending result promise with
     * the signal's reason. Honored by the state-aware lifecycle functions;
     * one-shot spawn currently ignores it (kill the returned IPty /
     * ChildProcess directly instead).
     *
     * Cancellation is best-effort: killing the executor mid-call leaves
     * any backend-side state (e.g. a partially-provisioned IsolationSession)
     * wherever it landed. Callers may need a follow-up `deprovisionSandbox`
     * (or its equivalent) to clean up an orphaned sandbox after an abort.
     */
    signal?: AbortSignal;
}
/**
 * Spawn a sandboxed process using wxc-exec with a PTY (node-pty) for
 * interactive terminal I/O (colors, input forwarding).
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * @param env Optional environment variables
 * @returns IPty object for interacting with the sandboxed process
 * @throws Error if platform is not supported or wxc-exec is not found
 *
 * @example
 * ```typescript
 * const script = 'python -c "import sys; print(sys.version)"';
 * const policy: SandboxPolicy = { version: '0.4.0-alpha' };
 *
 * const ptyProcess = spawnSandbox(script, policy);
 * ptyProcess.onData((data) => console.log(data));
 * ptyProcess.onExit((e) => console.log('Exit code:', e.exitCode));
 * ```
 */
export declare function spawnSandbox(script: string, policy: SandboxPolicy, options?: SandboxSpawnOptions, workingDirectory?: string, containerName?: string, env?: {
    [key: string]: string | undefined;
}): pty.IPty;
/**
 * Spawn a sandboxed process from a pre-built ContainerConfig.
 *
 * Use with `createConfigFromPolicy()` when you need to modify
 * backend-specific settings before spawning. The config must have
 * `process.commandLine` already set.
 *
 * @param config The container configuration (from createConfigFromPolicy)
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @returns IPty when usePty is true or unset; ChildProcess when usePty is false
 *
 * @example
 * ```typescript
 * const config = createConfigFromPolicy(policy, "process");
 * config.process!.commandLine = 'echo hello';
 * config.processContainer!.ui!.isolation = "atoms";
 *
 * // PTY mode (default) — returns IPty:
 * const ptyProcess = spawnSandboxFromConfig(config);
 *
 * // Non-PTY mode — returns ChildProcess with reliable exit codes:
 * const child = spawnSandboxFromConfig(config, { usePty: false });
 * child.stdout?.on('data', (data) => console.log(data.toString()));
 * ```
 */
export declare function spawnSandboxFromConfig(config: ContainerConfig, options: SandboxSpawnOptions & {
    usePty: false;
}, workingDirectory?: string, env?: {
    [key: string]: string | undefined;
}): ChildProcess;
export declare function spawnSandboxFromConfig(config: ContainerConfig, options?: SandboxSpawnOptions, workingDirectory?: string, env?: {
    [key: string]: string | undefined;
}): pty.IPty;
/**
 * Spawn a sandboxed process and return a promise that resolves with output.
 * Convenience wrapper around spawnSandbox for non-interactive use cases.
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 *
 * @returns Promise that resolves with stdout/stderr and exit code
 *
 * @example
 * ```typescript
 * const policy: SandboxPolicy = {
 *   version: '0.4.0-alpha',
 *   filesystem: { readwritePaths: ['/workspace'] },
 * };
 *
 * const result = await spawnSandboxAsync('echo hello', policy);
 * console.log('Output:', result.stdout);
 * console.log('Exit code:', result.exitCode);
 * ```
 */
export declare function spawnSandboxAsync(script: string, policy: SandboxPolicy, options?: SandboxSpawnOptions, workingDirectory?: string, containerName?: string): Promise<{
    stdout: string;
    stderr: string;
    exitCode: number;
}>;
//# sourceMappingURL=sandbox.d.ts.map