/**
 * MXC SDK - TypeScript SDK for Microsoft eXecution Containers
 *
 * This package provides a Node.js interface for spawning sandboxed containers.
 *
 * @example
 * ```typescript
 * import { spawnSandbox, spawnSandboxWithPty, SandboxPolicy, getPlatformSupport } from '@microsoft/mxc-sdk';
 *
 * if (getPlatformSupport().isSupported) {
 *   const policy: SandboxPolicy = {
 *     version: '0.4.0-alpha',
 *     network: { allowOutbound: true },
 *   };
 *
 *   const ptyProcess = spawnSandboxWithPty('python -c "print(\'Hello from sandbox\')"', policy);
 *   ptyProcess.onData((data) => console.log(data));
 *   ptyProcess.onExit((event) => console.log('Exit code:', event.exitCode));
 * }
 * ```
 *
 * @packageDocumentation
 */
export { SandboxPolicy, SandboxingMethod, IsolationTier, ContainmentType, ContainmentTypes, ContainmentBackend, ExperimentalBackends, ContainerConfig, PlatformSupport, UiCapabilitySupport, } from './types.js';
export { getPlatformSupport, } from './platform.js';
export { createConfigFromPolicy, spawnSandbox, spawnSandboxAsync, spawnSandboxFromConfig, buildSandboxPayload, SandboxSpawnOptions, } from './sandbox.js';
export { getAvailableToolsPolicy, getUserProfilePolicy, getTemporaryFilesPolicy, FilesystemPolicyResult, ToolsPolicyOptions, } from './policy.js';
export { ErrorCode, MxcError, mxcErrorFromCode, } from './errors.js';
export { Phase, StateAwareContainmentBackend, SandboxId, IsolationSessionUserConfig, IsolationSessionProvisionConfig, IsolationSessionStartConfig, IsolationSessionExecConfig, IsolationSessionStopConfig, IsolationSessionDeprovisionConfig, IsolationSessionProvisionMetadata, ConfigsForBackend, ProvisionConfigFor, StartConfigFor, ExecConfigFor, StopConfigFor, DeprovisionConfigFor, StateAwareMetadata, ProvisionMetadataFor, StartMetadataFor, StopMetadataFor, DeprovisionMetadataFor, ProvisionResult, StartResult, StopResult, DeprovisionResult, ExecResult, } from './state-aware-types.js';
export { provisionSandbox, startSandbox, execInSandbox, execInSandboxAsync, stopSandbox, deprovisionSandbox, } from './state-aware.js';
//# sourceMappingURL=index.d.ts.map