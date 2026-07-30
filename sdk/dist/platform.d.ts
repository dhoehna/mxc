import { PlatformSupport } from './types.js';
/**
 * Result of querying the host's Windows build number, or `null` when the
 * registry values are missing or unparseable.
 */
type WindowsBuild = {
    major: number;
    minor: number;
} | null;
/** @internal Test-only: override the Windows build lookup. */
export declare function _setWindowsBuildQuery(fn: (() => WindowsBuild) | null): void;
/**
 * Get platform support information.
 *
 * On Windows, this also invokes `wxc-exec --probe` to populate
 * `isolationTier`, the `isolationWarnings` array (if any), and portable UI
 * capability facts. Linux and macOS currently do not expose native probe data,
 * so `uiCapabilities` is omitted on those platforms. The result is cached for
 * the lifetime of the SDK module — the underlying machine state is not
 * expected to change at runtime.
 *
 * @returns Platform support details including available sandboxing methods
 */
export declare function getPlatformSupport(): PlatformSupport;
/** @internal Test-only: clear the cached PlatformSupport. */
export declare function _resetPlatformSupportCache(): void;
/**
 * Probe runner injection seam. Spawns `wxc-exec --probe` and returns
 * its stdout. Replaceable in unit tests via {@link _setProbeRunner}.
 */
type ProbeRunner = () => string;
/** @internal Test-only: override the probe runner. */
export declare function _setProbeRunner(runner: ProbeRunner | null): void;
/**
 * Find the wxc-exec executable
 * Searches in common locations relative to the SDK package,
 * selecting the build matching the current machine architecture.
 * @returns Path to wxc-exec.exe if found, null otherwise
 */
export declare function findWxcExecutable(): string | null;
/**
 * Find the lxc-exec executable on Linux
 * Searches in common locations relative to the SDK package.
 * @returns Path to lxc-exec if found, null otherwise
 */
export declare function findLxcExecutable(): string | null;
/**
 * Find the mxc-exec-mac executable on macOS.
 * Searches in the SDK bin directory (npm install path) and Cargo build
 * output directories (monorepo dev path).
 * @returns Path to mxc-exec-mac if found, null otherwise
 */
export declare function findSeatbeltExecutable(): string | null;
export {};
//# sourceMappingURL=platform.d.ts.map