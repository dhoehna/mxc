/**
 * Policy discovery APIs for building sandbox filesystem policy.
 *
 * These functions enumerate the host environment to discover tool paths,
 * user profile locations, and temporary storage — returning policy fragments
 * that callers can merge into a {@link SandboxPolicy}.
 */
/**
 * A composable fragment of filesystem policy.
 * Callers merge one or more fragments into {@link SandboxPolicy.filesystem}.
 */
export interface FilesystemPolicyResult {
    /** Paths that should be granted read-only access inside the container */
    readonlyPaths: string[];
    /** Paths that should be granted read-write access inside the container */
    readwritePaths: string[];
}
/**
 * Options for {@link getAvailableToolsPolicy}.
 */
export interface ToolsPolicyOptions {
    /**
     * When set to `'processcontainer'`, directories whose ACLs already grant
     * access to ALL_APPLICATION_PACKAGES are excluded from the result
     * because AppContainer processes can already see them implicitly.
     */
    containerType?: 'processcontainer';
}
/**
 * Discover tool and SDK directories from the environment and return them as
 * policy paths.
 *
 * Reads the `PATH` variable and a set of well-known tool / SDK environment
 * variables, enumerates the directories they reference, then applies filters:
 *
 * 1. Directories that do not exist on disk are removed.
 * 2. System-critical directories (under `%WINDIR%`) are removed.
 * 3. When `options.containerType` is `'processcontainer'`, directories whose ACLs
 *    already grant access to `ALL_APPLICATION_PACKAGES` are removed because
 *    AppContainer processes can see them without explicit brokering.
 *
 * Additionally, if PowerShell (`pwsh.exe`) is found on PATH, the drive root
 * (`C:\`) is added to `readonlyPaths` and the PSReadLine history directory
 * is added to `readwritePaths` so that interactive PowerShell sessions work
 * correctly inside the container.
 *
 * @param env - Environment variable map. Defaults to `process.env`.
 * @param options - Filtering options.
 * @returns A policy fragment with discovered paths.
 */
export declare function getAvailableToolsPolicy(env?: {
    [key: string]: string | undefined;
}, options?: ToolsPolicyOptions): FilesystemPolicyResult;
/**
 * Build read-only policy for standard user profile application data locations.
 *
 * Enumerates immediate subdirectories of `%LOCALAPPDATA%\Programs`
 * (per-user installed developer tools) as additional read-only paths.
 *
 * @returns A policy fragment with user profile paths in `readonlyPaths`.
 */
export declare function getUserProfilePolicy(): FilesystemPolicyResult;
/**
 * Generate a dedicated temporary directory for a container and return it as
 * read-write policy.
 *
 * If the provided environment contains a `TEMP` (or `TMP`) variable, a
 * uniquely-named subdirectory is created beneath that path and returned in
 * `tempDirectory` and `readwritePaths`. If neither variable is set the
 * container is assumed to manage its own temp directory, so the returned
 * policy is empty.
 *
 * @param env - Environment variable map. Defaults to `process.env`.
 * @returns Policy fragment with the temp directory in both `tempDirectory`
 *          and `readwritePaths`, or empty values when no TEMP path is found.
 */
export declare function getTemporaryFilesPolicy(env?: {
    [key: string]: string | undefined;
}): FilesystemPolicyResult;
//# sourceMappingURL=policy.d.ts.map