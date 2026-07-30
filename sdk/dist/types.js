// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Runtime list of {@link ContainmentType} values. Kept in sync with the
 * `ContainmentType` union via the type annotation. Use this to recognise
 * abstract intents at run time (the union itself only exists at compile
 * time).
 */
export const ContainmentTypes = ['process', 'vm', 'microvm'];
/**
 * Deprecated containment wire values, mapped to their canonical
 * {@link ContainmentBackend} replacement. The native binary (wxc-exec) accepts
 * the deprecated form via serde aliases; this map mirrors that behavior in
 * the SDK validator so legacy configs are not rejected before reaching the
 * binary.
 *
 * The map is intentionally partial: only deprecated keys appear. Use a
 * presence check (e.g. `LegacyContainmentAliases[value] ?? value`) rather
 * than indexing blindly.
 *
 * The wire payload is forwarded to wxc-exec unchanged — the Rust parser
 * performs the final mapping at runtime. Resolution here is purely so the
 * SDK's experimental-mode, platform-support, and availability checks see
 * the canonical backend.
 *
 * Internal to the SDK; not part of the public API. Subject to removal in a
 * future minor release once the deprecation window closes.
 */
export const LegacyContainmentAliases = {
    appcontainer: 'processcontainer',
    macos_sandbox: 'seatbelt',
};
/**
 * Containment values (abstract intent or concrete backend) that require
 * the `--experimental` flag.
 */
export const ExperimentalBackends = ['microvm', 'windows_sandbox', 'hyperlight', 'wslc', 'isolation_session'];
//# sourceMappingURL=types.js.map