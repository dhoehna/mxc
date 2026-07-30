// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// State-aware wire-type conformance oracle (Phase 2.5).
//
// The one-shot oracle (`wire-conformance.test.ts`) asserts that
// `sdk/src/types.ts` conforms to the generated wire types. This companion does
// the same for the STATE-AWARE lifecycle public types in
// `sdk/src/state-aware-types.ts`, against the generated wire state-aware defs
// (`Phase`, `IsolationConfigurationId`, `IsolationUser`, `IsolationSessionPhase`).
// Without it, a wire-model change to the state-aware surface — a new sizing
// profile, a field added to the Entra user bundle, a `Phase` change — would
// regenerate `wire.ts`, pass the codegen gate, and still leave the SDK silently
// lagging with no CI signal.
//
// Mapping note (why this is a separate file, not part of the one-shot oracle):
// the public per-phase call configs do NOT map 1:1 to a single wire type. Each
// mixes SDK-level / top-level wire fields with `IsolationSessionPhase` fields:
//
//   public field                          wire location
//   ------------------------------------  --------------------------------------
//   *Config.version                       top-level `version` (SDK fills default)
//   ProvisionConfig.filesystem            top-level `Filesystem`
//   ExecConfig.process                    top-level `Process`
//   StartConfig.configurationId           IsolationSessionPhase.configurationId
//   {Provision,Start}Config.user          IsolationSessionPhase.user / IsolationUser
//
// The top-level fields are already covered by the one-shot oracle; here we (a)
// assert the per-phase configs REUSE those same public leaf types (so the
// delegation is real, not a re-derived shape that could escape the one-shot
// oracle), and (b) directly check the genuinely state-aware shapes (the phase
// enum, the sizing-profile enum, the user bundle, and the `IsolationSessionPhase`
// field set). The runtime body is a no-op; the guarantee is enforced at `tsc`
// time.
import { test } from 'node:test';
test('public state-aware SDK types conform to the generated wire schema (compile-time)', () => {
    // Intentionally empty: the guarantee is enforced by the type aliases above at
    // `tsc` time. If they fail to compile, `npm run build:test-unit` fails before
    // this test ever runs.
});
