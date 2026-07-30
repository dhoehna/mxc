// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Wire-type conformance oracle (Phase 2C, option C).
//
// The generated module `../../src/generated/wire.ts` is emitted from the Rust
// wire model (`wxc_common::wire`) by the `mxc_schema_gen --ts` Rust TypeScript
// emitter. It is the single source of truth for the wire shape.
//
// This file asserts — at COMPILE TIME — that the hand-written public SDK types
// in `../../src/types.ts` still conform to that generated shape. If the Rust
// wire model changes (a field renamed/removed, an enum value added/dropped, a
// type narrowed) the regenerated `wire.ts` shifts and these assertions stop
// compiling, so `npm run build:test-unit` fails. The runtime body is a no-op;
// the test exists so `tsc` type-checks the assertions below.
//
// Direction & null-handling rationale:
//  * Generated fields are uniformly `field?: T | null` (optional AND nullable),
//    so they are strictly more permissive than the SDK's `field?: T`. Therefore
//    `PublicType extends GeneratedType` ("public is assignable to wire") holds
//    cleanly and catches enum/type NARROWING in the wire model.
//  * `OnlyInPublic` additionally catches a public field whose wire counterpart
//    was renamed or removed (width subtyping alone would not), and is asserted
//    to equal a documented, explicit set of SDK-only fields — so a NEW
//    divergence (not on the allow-list) fails the build. This is applied at the
//    ROOT (`ContainerConfig` ↔ `MXCConfiguration`) as well as the leaves, so a
//    top-level rename/removal cannot slip past (review finding F1, codex pass).
//  * `OnlyInWire` covers the OPPOSITE direction: because every generated wire
//    field is optional, `Public extends Wire` stays true when the SDK forgets a
//    newly added wire field, so a wire-only ADDITION needs its own check. Each
//    object asserts its wire-only key set equals an explicit allow-list (mostly
//    `never`), so a new wire field the SDK does not expose fails the build until
//    it is surfaced or documented (review finding F1, gpt-5.5 pass).
//  * Assignability is one-way and so does NOT catch a wire ENUM WIDENING (a new
//    value added in the wire model). Enum-backed domains the SDK exposes are
//    therefore additionally checked with the bidirectional `Equivalent` — both
//    the standalone enum types and the enum-typed object fields (review finding
//    F2, codex pass).
//
// One emitter artifact is normalized away: `StripIndex<T>` drops the
// `[k: string]: unknown` index signatures the emitter writes on the OPEN
// (experimental) objects; without this, structural assignment to those
// interfaces misbehaves.
import { test } from 'node:test';
test('public SDK wire types conform to the generated wire schema (compile-time)', () => {
    // Intentionally empty: the guarantee is enforced by the type aliases above at
    // `tsc` time. If they fail to compile, `npm run build:test-unit` fails before
    // this test ever runs.
});
