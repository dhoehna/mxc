# Publishing MXC Crates to crates.io

This document describes the Azure DevOps pipeline that publishes MXC's Rust
crate workspace to [crates.io](https://crates.io) via ESRP Release.

## Overview

The **1ES.Release.Crates** pipeline (`.azure-pipelines/1ES.Release.Crates.yml`)
packages and publishes the 20-crate release closure from the MXC Rust workspace
in a single pipeline run:

1. **Package stage** — checks out the release tag the run was queued against,
   runs one `cargo package` invocation carrying a `-p` flag per crate, and
   uploads the `.crate` files plus a `release-order.json` manifest as the
   `mxc-crates-package` artifact.
2. **Publish stage** — downloads that artifact and publishes each `.crate` to
   crates.io through ESRP, one `EsrpRelease@12` task per crate, leaf-first.

No `CARGO_REGISTRY_TOKEN` exists in this repository. ESRP holds the publishing
credentials and publishes under the `microsoft-oss-releases` account.

## Crate list (leaf-first order)

Defined in `.azure-pipelines/scripts/crates_release.py`:

| # | Crate |
|---|-------|
| 1 | `nanvix_common` |
| 2 | `mxc_telemetry` |
| 3 | `wxc_common` |
| 4 | `nanvix_runner` |
| 5 | `hyperlight_common` |
| 6 | `mxc_pty` |
| 7 | `lxc_common` |
| 8 | `bwrap_common` |
| 9 | `seatbelt_common` |
| 10 | `sandbox_spec` |
| 11 | `learning_mode_core` |
| 12 | `learning_mode_windows` |
| 13 | `appcontainer_common` |
| 14 | `isolation_session_bindings` |
| 15 | `isolation_session_common` |
| 16 | `windows_sandbox_common` |
| 17 | `windows_sandbox_lifecycle` |
| 18 | `wslc_common` |
| 19 | `mxc_engine` |
| 20 | `mxc-sdk` |

These names are provisional until the public naming scheme is approved. The
same sequence is duplicated as the `crateOrder` default in
`.azure-pipelines/1ES.Release.Crates.yml`, and `verify-order` fails the run if
the two disagree. It accepts an ordered subset of the packaged closure, so a
`crateOrder` that omits crates will pass — that is what makes a partial resume
possible, and it is why the list must be edited deliberately.

## How versions are determined

All crates declare `version.workspace = true` in their own `Cargo.toml`, so the
single `version` field in `src/Cargo.toml` (currently `0.7.0`) is the version
that ships. The pipeline does not set or override the version — it packages
whatever `src/Cargo.toml` contains at the tagged commit. To release a new
version:

1. Bump the version in `src/Cargo.toml`.
2. Commit and push.
3. Create a new git tag named `release/v<major>.<minor>.<patch>[-rc<n>]` (for
   example `release/v0.8.0`). The `release/` prefix is required — see
   [Choosing the release ref](#choosing-the-release-ref).
4. Run the pipeline against that tag.

Re-running against the same tag re-packages the same version, which crates.io
rejects (duplicate version). See [Resuming a failed release](#resuming-a-failed-release)
for what to do when only some crates landed.

## Choosing the release ref

There is no tag parameter to type. The pipeline packages **the ref the run is
queued against**, chosen from the branch/tag selector at the top of the **Run
pipeline** dialog.

That ref must be a tag under `refs/tags/release/*` — for example
`release/v0.8.0`. The `Validate_Release_Ref` stage fails the run for anything
else (a branch, or a bare `v0.8.0` tag), and both the package and publish
stages depend on it, so nothing is checked out or published from a
non-release ref. That stage is marked `isSkippable: false`, so it also cannot
be switched off in the Run dialog's **Stages to run** panel.

Azure DevOps offers no way to filter that selector — it lists every branch and
tag in the repository — which is why the guard exists. For enforcement outside
the pipeline's own YAML, add a **branch control check** to the ESRP service
connection in the Azure DevOps UI.

Because the ref supplies the pipeline definition as well as the source, a
release is fully immutable: changing anything about how a release is built,
including this pipeline, requires cutting a new tag.

## Running the pipeline (step-by-step)

### 1. Dry run (recommended first)

1. In Azure DevOps, navigate to Pipelines → find the pipeline registered
   against `.azure-pipelines/1ES.Release.Crates.yml`.
2. Click **Run pipeline**.
3. In the branch/tag selector at the top of the dialog, pick the release tag
   (for example `release/v0.8.0`).
4. Fill in the parameters:

   | Parameter | Value |
   |---|---|
   | **Dry run** (`cratesDryRun`) | Set to `true` for this first run. |
   | **ESRP release owners email** (`esrpOwnersEmail`) | Defaults to `Darren.Hoehna@microsoft.com`; see [ESRP identity](#esrp-identity) below. |
   | **ESRP release approvers email** (`esrpApproversEmail`) | Defaults to `Darren.Hoehna@microsoft.com`; see [ESRP identity](#esrp-identity) below. |

   `crateOrder` is an `object` parameter whose default is the full 20-crate
   list baked into the YAML, so a full release needs no input here. Whether
   Azure DevOps renders an `object` parameter as an editable field in the Run
   dialog is unverified; to change the list (to resume a partial release), edit
   the pipeline file — see [Resuming a failed release](#resuming-a-failed-release).

5. Click **Run**.
6. Confirm the package stage succeeds, `verify-order` passes, and each crate
   logs `DRY RUN: skipping ESRP publish for <crate> (staged .crate only).`

### ESRP identity

The six ESRP signing fields (`serviceName`, `tenantId`, `azureKeyVaultName`,
`authCertName`, `signCertName`, `clientId`) come from the **`MXC-ESRP-Signing`**
variable group, the same group `.azure-pipelines/1ES.Build.Official.yml` uses
for code signing. The pipeline must be granted access to that group in ADO.

ESRP Release additionally needs owner and approver emails. The
`MXC-ESRP-Signing` group was inspected through the ADO REST API and contains
exactly the six signing keys above — it does **not** contain `OwnersEmail` or
`ApproversEmail`.  They are therefore exposed as the string parameters
`esrpOwnersEmail` and `esrpApproversEmail`, both defaulting to the predefined
variable `$(Build.RequestedForEmail)` — the email of whoever queued the run —
so a normal release is one click, with no address typed and no individual
hardcoded in the repository.  The default is a macro token, not a literal
address: the `${{ }}` template substitutions preserve the literal string
`$(Build.RequestedForEmail)`, which Azure DevOps expands at runtime in the
`EsrpRelease` task's `owners` and `approvers` inputs, since macro syntax is
expanded in task inputs after template expansion.  An operator may override
either value in the Run dialog.  For a manually queued run,
`Build.RequestedForEmail` is the queuer's email; it can be empty for a run
started by a service identity or a schedule, so if this pipeline is ever
automated rather than queued by a person, pass an explicit owner and approver
instead.  If either value is cleared to an empty or space-only string, the
`Validate_Release_Ref` stage fails the run immediately, naming the empty
parameter, before anything is checked out or packaged — an empty value would
otherwise submit an ESRP release with no owner or no approver.

### 2. Real release

Same steps as above, but leave **Dry run** at `false` (the default). Each
crate publishes sequentially via ESRP. If any crate fails, later crates are
skipped (the job fails).

## Resuming a failed release

crates.io rejects duplicate versions. If the pipeline fails partway through
(e.g. crate 7 of 20 fails for a transient reason), crates 1–6 are already
published and cannot be republished.

To resume:

1. Identify which crates were already published (check the pipeline logs — each
   successful `EsrpRelease@12` task confirms its crate).
2. Edit the `crateOrder` default in `.azure-pipelines/1ES.Release.Crates.yml`,
   removing the already-published crates, and merge that change to `main`.
   `crateOrder` is an `object` parameter; changing it means editing the
   pipeline file.
3. Cut a **new** release tag containing that edit (for example
   `release/v0.8.0-resume1`) and run the pipeline against it. The tag supplies
   the pipeline definition as well as the source, so the edited `crateOrder`
   only takes effect once it is inside a tag. Do not bump the crate version —
   the remaining crates still need to publish at the version that failed.
4. The `verify-order` guard accepts a subset of the original order as long as
   it is still in correct leaf-first sequence. It logs a warning naming every
   dependency it assumes is already live.

There is no automated resume. The operator asserts what landed by editing
`crateOrder`.

## Network isolation

The publish job runs on a 1ES pool with CFSClean network isolation — crates.io
is **not reachable** from the agent. Dependency resolution during packaging uses
the internal `Mxc-Azure-Feed`, appended to the workspace cargo config by
`.azure-pipelines/templates/Cargo.Setup.Private.yml` from
`.azure-pipelines/.cargo/config.toml`. ESRP itself handles the outbound publish
to crates.io.

Packaging passes `--registry Mxc-Azure-Feed` to work around
[rust-lang/cargo#17196](https://github.com/rust-lang/cargo/issues/17196): with
`[source.crates-io] replace-with` active, cargo registers the temporary overlay
holding the just-packaged workspace siblings under the pre-replacement source
id but looks it up under the post-replacement one, so the overlay is silently
bypassed and each sibling is searched for in the feed, where it does not exist.
The emitted `.crate` files are byte-identical either way.

Because `--registry` already steers resolution to the temporary overlay,
per-crate verification builds succeed and packaging deliberately does *not*
pass `--no-verify`. Nor does it pass `--allow-dirty`: the only file the
pipeline modifies is the workspace `.cargo/config.toml`, which lies outside
every package directory and so does not make any package dirty. A dirty-tree
failure during packaging therefore means a crate source really was modified,
and should stop the release.

## Prerequisites / known blockers

These must be resolved before the first real (non-dry-run) publish:

1. **OSPO OSS-release registration** — the crate closure must be registered in
   OSPO's open-source release tracker before ESRP will accept a `Rust`
   content-type release.
2. **ESRP `Rust` content-type onboarding** — the ESRP service connection must
   have the `Rust` content type enabled, requested through the ESRP onboarding
   portal.
3. **`hyperlight_common` name collision** — crates.io treats `-` and `_` as
   equivalent when checking name collisions, so `hyperlight_common` collides
   with the existing `hyperlight-common` crate, published from
   github.com/hyperlight-dev/hyperlight.  It is the only one of the 20 names
   that is taken today; the other 19 are unregistered.  The crate must be
   renamed or co-ownership obtained before it can be published. Note that
   `hyperlight-common` is marked `trustpub_only` on crates.io, so co-ownership
   alone may not permit an ESRP token publish.
4. **crates.io rate limit** — the default `PublishNew` rate limit is burst-5
   plus 1 per 10 minutes.  A 20-crate first release will be throttled.  An
   override must be requested from help@crates.io before the first publish.
5. **Pipeline registration** — `.azure-pipelines/1ES.Release.Crates.yml` is new
   and must be registered as a pipeline in Azure DevOps, and that pipeline must
   be authorized to use the `MXC-ESRP-Signing` variable group.

## Pipeline and template files

| File | Purpose |
|------|---------|
| `.azure-pipelines/1ES.Release.Crates.yml` | Top-level release pipeline (parameters, release-ref gate, stage wiring) |
| `.azure-pipelines/templates/Package.Crates.Job.yml` | Packaging job — runs `cargo package`, produces artifact |
| `.azure-pipelines/templates/Publish.CratesIo.Job.yml` | ESRP publish job — `verify-order`, stage, publish loop |
| `.azure-pipelines/scripts/crates_release.py` | Helper script (`package`, `verify-order`, `stage` subcommands) |
| `src/Cargo.toml` | Workspace version (single source of truth for all crate versions) |

## Comparison with the npm release

The npm SDK release (`.azure-pipelines/1ES.Release.yml`) consumes artifacts from
a **separate** official build pipeline (`MXC-Official-Build`) and publishes a
single `@microsoft/mxc-sdk` package. The crates release is self-contained: it
checks out the release tag, packages, and publishes in one run. This design
exists because 1ES forbids `checkout` in a release *job*, but a normal job in
the same *pipeline* may check out and build.
