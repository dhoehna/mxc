#!/usr/bin/env python3
"""crates.io release helper for the `mxc-sdk` crate closure, ESRP edition.

MXC publishes crates through ESRP Release under the official
`microsoft-oss-releases` account. ESRP accepts pre-built `.crate` files, so this
repository never handles a `CARGO_REGISTRY_TOKEN`. See:
https://eng.ms/docs/microsoft-security/identity/trust-and-security-services/tss-release-distribute/tss-release-esrp-parent/oss-publishing/releasing-open-source/cratesio

ESRP does not sort a multi-crate dependency graph. The pipeline publishes one
crate at a time in leaf-first order, an order this helper validates offline
against the workspace's real dependency edges.

The release pool enforces 1ES network isolation (CFSClean), which blocks
crates.io. This helper therefore performs NO crates.io reads. The guarantees
that used to depend on them are covered earlier or elsewhere:

  * a dependency's version requirement matching its real version is enforced by
    `cargo package` itself at packaging time (it fails the build);
  * leaf-first ordering is enforced offline by `_validate_release_graph`;
  * a dependency crate existing at all is enforced server-side by crates.io,
    which rejects a publish naming an unknown crate;
  * yank detection and the published-checksum audit are out-of-band concerns
    and do not belong in the isolated release job.

Subcommands
-----------
package       Validate and package the complete first-party closure, then write
              `.crate` files and release-order.json.

verify-order  Assert that the crates the pipeline is about to publish are a
              correctly-ordered subset of what was packaged. A partial subset is
              allowed so an operator can resume a release that failed partway.

stage         Copy one `.crate` file into a clean directory for an ESRP task.

Resuming a failed release
-------------------------
There is no automated resume. crates.io rejects a duplicate version outright, so
re-running a partially-completed release unchanged fails on the first crate that
already landed. The isolated pool cannot ask crates.io what landed, so the
operator asserts it: re-queue the release with the finished crates removed from
the `crateOrder` parameter. `verify-order` still enforces that whatever remains
is published in correct leaf-first order, and logs every dependency it is
therefore assuming is already live.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

# Current Cargo package names in leaf-first order. These names remain
# provisional until the public naming scheme is approved; the crates.io release
# pipeline (.azure-pipelines/1ES.Release.Crates.yml) is manual-trigger only and
# offers a dry-run mode, so nothing reaches crates.io until that is settled.
#
# ADDING A CRATE -- do not work the order out by hand.  It is a topological
# sort of the workspace dependency graph, and `cargo metadata` already knows
# the graph:
#
#   1. Add the package name anywhere in CRATES below.  Position does not
#      matter yet.  It must go in first because `--derive` orders the crates
#      named here, so a package missing from CRATES is invisible to it.
#
#   2. Replace CRATES with a correctly sorted version of itself:
#        python3 .azure-pipelines/scripts/crates_release.py order \
#            --derive --format python
#
#   3. Mirror the result into the `crateOrder` default in
#      .azure-pipelines/templates/Publish.CratesIo.Job.yml:
#        python3 .azure-pipelines/scripts/crates_release.py order \
#            --format yaml
#
#   4. Confirm:
#        python3 .azure-pipelines/scripts/crates_release.py order --check
#
# Steps 2 and 3 go together.  A dependency graph admits many valid topological
# orders; `verify-order` requires the template's crateOrder to be an ordered
# SUBSET of the packaged order, which comes from this list.  Updating one
# without the other fails the run.
#
# The pipeline cannot use `cargo publish --workspace` (which would order the
# publish itself) because ESRP performs the upload, one .crate file at a time,
# so the order has to exist as data rather than as cargo's internal plan.
CRATES: list[str] = [
    "nanvix_common",
    "mxc_telemetry",
    "wxc_common",
    "nanvix_runner",
    "hyperlight_common",
    "mxc_pty",
    "lxc_common",
    "bwrap_common",
    "seatbelt_common",
    "sandbox_spec",
    "learning_mode_core",
    "learning_mode_windows",
    "appcontainer_common",
    "isolation_session_bindings",
    "isolation_session_common",
    "windows_sandbox_common",
    "windows_sandbox_lifecycle",
    "wslc_common",
    "mxc_engine",
    "mxc-sdk",
]


def _cargo_metadata(manifest_path: str) -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            manifest_path,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def _run(args: list[str], cwd: str | None = None) -> int:
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(args, cwd=cwd).returncode


def _load_order(order_file: str) -> list[dict]:
    with open(order_file, encoding="utf-8") as fh:
        return json.load(fh)["crates"]


def _entry_for_crate(order_file: str, crate: str) -> dict | None:
    return next(
        (
            entry
            for entry in _load_order(order_file)
            if entry["name"] == crate
        ),
        None,
    )


def _crate_file(order_file: str, entry: dict) -> str:
    return os.path.join(
        os.path.dirname(os.path.abspath(order_file)),
        entry["file"],
    )


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_release_graph(metadata: dict) -> dict[str, list[str]]:
    """Validate the full local dependency closure and return its edges."""
    packages = {package["name"]: package for package in metadata["packages"]}
    positions = {crate: index for index, crate in enumerate(CRATES)}
    dependencies: dict[str, list[str]] = {}
    errors: list[str] = []

    if len(positions) != len(CRATES):
        errors.append("CRATES contains duplicate package names")

    for crate in CRATES:
        package = packages.get(crate)
        if package is None:
            errors.append(f"{crate}: not found in workspace metadata")
            continue

        allowed_registries = package.get("publish")
        if allowed_registries == []:
            errors.append(f"{crate}: package has publish = false")
        elif (
            allowed_registries is not None
            and "crates-io" not in allowed_registries
        ):
            errors.append(
                f"{crate}: package publish list does not include crates-io"
            )

        local_dependencies: list[str] = []
        for dependency in package["dependencies"]:
            dependency_name = dependency["name"]
            if not dependency.get("path") or dependency_name not in packages:
                continue
            if dependency.get("req") in (None, "*"):
                errors.append(
                    f"{crate} -> {dependency_name}: local dependency is missing "
                    "a registry version"
                )
            if dependency_name not in positions:
                errors.append(
                    f"{crate} -> {dependency_name}: local dependency is missing "
                    "from CRATES"
                )
                continue
            if positions[dependency_name] >= positions[crate]:
                errors.append(
                    f"{crate} -> {dependency_name}: dependency must appear "
                    "earlier in CRATES"
                )
            local_dependencies.append(dependency_name)

        dependencies[crate] = sorted(
            set(local_dependencies),
            key=positions.__getitem__,
        )

    if errors:
        raise RuntimeError(
            "Invalid crates.io release graph:\n  - " + "\n  - ".join(errors)
        )
    return dependencies


def cmd_package(args: argparse.Namespace) -> int:
    metadata = _cargo_metadata(args.manifest_path)
    versions = {
        package["name"]: package["version"]
        for package in metadata["packages"]
    }
    try:
        dependencies = _validate_release_graph(metadata)
    except RuntimeError as error:
        print(f"FAIL  {error}")
        return 1

    target_dir = metadata["target_directory"]
    package_dir = os.path.join(target_dir, "package")
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    print(f"=== cargo package: {len(CRATES)} crates (leaf-first) ===")
    for crate in CRATES:
        print(f"  {crate} {versions[crate]}")
    print(flush=True)

    manifest = os.path.abspath(args.manifest_path)
    # Verification stays on. Passing --registry (rather than the default
    # crates-io) is what makes cargo resolve sibling crates against the
    # temporary package registry, so the overlay bug in cargo#17196 does not
    # apply here and --no-verify is unnecessary. --allow-dirty is likewise
    # omitted: the only file the pipeline modifies is the workspace
    # .cargo/config.toml, which lies outside every package directory, so a
    # dirty-tree failure here means a crate source really was modified.
    package_args = [
        "cargo",
        "package",
        "--registry",
        args.registry,
        "--manifest-path",
        manifest,
    ]
    for crate in CRATES:
        package_args += ["-p", crate]
    rc = _run(package_args)
    if rc != 0:
        print(f"FAIL  cargo package exited {rc}")
        return 1

    ordered: list[dict] = []
    for crate in CRATES:
        version = versions[crate]
        crate_file = f"{crate}-{version}.crate"
        source = os.path.join(package_dir, crate_file)
        if not os.path.isfile(source):
            print(f"FAIL  expected {source} was not produced by cargo package")
            return 1
        destination = os.path.join(out_dir, crate_file)
        shutil.copy2(source, destination)
        ordered.append(
            {
                "name": crate,
                "version": version,
                "file": crate_file,
                # Recorded so an out-of-band auditor can confirm what crates.io
                # actually serves matches what this build produced. The release
                # job itself cannot check that -- crates.io is unreachable from
                # the isolated pool.
                "sha256": _sha256(destination),
                "dependencies": dependencies[crate],
            }
        )
        print(f"OK    packaged {crate_file}", flush=True)

    order_path = os.path.join(out_dir, "release-order.json")
    with open(order_path, "w", encoding="utf-8") as fh:
        json.dump({"crates": ordered}, fh, indent=2)
    print(f"\nWrote {order_path}")
    print(f"=== packaged {len(ordered)} crates into {out_dir} ===")
    return 0


def cmd_verify_order(args: argparse.Namespace) -> int:
    entries = _load_order(args.order_file)
    packaged = [entry["name"] for entry in entries]
    by_name = {entry["name"]: entry for entry in entries}
    requested = json.loads(args.expected)

    if len(set(requested)) != len(requested):
        print("The crateOrder parameter lists the same crate more than once.")
        return 1

    unknown = [name for name in requested if name not in by_name]
    if unknown:
        print(
            "The crateOrder parameter names crates that were not packaged: "
            f"{unknown}"
        )
        print(f"  release-order.json : {packaged}")
        return 1

    # A release may deliberately publish a SUBSET of the packaged closure: that
    # is how an operator resumes a run that failed partway through. The release
    # pool cannot ask crates.io what already landed (network isolation), so the
    # operator asserts it by removing the finished crates from crateOrder.
    # The subset must remain a SUBSEQUENCE of the packaged leaf-first order, so
    # that whatever is published is still published in dependency order.
    remaining = iter(packaged)
    if not all(name in remaining for name in requested):
        print(
            "The crateOrder parameter is not in packaged leaf-first order. It "
            "must list a subset of the packaged crates in the same relative "
            "order."
        )
        print(f"  pipeline crateOrder : {requested}")
        print(f"  release-order.json  : {packaged}")
        return 1

    positions = {name: index for index, name in enumerate(requested)}
    assumed_published: list[str] = []
    for name in requested:
        entry = by_name[name]
        if "dependencies" not in entry:
            print(f"Crate {name} is missing dependency metadata.")
            return 1
        for dependency in entry["dependencies"]:
            if dependency not in by_name:
                print(f"Crate {name} depends on unpackaged crate {dependency}.")
                return 1
            if dependency not in positions:
                assumed_published.append(f"{name} -> {dependency}")
                continue
            if positions[dependency] >= positions[name]:
                print(f"Crate {name} appears before dependency {dependency}.")
                return 1

    if len(requested) == len(packaged):
        print(f"Crate order verified ({len(packaged)} crates, leaf-first).")
        return 0

    skipped = [name for name in packaged if name not in positions]
    print(
        f"Crate order verified ({len(requested)} of {len(packaged)} crates, "
        "leaf-first)."
    )
    print(
        "##vso[task.logissue type=warning]PARTIAL RELEASE: publishing "
        f"{len(requested)} of {len(packaged)} packaged crates. Skipping: "
        f"{skipped}"
    )
    for edge in assumed_published:
        print(
            f"##vso[task.logissue type=warning]Assuming already published on "
            f"crates.io: {edge}"
        )
    return 0


def cmd_stage(args: argparse.Namespace) -> int:
    entry = _entry_for_crate(args.order_file, args.crate)
    if entry is None:
        print(f"Crate {args.crate!r} not found in {args.order_file}")
        return 1

    out_dir = os.path.abspath(args.out_dir)
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    source = _crate_file(args.order_file, entry)
    if not os.path.isfile(source):
        print(f"Crate file not found: {source}")
        return 1

    # Staging is the last point at which a truncated or substituted archive can
    # be caught: past here ESRP uploads it and the crates.io version is
    # immutable. Fail closed when the digest is missing as well as when it
    # disagrees, so an order file written without one cannot silently skip this.
    expected = entry.get("sha256")
    if not expected:
        print(f"FAIL  no sha256 recorded for {entry['file']} in {args.order_file}")
        return 1
    actual = _sha256(source)
    if actual != expected:
        print(f"FAIL  checksum mismatch for {entry['file']}")
        print(f"      expected {expected}")
        print(f"      actual   {actual}")
        return 1

    shutil.copy2(source, os.path.join(out_dir, entry["file"]))
    print(
        f"Staged {entry['file']} ({args.crate} {entry['version']}) "
        f"into {out_dir} for ESRP, sha256 verified."
    )
    return 0


def _derive_order(metadata: dict) -> list[str]:
    """Topologically sort the publishable workspace closure, leaf-first.

    The order is a property of the dependency graph, not a human choice, so it
    is derived from `cargo metadata` rather than maintained by hand.  Ties are
    broken alphabetically so the output is stable across runs and diffs stay
    readable.
    """
    packages = {package["name"]: package for package in metadata["packages"]}
    wanted = set(CRATES)

    edges: dict[str, set[str]] = {}
    for name in wanted:
        package = packages.get(name)
        if package is None:
            raise RuntimeError(f"{name}: not found in workspace metadata")
        edges[name] = {
            dependency["name"]
            for dependency in package["dependencies"]
            if dependency.get("path") and dependency["name"] in wanted
        }

    ordered: list[str] = []
    placed: set[str] = set()
    while len(ordered) < len(wanted):
        ready = sorted(
            name
            for name in wanted - placed
            if edges[name] <= placed
        )
        if not ready:
            remaining = ", ".join(sorted(wanted - placed))
            raise RuntimeError(
                "dependency cycle among publishable crates: " + remaining
            )
        ordered.extend(ready)
        placed.update(ready)
    return ordered


def cmd_order(args: argparse.Namespace) -> int:
    metadata = _cargo_metadata(args.manifest_path)

    if args.derive:
        # A freshly computed order, for when a crate is ADDED and CRATES needs
        # a new entry.  Deliberately NOT the default: any valid topological
        # order differs from any other, and `verify-order` requires the
        # template's crateOrder to be an ordered SUBSET of the packaged order
        # (which comes from CRATES).  Pasting a derived order into the template
        # without also updating CRATES fails the run.  Update both together.
        for crate in _derive_order(metadata):
            print(_format_crate(crate, args.format))
        return 0

    # Default and --check both validate CRATES against the real dependency
    # graph: every local dependency present, ordered earlier, publishable.
    _validate_release_graph(metadata)
    if args.check:
        print(f"OK: CRATES is a valid leaf-first order ({len(CRATES)} crates)")
        return 0

    for crate in CRATES:
        print(_format_crate(crate, args.format))
    return 0


def _format_crate(crate: str, style: str) -> str:
    if style == "yaml":
        return f"    - {crate}"
    if style == "python":
        return f'    "{crate}",'
    return crate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    package = sub.add_parser(
        "package",
        help="validate and cargo package the complete closure",
    )
    package.add_argument("--manifest-path", default="src/Cargo.toml")
    package.add_argument("--out-dir", required=True)
    # Which registry cargo resolves unpublished workspace siblings against.
    # Defaults to the private feed because that is the only value known to
    # work: verification is enabled (see cmd_package), and with the default
    # crates-io the overlay bug in rust-lang/cargo#17196 fails the run. Keeping
    # this aligned with the pipeline also means a local repro matches CI.
    package.add_argument("--registry", default="Mxc-Azure-Feed")
    package.set_defaults(func=cmd_package)

    verify_order = sub.add_parser(
        "verify-order",
        help="assert crateOrder matches the packaged dependency graph",
    )
    verify_order.add_argument("--order-file", required=True)
    verify_order.add_argument("--expected", required=True)
    verify_order.set_defaults(func=cmd_verify_order)

    stage = sub.add_parser(
        "stage",
        help="copy one crate into a clean ESRP input directory",
    )
    stage.add_argument("--order-file", required=True)
    stage.add_argument("--crate", required=True)
    stage.add_argument("--out-dir", required=True)
    stage.set_defaults(func=cmd_stage)

    order = sub.add_parser(
        "order",
        help="print or validate the leaf-first publish order",
    )
    order.add_argument("--manifest-path", default="src/Cargo.toml")
    order.add_argument(
        "--format",
        choices=["plain", "yaml", "python"],
        default="plain",
        help="yaml emits lines ready to paste into Publish.CratesIo.Job.yml",
    )
    order.add_argument(
        "--check",
        action="store_true",
        help="validate CRATES against cargo metadata and print nothing else",
    )
    order.add_argument(
        "--derive",
        action="store_true",
        help=(
            "compute a fresh order from the dependency graph instead of "
            "printing CRATES; use when adding a crate, and update CRATES and "
            "the template's crateOrder together"
        ),
    )
    order.set_defaults(func=cmd_order)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
