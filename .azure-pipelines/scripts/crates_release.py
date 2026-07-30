#!/usr/bin/env python3
"""crates.io release helper for the `mxc-sdk` crate closure, ESRP edition.

MXC publishes crates through ESRP Release under the official
`microsoft-oss-releases` account. ESRP accepts pre-built `.crate` files, so this
repository never handles a `CARGO_REGISTRY_TOKEN`. See:
https://eng.ms/docs/microsoft-security/identity/trust-and-security-services/tss-release-distribute/tss-release-esrp-parent/oss-publishing/releasing-open-source/cratesio

ESRP does not sort a multi-crate dependency graph. The pipeline publishes one
crate at a time in leaf-first order. Before a dependent crate is submitted, this
helper confirms that every first-party dependency exists on the real crates.io
sparse index with the checksum produced by the same official build.

Subcommands
-----------
package       Validate and package the complete first-party closure, then write
              `.crate` files and release-order.json.

verify-order  Assert that the pipeline's compile-time crate order exactly
              matches the packaged order and its dependency graph.

probe         Confirm the release pool can read the crates.io sparse index.

stage         Copy one `.crate` file into a clean directory for an ESRP task.

verify-dependencies
              Confirm every first-party dependency of one packaged crate exists
              on crates.io with the exact packaged checksum.

status        Set the pipeline's `crateAlreadyPublished` variable after checking
              whether the exact packaged crate is already on crates.io.

wait          Poll crates.io until the exact packaged crate is visible before
              the release continues to any dependent crate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Current Cargo package names in leaf-first order. These names remain
# provisional until the public naming scheme is approved; publishCrates defaults
# to false in 1ES.Release.yml.
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
    "appcontainer_common",
    "isolation_session_bindings",
    "isolation_session_common",
    "windows_sandbox_common",
    "windows_sandbox_lifecycle",
    "wslc_common",
    "mxc_engine",
    "mxc-sdk",
]

CRATES_IO_SPARSE_INDEX = "https://index.crates.io"
PROPAGATION_TIMEOUT = 300
PROPAGATION_POLL = 5


def _sparse_index_path(name: str) -> str:
    """Return the crates.io sparse-index path for a package name."""
    name = name.lower()
    if len(name) == 1:
        return f"1/{name}"
    if len(name) == 2:
        return f"2/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def _index_request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={"User-Agent": "mxc-crates-release/1.0"},
    )


def _published_releases(crate: str) -> dict[str, dict]:
    """Return crates.io sparse-index records for `crate`, keyed by version."""
    url = f"{CRATES_IO_SPARSE_INDEX}/{_sparse_index_path(crate)}"
    try:
        with urllib.request.urlopen(_index_request(url), timeout=30) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        raise

    releases: dict[str, dict] = {}
    for line in body.splitlines():
        line = line.strip()
        if line:
            record = json.loads(line)
            releases[record["vers"]] = record
    return releases


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


def _published_matches(order_file: str, entry: dict) -> bool:
    """Return whether crates.io has this exact crate; reject conflicts."""
    record = _published_releases(entry["name"]).get(entry["version"])
    if record is None:
        return False
    if record.get("yanked", False):
        raise RuntimeError(
            f"{entry['name']} {entry['version']} exists on crates.io but is yanked"
        )

    expected_checksum = _sha256(_crate_file(order_file, entry))
    actual_checksum = record.get("cksum")
    if actual_checksum != expected_checksum:
        raise RuntimeError(
            f"{entry['name']} {entry['version']} already exists on crates.io "
            f"with checksum {actual_checksum}, but this build packaged "
            f"{expected_checksum}"
        )
    return True


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
    package_args = [
        "cargo",
        "package",
        "--no-verify",
        "--allow-dirty",
        "--registry",
        "crates-io",
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
        shutil.copy2(source, os.path.join(out_dir, crate_file))
        ordered.append(
            {
                "name": crate,
                "version": version,
                "file": crate_file,
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
    expected = json.loads(args.expected)
    if packaged != expected:
        print(
            "Crate order mismatch between the pipeline `crateOrder` parameter "
            "and the packaged release-order.json."
        )
        print(f"  pipeline crateOrder : {expected}")
        print(f"  release-order.json  : {packaged}")
        return 1

    positions = {crate: index for index, crate in enumerate(packaged)}
    for entry in entries:
        if "dependencies" not in entry:
            print(f"Crate {entry['name']} is missing dependency metadata.")
            return 1
        for dependency in entry["dependencies"]:
            if dependency not in positions:
                print(
                    f"Crate {entry['name']} depends on unpackaged crate "
                    f"{dependency}."
                )
                return 1
            if positions[dependency] >= positions[entry["name"]]:
                print(
                    f"Crate {entry['name']} appears before dependency "
                    f"{dependency}."
                )
                return 1

    print(f"Crate order verified ({len(packaged)} crates, leaf-first).")
    return 0


def cmd_probe(_args: argparse.Namespace) -> int:
    url = f"{CRATES_IO_SPARSE_INDEX}/config.json"
    try:
        with urllib.request.urlopen(_index_request(url), timeout=30) as response:
            config = json.load(response)
        if "dl" not in config:
            print(f"FAIL  crates.io index config at {url} has no download URL")
            return 1
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
    ) as error:
        print(
            "FAIL  cannot read the crates.io sparse index. Allow read-only "
            f"HTTPS egress to index.crates.io on the release pool: {error}"
        )
        return 1

    print(f"OK    crates.io sparse index is reachable at {url}")
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
    shutil.copy2(source, os.path.join(out_dir, entry["file"]))
    print(
        f"Staged {entry['file']} ({args.crate} {entry['version']}) "
        f"into {out_dir} for ESRP."
    )
    return 0


def cmd_verify_dependencies(args: argparse.Namespace) -> int:
    entries = _load_order(args.order_file)
    entry = next(
        (item for item in entries if item["name"] == args.crate),
        None,
    )
    if entry is None:
        print(f"Crate {args.crate!r} not found in {args.order_file}")
        return 1
    by_name = {item["name"]: item for item in entries}

    dependencies = entry.get("dependencies")
    if dependencies is None:
        print(f"Crate {args.crate!r} has no dependency metadata")
        return 1
    if not dependencies:
        print(f"OK    {args.crate} has no first-party crate dependencies.")
        return 0

    for dependency in dependencies:
        dependency_entry = by_name.get(dependency)
        if dependency_entry is None:
            print(
                f"FAIL  {args.crate} depends on unpackaged crate {dependency}"
            )
            return 1
        try:
            published = _published_matches(args.order_file, dependency_entry)
        except (
            RuntimeError,
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
            OSError,
        ) as error:
            print(f"FAIL  cannot validate dependency {dependency}: {error}")
            return 1
        if not published:
            print(
                f"FAIL  {args.crate} requires {dependency} "
                f"{dependency_entry['version']}, but that exact package is "
                "not on crates.io"
            )
            return 1
        print(
            f"OK    {dependency} {dependency_entry['version']} is on crates.io "
            "with the packaged checksum."
        )

    print(
        f"=== verified {len(dependencies)} first-party dependencies for "
        f"{args.crate} ==="
    )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    entry = _entry_for_crate(args.order_file, args.crate)
    if entry is None:
        print(f"Crate {args.crate!r} not found in {args.order_file}")
        return 1
    try:
        published = _published_matches(args.order_file, entry)
    except (
        RuntimeError,
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        OSError,
    ) as error:
        print(f"FAIL  cannot check {args.crate} on crates.io: {error}")
        return 1

    value = "true" if published else "false"
    print(f"##vso[task.setvariable variable=crateAlreadyPublished]{value}")
    if published:
        print(
            f"OK    {entry['name']} {entry['version']} is already on crates.io "
            "with the packaged checksum."
        )
    else:
        print(
            f"INFO  {entry['name']} {entry['version']} is not yet on crates.io."
        )
    return 0


def cmd_wait(args: argparse.Namespace) -> int:
    entry = _entry_for_crate(args.order_file, args.crate)
    if entry is None:
        print(f"Crate {args.crate!r} not found in {args.order_file}")
        return 1
    crate, version = entry["name"], entry["version"]

    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        try:
            if _published_matches(args.order_file, entry):
                print(
                    f"OK    {crate} {version} is live on crates.io with the "
                    "packaged checksum."
                )
                return 0
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
            print(
                f"WARN  crates.io index unreachable for {crate}: "
                f"{error}; retrying"
            )
        except (RuntimeError, json.JSONDecodeError, OSError) as error:
            print(f"FAIL  cannot validate {crate}: {error}")
            return 1
        time.sleep(args.poll)

    print(
        f"##vso[task.logissue type=error]{crate} {version} was not confirmed "
        f"on crates.io within {args.timeout}s. Stopping before publishing a "
        "dependent crate."
    )
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    package = sub.add_parser(
        "package",
        help="validate and cargo package the complete closure",
    )
    package.add_argument("--manifest-path", default="src/Cargo.toml")
    package.add_argument("--out-dir", required=True)
    package.set_defaults(func=cmd_package)

    verify_order = sub.add_parser(
        "verify-order",
        help="assert crateOrder matches the packaged dependency graph",
    )
    verify_order.add_argument("--order-file", required=True)
    verify_order.add_argument("--expected", required=True)
    verify_order.set_defaults(func=cmd_verify_order)

    probe = sub.add_parser(
        "probe",
        help="confirm the release pool can read the crates.io sparse index",
    )
    probe.set_defaults(func=cmd_probe)

    stage = sub.add_parser(
        "stage",
        help="copy one crate into a clean ESRP input directory",
    )
    stage.add_argument("--order-file", required=True)
    stage.add_argument("--crate", required=True)
    stage.add_argument("--out-dir", required=True)
    stage.set_defaults(func=cmd_stage)

    dependencies = sub.add_parser(
        "verify-dependencies",
        help="verify one crate's first-party dependencies on crates.io",
    )
    dependencies.add_argument("--order-file", required=True)
    dependencies.add_argument("--crate", required=True)
    dependencies.set_defaults(func=cmd_verify_dependencies)

    status = sub.add_parser(
        "status",
        help="set whether the exact packaged crate is already on crates.io",
    )
    status.add_argument("--order-file", required=True)
    status.add_argument("--crate", required=True)
    status.set_defaults(func=cmd_status)

    wait = sub.add_parser(
        "wait",
        help="poll crates.io for the exact packaged crate",
    )
    wait.add_argument("--order-file", required=True)
    wait.add_argument("--crate", required=True)
    wait.add_argument("--timeout", type=int, default=PROPAGATION_TIMEOUT)
    wait.add_argument("--poll", type=int, default=PROPAGATION_POLL)
    wait.set_defaults(func=cmd_wait)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
