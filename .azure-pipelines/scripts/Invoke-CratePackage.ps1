# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Packages the crates.io release closure into .crate files and copies them
# where the artifact task expects them.
#
# Called by Package.Crates.Job.yml.  Runnable by hand from the repo root to
# reproduce exactly what the packaging leg does:
#
#   pwsh .azure-pipelines/scripts/Invoke-CratePackage.ps1 -OutDir out/crates

[CmdletBinding()]
param
(
    [Parameter(Mandatory)]
    [string] $OutDir,

    # The feed that replaced crates-io on this agent.  Omit to package against
    # whatever the ambient cargo config resolves, which is what a local run
    # without source replacement wants.
    [string] $Registry,

    [string] $ManifestPath = 'src/Cargo.toml'
)

$ErrorActionPreference = 'Stop'

$crates = & (Join-Path $PSScriptRoot 'Get-CrateOrder.ps1') -ManifestPath $ManifestPath

$packageArgs = @()
foreach ($crate in $crates)
{
    $packageArgs += '-p'
    $packageArgs += $crate
}

if ($Registry)
{
    $packageArgs += '--registry'
    $packageArgs += $Registry
}

Write-Host "packaging $($crates.Count) crates"

# One cargo call for the whole closure: cargo resolves the crates against each
# other inside a temporary overlay, which is the only way to package a crate
# whose path dependencies are not on a registry yet.
cargo package --manifest-path $ManifestPath @packageArgs
if ($LASTEXITCODE -ne 0) { throw "cargo package failed with exit $LASTEXITCODE" }

$metadata = cargo metadata --format-version 1 --no-deps --manifest-path $ManifestPath | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed with exit $LASTEXITCODE" }

$packageDir = Join-Path $metadata.target_directory 'package'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$found = @(Get-ChildItem -Path $packageDir -Filter '*.crate' -File)
if ($found.Count -ne $crates.Count) { throw "packaged $($crates.Count) crates but found $($found.Count) .crate files in $packageDir" }

Copy-Item $found.FullName -Destination $OutDir
Write-Host "collected $($found.Count) crates into $OutDir"
