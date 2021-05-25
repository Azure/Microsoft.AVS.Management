#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$srcAbsPath,
    [Parameter(Mandatory=$true)][string]$dstAbsPath
)
Write-Output "----START:  $(Split-Path -Path "$PSCommandPath" -Leaf)----"

[bool]$isValidModulePath=(Test-Path -Path "$srcAbsPath")
[bool]$isValidArtifactPath=(Test-Path -Path "$dstAbsPath")
if (!$isValidModulePath) {
    Write-Error -Message "Invalid source path $srcAbsPath"
    Throw "One or more paths could not be validated"
}else {
    Write-Output "Validated source path: $srcAbsPath"
}
if (!$isValidArtifactPath) {
    Write-Output "Destination path $dstAbsPath does not exist"
    Write-Output "Creating path $dstAbsPath"
    New-Item -ItemType Directory -Path "$dstAbsPath"
}else {
    Write-Error -Message "Destination path $dstAbsPath already exists."
    Throw "Must provide a new destination path for copy"
}

Write-Output "Copying contents of $srcAbsPath to $dstAbsPath"
Copy-Item -Path "$srcAbsPath" -Destination "$dstAbsPath" -Recurse

