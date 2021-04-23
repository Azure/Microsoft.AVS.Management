#!/usr/bin/pwsh
## See https://msazure.visualstudio.com/One/_git/Azure-Dedicated-AVS?path=%2Ftools%2FCDPxHelpers%2FgenerateCustomVersion.ps1
param (
    [string]$versionTag = "",
    [Parameter(Mandatory=$true)][int]$major = "",
    [Parameter(Mandatory=$true)][int]$minor = ""
)

$buildNumber = ""
$revision = $env:CDP_DEFINITION_BUILD_COUNT # Monotonically increasing revision number, always increases by simply 
                                            # counting the number of builds run for this build definition.

if (($null -ne $env:CDP_COMMIT_ID) -and ($env:CDP_COMMIT_ID -ne "")) {
    $commit = ${env:CDP_COMMIT_ID}
} elseif (($null -ne $env:BUILD_SOURCEVERSION) -and ($env:BUILD_SOURCEVERSION -ne "*")) {
    $commit = ${env:BUILD_SOURCEVERSION}.substring(0,8)
} else {
    $var = (Get-ChildItem env:*).GetEnumerator() | Sort-Object Name
    Foreach ($v in $var) {
        Write-Host $v.Name": "$v.Value
    }
    throw "Missing some commit hash environment variables.  Please check the environment dump."
}

if (($null -ne $versionTag) -and ($versionTag -ne "")) {
    $versionTag = "-$versionTag"
}

$buildNumber = "$major.$minor.$revision$versionTag-$commit"

[Environment]::SetEnvironmentVariable("CustomBuildNumber",$buildNumber,"User")
[Environment]::SetEnvironmentVariable("BUILD_BUILDNUMBER",$buildNumber,"User")
Write-Host "##vso[build.updatebuildnumber]${buildNumber}"

$generatedVerFile = [IO.Path]::Combine($env:CDP_USER_SOURCE_FOLDER_CONTAINER_PATH, ".pipelines", ".generatedVersion")
Write-Host "FilePath: $generatedVerFile"
$buildNumber | Out-File $generatedVerFile
Get-Content $generatedVerFile