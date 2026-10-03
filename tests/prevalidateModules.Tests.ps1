BeforeAll {
    $prevalidationScript = Join-Path $PSScriptRoot 'prevalidateModules.ps1'

    function Invoke-ScriptAnalyzer { }
}

Describe 'Module prevalidation' {
    BeforeEach {
        $previousWorkingDirectory = $env:SYSTEM_DEFAULTWORKINGDIRECTORY
        $previousSkipIntegrationTests = $env:SKIP_INTEGRATION_TESTS
        $previousFeedSettings = $Global:FeedSettings
        $env:SYSTEM_DEFAULTWORKINGDIRECTORY = $TestDrive

        $moduleDirectory = Join-Path $TestDrive 'Fixture.Module'
        New-Item $moduleDirectory -ItemType Directory -Force | Out-Null
        $scriptPath = Join-Path $moduleDirectory 'Example.ps1'
        New-PSScriptFileInfo -Path $scriptPath -Version '1.0.0' -Author 'Test' -Description 'Test script'
        Set-Content (Join-Path $moduleDirectory 'Fixture.Module.psm1') ''
        $manifestPath = Join-Path $moduleDirectory 'Fixture.Module.psd1'
        New-ModuleManifest -Path $manifestPath -RootModule 'Fixture.Module.psm1' -ModuleVersion '1.0.0'

        Mock Invoke-ScriptAnalyzer { }
    }

    AfterEach {
        $env:SYSTEM_DEFAULTWORKINGDIRECTORY = $previousWorkingDirectory
        $env:SKIP_INTEGRATION_TESTS = $previousSkipIntegrationTests
        $Global:FeedSettings = $previousFeedSettings
        Remove-Item $moduleDirectory -Recurse -Force
        $testsDirectory = Join-Path $TestDrive 'tests'
        if (Test-Path $testsDirectory) {
            Remove-Item $testsDirectory -Recurse -Force
        }
    }

    It 'accepts valid script metadata and a valid module manifest' {
        & $prevalidationScript 'Fixture.Module' | Should -Contain 'SUCCESS: completed pre-validation'
    }

    It 'does not require a script analyzer in the module build job' {
        Mock Invoke-ScriptAnalyzer { throw 'PSScriptAnalyzer belongs in the 1ES source analysis job.' }

        & $prevalidationScript 'Fixture.Module' | Should -Contain 'SUCCESS: completed pre-validation'
    }

    It 'still reports invalid script metadata' {
        Set-Content $scriptPath 'Write-Output "Missing script metadata"'

        & $prevalidationScript 'Fixture.Module' | Should -Contain $false
    }

    It 'still rejects an invalid module manifest' {
        Set-Content $manifestPath "@{ ModuleVersion = 'invalid' }"

        { & $prevalidationScript 'Fixture.Module' -ErrorAction Continue 2>$null } |
            Should -Throw '*Prevalidation failed*'
    }

    It 'still fails when the module Pester suite reports a failure' {
        $testsDirectory = Join-Path $TestDrive 'tests'
        New-Item $testsDirectory -ItemType Directory | Out-Null
        Set-Content (Join-Path $testsDirectory 'Fixture.Module.Tests.ps1') ''
        Mock Invoke-Pester {
            [PSCustomObject]@{ FailedCount = 1; PassedCount = 0 }
        } -ParameterFilter {
            $Configuration.Run.Path.Value -eq (Join-Path $TestDrive 'tests/Fixture.Module.Tests.ps1')
        }

        { & $prevalidationScript 'Fixture.Module' -ErrorAction Continue 2>$null } |
            Should -Throw '*Prevalidation failed*'
    }
}
