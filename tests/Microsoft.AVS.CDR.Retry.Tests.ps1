BeforeAll {
    Import-Module "$PSScriptRoot/../Microsoft.AVS.CDR/Microsoft.AVS.CDR.psd1" -Force
}

Describe 'CDR throttling recovery for <Operation>' -ForEach @(
    @{ Operation = 'Install-PSResourcePinned'; Acquisition = 'Install-PSResource' }
    @{ Operation = 'Install-PSResourceDependencies'; Acquisition = 'Install-PSResource' }
    @{ Operation = 'Save-PSResourcePinned'; Acquisition = 'Save-PSResource' }
) {
    BeforeEach {
        InModuleScope Microsoft.AVS.CDR {
            Mock Build-RemoteDependencyGraph {
                param($ModuleName, $ModuleVersion, $Graph)
                $key = "$ModuleName@$ModuleVersion"
                $Graph[$key] = [DependencyGraphNode]::new(
                    $ModuleName, $ModuleVersion, @(), $false, 'TestRepo', $null)
                $key
            }
        }
        Mock Find-PSResourceDependencies -ModuleName Microsoft.AVS.CDR {
            [pscustomobject]@{ Name = 'Retry.Module'; Version = '1.0.0'; Repository = 'TestRepo' }
        }
        Mock Get-InstalledPSResource -ModuleName Microsoft.AVS.CDR { }
        Mock Start-Sleep -ModuleName Microsoft.AVS.CDR { }

        $commandParams = @{ Repository = 'TestRepo' }
        if ($Operation -eq 'Install-PSResourceDependencies') {
            $commandParams.ManifestPath = Join-Path $TestDrive 'Retry.Module.psd1'
        }
        else {
            $commandParams.Name = 'Retry.Module'
            $commandParams.RequiredVersion = '1.0.0'
        }
        if ($Operation -eq 'Save-PSResourcePinned') {
            $commandParams.Path = $TestDrive
        }
    }

    It 'recovers from the reported PSResourceGet 429 error' {
        InModuleScope Microsoft.AVS.CDR -Parameters @{
            Operation = $Operation; Acquisition = $Acquisition; CommandParams = $commandParams
        } {
            $script:acquisitionAttempts = 0
            Mock $Acquisition {
                $script:acquisitionAttempts++
                if ($script:acquisitionAttempts -lt 3) {
                    Write-Error "Response status code does not indicate success: 429 (Too Many Requests)."
                }
                'acquired'
            }

            $result = @(& $Operation @CommandParams -WarningVariable retryWarnings)

            $result | Should -Be @('acquired')
            $retryWarnings.Count | Should -Be 2
            $retryWarnings[0] | Should -BeLike '*Retry.Module*1.0.0*429*2 seconds*'
            Should -Invoke $Acquisition -Times 3 -Exactly -ParameterFilter {
                $Name -eq 'Retry.Module' -and $Version -eq '1.0.0' -and
                $Repository -eq 'TestRepo' -and $SkipDependencyCheck -and
                $ErrorAction -eq 'Stop'
            }
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 2 }
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 4 }
        }
    }

    It 'stops after three retries and preserves the final failure' {
        InModuleScope Microsoft.AVS.CDR -Parameters @{
            Operation = $Operation; Acquisition = $Acquisition; CommandParams = $commandParams
        } {
            $script:acquisitionAttempts = 0
            Mock $Acquisition {
                $script:acquisitionAttempts++
                throw "Response status code does not indicate success: 429 (Too Many Requests). Attempt $script:acquisitionAttempts"
            }

            { & $Operation @CommandParams } | Should -Throw '*429*Attempt 4'
            Should -Invoke $Acquisition -Times 4 -Exactly
            Should -Invoke Start-Sleep -Times 3 -Exactly
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 8 }
        }
    }

    It 'does not retry a permanent or unrelated failure: <Failure>' -ForEach @(
        @{ Failure = 'Response status code does not indicate success: 401 (Unauthorized).' }
        @{ Failure = 'Response status code does not indicate success: 404 (Not Found).' }
        @{ Failure = 'Response status code does not indicate success: 500 (Internal Server Error).' }
        @{ Failure = 'Access denied to /modules/429/Retry.Module' }
    ) {
        InModuleScope Microsoft.AVS.CDR -Parameters @{
            Operation = $Operation; Acquisition = $Acquisition; CommandParams = $commandParams; Failure = $Failure
        } {
            $script:acquisitionFailure = $Failure
            Mock $Acquisition { throw $script:acquisitionFailure }

            { & $Operation @CommandParams } | Should -Throw -ExpectedMessage $Failure
            Should -Invoke $Acquisition -Times 1 -Exactly
            Should -Invoke Start-Sleep -Times 0
        }
    }

    It 'does not wait or warn on first-attempt success' {
        InModuleScope Microsoft.AVS.CDR -Parameters @{
            Operation = $Operation; Acquisition = $Acquisition; CommandParams = $commandParams
        } {
            Mock $Acquisition { 'acquired' }

            @(& $Operation @CommandParams -WarningVariable retryWarnings) | Should -Be @('acquired')
            $retryWarnings.Count | Should -Be 0
            Should -Invoke $Acquisition -Times 1 -Exactly
            Should -Invoke Start-Sleep -Times 0
        }
    }
}

Describe 'CDR structured throttling detection' {
    It 'recognizes a nested HTTP 429 without relying on the error message' {
        InModuleScope Microsoft.AVS.CDR {
            $script:acquisitionAttempts = 0
            Mock Start-Sleep { }
            Mock Install-PSResource {
                $script:acquisitionAttempts++
                if ($script:acquisitionAttempts -eq 1) {
                    $httpError = [System.Net.Http.HttpRequestException]::new(
                        'Localized throttling message', $null, [System.Net.HttpStatusCode]::TooManyRequests)
                    throw [System.InvalidOperationException]::new('Acquisition failed', $httpError)
                }
                'acquired'
            }

            $result = Invoke-CdrPSResourceWithRetry -CommandName Install-PSResource -Parameters @{
                Name = 'Retry.Module'; Version = '1.0.0'
            }

            $result | Should -BeExactly 'acquired'
            Should -Invoke Install-PSResource -Times 2 -Exactly
            Should -Invoke Start-Sleep -Times 1 -Exactly
        }
    }

    It 'recognizes an HTTP response status on a web exception' {
        InModuleScope Microsoft.AVS.CDR {
            $script:acquisitionAttempts = 0
            Mock Start-Sleep { }
            Mock Save-PSResource {
                $script:acquisitionAttempts++
                if ($script:acquisitionAttempts -eq 1) {
                    $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
                    throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Localized response', $response)
                }
                'acquired'
            }

            Invoke-CdrPSResourceWithRetry -CommandName Save-PSResource -Parameters @{
                Name = 'Retry.Module'; Version = '1.0.0'; Path = $TestDrive
            } | Should -BeExactly 'acquired'
            Should -Invoke Save-PSResource -Times 2 -Exactly
        }
    }
}
