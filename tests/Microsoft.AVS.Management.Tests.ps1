BeforeAll {
    # Define the AVSAttribute class that Management module functions use
    # This is a minimal definition matching what's in Microsoft.AVS.Management/Classes.ps1
    if (-not ('AVSAttribute' -as [type])) {
        class AVSAttribute : Attribute {
            [bool]$UpdatesSDDC = $false
            [TimeSpan]$Timeout
            [bool]$AutomationOnly = $false
            AVSAttribute([int]$timeoutMinutes) { $this.Timeout = New-TimeSpan -Minutes $timeoutMinutes }
        }
    }

    if (-not ('VMware.VimAutomation.ViCore.Types.V1.Inventory.Folder' -as [type])) {
        Add-Type @"
namespace VMware.VimAutomation.ViCore.Types.V1.Inventory {
    public class Folder {}
}
"@
    }

    # Import the Management module
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.Management" "Microsoft.AVS.Management.psd1"
    Import-Module $modulePath -Force
}

AfterAll {
    # Clean up
    Get-Module Microsoft.AVS.Management -ErrorAction SilentlyContinue | Remove-Module -Force
}

Describe "Microsoft.AVS.Management Module" {
    Context "Module Loading" {
        It "Should import the module successfully" {
            $module = Get-Module Microsoft.AVS.Management
            $module | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Set-ToolsRepo" {
    BeforeAll {
        # Helper function to create SecureString from plain text for testing
        function ConvertTo-TestSecureString {
            param([string]$PlainText)
            return ConvertTo-SecureString -String $PlainText -AsPlainText -Force
        }
    }

    Context "Parameter Validation" {
        It "Should have ToolsURL as mandatory parameter" {
            $command = Get-Command Set-ToolsRepo
            $param = $command.Parameters['ToolsURL']
            $param.Attributes.Mandatory | Should -Contain $true
        }

        It "Should have ToolsURL parameter of type SecureString" {
            $command = Get-Command Set-ToolsRepo
            $param = $command.Parameters['ToolsURL']
            $param.ParameterType.Name | Should -Be 'SecureString'
        }

        It "Should have ValidateNotNullOrEmpty attribute on ToolsURL" {
            $command = Get-Command Set-ToolsRepo
            $param = $command.Parameters['ToolsURL']
            $validateAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
            $validateAttr | Should -Not -BeNullOrEmpty
        }

        It "Should have HelpMessage on ToolsURL parameter" {
            $command = Get-Command Set-ToolsRepo
            $param = $command.Parameters['ToolsURL']
            $paramAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $paramAttr.HelpMessage | Should -Not -BeNullOrEmpty
        }

        It "Should have AVSAttribute with 30 minute timeout" {
            $command = Get-Command Set-ToolsRepo
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr | Should -Not -BeNullOrEmpty
            $avsAttr.Timeout.TotalMinutes | Should -Be 30
        }

        It "Should have AVSAttribute with UpdatesSDDC set to false" {
            $command = Get-Command Set-ToolsRepo
            $avsAttr = $command.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'AVSAttribute' }
            $avsAttr.UpdatesSDDC | Should -Be $false
        }
    }

    Context "URL Pattern Validation" {
        It "Should throw for non-HTTP/HTTPS URL" {
            $secureUrl = ConvertTo-TestSecureString "ftp://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*ToolsURL must be a valid HTTP or HTTPS URL*"
        }

        It "Should throw for URL without protocol" {
            $secureUrl = ConvertTo-TestSecureString "example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*ToolsURL must be a valid HTTP or HTTPS URL*"
        }

        It "Should throw for file:// URL" {
            $secureUrl = ConvertTo-TestSecureString "file:///path/to/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*ToolsURL must be a valid HTTP or HTTPS URL*"
        }

        It "Should proceed past URL validation for valid HTTP URL" {
            Mock Invoke-WebRequest { throw "Expected network call" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "http://example.com/tools.zip"

            # Should fail at network request, not URL validation
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*"
        }

        It "Should proceed past URL validation for valid HTTPS URL" {
            Mock Invoke-WebRequest { throw "Expected network call" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            # Should fail at network request, not URL validation
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*"
        }

        It "Should proceed past URL validation for HTTPS URL with query parameters" {
            Mock Invoke-WebRequest { throw "Expected network call" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://storage.example.com/tools.zip?token=secret123&sig=abc"

            # Should fail at network request, not URL validation
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*"
        }
    }

    Context "URL Accessibility Validation" {
        It "Should throw when URL is not accessible" {
            Mock Invoke-WebRequest { throw "404 Not Found" } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://example.com/nonexistent.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Unable to access the provided URL*"
        }

        It "Should throw when URL returns non-200 status code" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 403 }
            } -ModuleName Microsoft.AVS.Management
            $secureUrl = ConvertTo-TestSecureString "https://example.com/forbidden.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*URL returned status code: 403*"
        }
    }

    Context "Temporary Directory Creation" {
        BeforeAll {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
        }

        It "Should throw when temporary directory cannot be created" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock New-Item { throw "Permission denied" } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to create temporary directory*"
        }
    }

    Context "File Download Validation" {
        BeforeAll {
            # Mock successful HEAD request
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            # Mock successful temp directory creation
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
        }

        It "Should throw when download fails" {
            Mock Invoke-WebRequest { throw "Download failed" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to download tools file*"
        }

        It "Should throw when downloaded file is empty" {
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 0 } } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Downloaded file is empty*"
        }
    }

    Context "Archive Extraction Validation" {
        BeforeAll {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when archive extraction fails" {
            Mock Expand-Archive { throw "Invalid archive" } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to extract tools archive*"
        }
    }

    Context "VMtools Directory Validation" {
        BeforeAll {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
        }

        It "Should throw when vmtools directory not found in archive" {
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                $null
            } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Unable to find vmtools directory*"
        }
    }

    Context "vSAN Datastore Validation" {
        BeforeAll {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test"; Name = "newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' -and $Path -match '^\.([\\/])newtools_' }

            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Join-Path { "$Path/$ChildPath" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like 'DS:*' }
        }

        It "Should throw when no vSAN datastores found" {
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                [PSCustomObject]@{ Name = "vmtools-12.3.0" }
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Datastore { $null } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*No vSAN datastores found*"
        }

        It "Should throw when Get-Datastore fails" {
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                [PSCustomObject]@{ Name = "vmtools-12.3.0" }
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Datastore { throw "Connection error" } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"
            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to retrieve vSAN datastores*"
        }
    }

    Context "SecureString Handling" {
        It "Should pass converted SecureString URL to HEAD request" {
            $capturedUri = $null
            Mock Invoke-WebRequest {
                $capturedUri = $Uri
                throw "Stop here for test"
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            $testUrl = "https://example.com/tools.zip?token=secret123"
            $secureUrl = ConvertTo-TestSecureString $testUrl

            try { Set-ToolsRepo -ToolsURL $secureUrl } catch { }

            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Uri -eq $testUrl -and $Method -eq 'Head'
            }
        }

        It "Should pass converted SecureString URL to download request" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }

            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }

            Mock Invoke-WebRequest { throw "Stop here" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }

            $testUrl = "https://example.com/tools.zip?token=secret123"
            $secureUrl = ConvertTo-TestSecureString $testUrl

            try { Set-ToolsRepo -ToolsURL $secureUrl } catch { }

            Should -Invoke Invoke-WebRequest -ModuleName Microsoft.AVS.Management -ParameterFilter {
                $Uri -eq $testUrl -and $OutFile
            }
        }
    }

    if (-not (Get-Module Microsoft.AVS.Management)) {
        Import-Module (Join-Path $PSScriptRoot ".." "Microsoft.AVS.Management" "Microsoft.AVS.Management.psd1") -Force
    }

    InModuleScope 'Microsoft.AVS.Management' {
        Context "Version and metadata decision logic (mock-only)" {
            BeforeAll {
                $script:originalTemp = $env:TEMP
                $script:originalTmp = $env:TMP
                $script:testTempDir = Join-Path $TestDrive 'temp'
                New-Item -Path $script:testTempDir -ItemType Directory -Force | Out-Null
                $env:TEMP = $script:testTempDir
                $env:TMP = $script:testTempDir

                function ConvertTo-TestSecureString {
                    param([string]$PlainText)
                    return ConvertTo-SecureString -String $PlainText -AsPlainText -Force
                }

                Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management

                # Shadow the real Get-EsxCli cmdlet with a plain function so Pester
                # can mock it without PowerCLI's VMHost[] type constraint blocking.
                function Get-EsxCli { param([switch]$V2, $VMHost) }

                function Initialize-SetToolsRepoScenarioMocks {
                    param(
                        [Parameter(Mandatory = $true)][string]$ToolsShortVersion,
                        [Parameter(Mandatory = $true)][string]$HighestExistingVersion,
                        [Parameter(Mandatory = $true)][bool]$VersionAlreadyExists
                    )

                    $script:toolsVersion = "vmtools-$ToolsShortVersion"
                    $script:tempRoot = Join-Path $TestDrive 'newtools_test'
                    $script:sourceDir = Join-Path $TestDrive "vmtools-$ToolsShortVersion"
                    $script:topLevelSourceDir = Join-Path $script:tempRoot 'vmware' 'apps' 'vmtools' 'windows64'
                    $script:destPath = "DS:/GuestStore/vmware/apps/vmtools/windows64"
                    $script:versionDestPath = "$script:destPath/$script:toolsVersion"
                    $script:highestExistingVersion = $HighestExistingVersion
                    $script:versionAlreadyExists = $VersionAlreadyExists

                    # Create fake extracted directory and metadata.json under $TestDrive
                    [System.IO.Directory]::CreateDirectory($script:sourceDir) | Out-Null
                    [System.IO.File]::WriteAllText((Join-Path $script:sourceDir 'metadata.json'), '{}')

                    # URL validation and download path are always mocked; no network access.
                    Mock Invoke-WebRequest {
                        if ($Method -eq 'Head') {
                            return [PSCustomObject]@{ StatusCode = 200 }
                        }

                        if ($OutFile) {
                            $parentPath = [System.IO.Path]::GetDirectoryName($OutFile)
                            if (-not [string]::IsNullOrEmpty($parentPath)) {
                                [System.IO.Directory]::CreateDirectory($parentPath) | Out-Null
                            }

                            [System.IO.File]::WriteAllText($OutFile, 'dummy')
                            return [PSCustomObject]@{ StatusCode = 200 }
                        }

                        return $null
                    } -ModuleName Microsoft.AVS.Management

                    Mock New-Item {
                        [PSCustomObject]@{ FullName = $script:tempRoot; Name = 'newtools_test' }
                    } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' -and $Path -match '^\.([\\/])newtools_' }

                    Mock New-Item {
                        [PSCustomObject]@{ FullName = $Path; Name = (Split-Path -Path $Path -Leaf) }
                    } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' -and $Path -like 'DS:/*' }

                    Mock Get-Item { [PSCustomObject]@{ Length = 4096 } } -ModuleName Microsoft.AVS.Management
                    Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
                    Mock Join-Path { "$Path/$ChildPath" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Path -like 'DS:*' }

                    Mock Test-Path {
                        switch ($Path) {
                            "$script:tempRoot/tools.zip" { return $true }
                            $script:destPath { return $true }
                            $script:versionDestPath { return $script:versionAlreadyExists }
                            $script:topLevelSourceDir { return $false }
                            default { return $true }
                        }
                    } -ModuleName Microsoft.AVS.Management

                    Mock Get-ChildItem {
                        param(
                            $Path,
                            $Filter,
                            [switch]$Directory,
                            [switch]$File,
                            [switch]$Recurse
                        )

                        # vmtools-* directory discovery: production passes
                        # <tmp>\vmware\apps\vmtools\windows64\vmtools-* with -Directory
                        if ($Directory -and $Path -like '*windows64*') {
                            return @([PSCustomObject]@{ Name = $script:toolsVersion; FullName = $script:sourceDir })
                        }

                        # Existing datastore versions used to compute highestExistingVersion
                        if ($Path -eq $script:destPath -and -not $Filter -and -not $Recurse -and -not $File) {
                            return @([PSCustomObject]@{ Name = "vmtools-$script:highestExistingVersion"; FullName = "$script:destPath/vmtools-$script:highestExistingVersion"; PSIsContainer = $true })
                        }

                        # Source metadata is present so update path is testable
                        if ($Path -eq $script:sourceDir -and $Filter -eq 'metadata.json') {
                            return @([PSCustomObject]@{ Name = 'metadata.json'; FullName = "$script:sourceDir\metadata.json" })
                        }

                        # Copied version folder metadata check after Copy-DatastoreItem
                        if ($Path -eq $script:versionDestPath -and $Filter -eq 'metadata.json') {
                            return @([PSCustomObject]@{ Name = 'metadata.json'; FullName = "$script:versionDestPath/metadata.json" })
                        }

                        return @()
                    } -ModuleName Microsoft.AVS.Management

                    $script:browser = New-Object psobject
                    Add-Member -InputObject $script:browser -MemberType ScriptMethod -Name SearchDatastore -Value {
                        param($path, $spec)
                        return [PSCustomObject]@{ File = @([PSCustomObject]@{ FriendlyName = 'GuestStore' }) }
                    } -Force

                    Mock Get-View { $script:browser } -ModuleName Microsoft.AVS.Management
                    Mock New-Object {
                        if ($TypeName -eq 'VMware.Vim.HostDatastoreBrowserSearchSpec') { return [PSCustomObject]@{ Query = @() } }
                        if ($TypeName -eq 'VMware.Vim.FolderFileQuery') { return [PSCustomObject]@{} }
                    } -ModuleName Microsoft.AVS.Management -ParameterFilter {
                        $TypeName -eq 'VMware.Vim.HostDatastoreBrowserSearchSpec' -or $TypeName -eq 'VMware.Vim.FolderFileQuery'
                    }

                    Mock Get-Datastore {
                        return @(
                            [PSCustomObject]@{
                                Name = 'vsanDatastore'
                                Id = 'Datastore-ds-123'
                                ExtensionData = [PSCustomObject]@{
                                    Browser = 'browser-1'
                                    Summary = [PSCustomObject]@{ Type = 'vsan'; Url = 'ds:///vmfs/volumes/vsanDatastore/' }
                                }
                            }
                        )
                    } -ModuleName Microsoft.AVS.Management

                    Mock Get-PSDrive { $null } -ModuleName Microsoft.AVS.Management
                    Mock New-PSDrive { [PSCustomObject]@{ Name = 'DS' } } -ModuleName Microsoft.AVS.Management
                    Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management

                    Mock Get-VMHost {
                        return @(
                            [PSCustomObject]@{
                                Name = 'esx1'
                                ExtensionData = [PSCustomObject]@{ Datastore = [PSCustomObject]@{ value = @('ds-123') } }
                            }
                        )
                    } -ModuleName Microsoft.AVS.Management

                    $script:setObj = New-Object psobject
                    Add-Member -InputObject $script:setObj -MemberType ScriptMethod -Name CreateArgs -Value { return @{ url = $null } } -Force
                    Add-Member -InputObject $script:setObj -MemberType ScriptMethod -Name invoke -Value { param($arguments) return $true } -Force
                    $script:esxcli = [PSCustomObject]@{
                        system = [PSCustomObject]@{
                            settings = [PSCustomObject]@{
                                gueststore = [PSCustomObject]@{
                                    repository = [PSCustomObject]@{ set = $script:setObj }
                                }
                            }
                        }
                    }
                    Mock Get-EsxCli {
                        param(
                            [switch]$V2,
                            [object]$VMHost
                        )

                        return $script:esxcli
                    } -ModuleName Microsoft.AVS.Management

                    Mock Copy-DatastoreItem { } -ModuleName Microsoft.AVS.Management
                }
            }

            AfterAll {
                $env:TEMP = $script:originalTemp
                $env:TMP = $script:originalTmp
            }

            It "Older version upload preserves top-level metadata.json" {
                # Validates: when incoming version is older than existing highest, top-level metadata is not overwritten.
                $IncomingVersion = '12.3.0'
                $ExistingVersion = '12.4.0'
                Initialize-SetToolsRepoScenarioMocks -ToolsShortVersion $IncomingVersion -HighestExistingVersion $ExistingVersion -VersionAlreadyExists $false
                $secureUrl = ConvertTo-TestSecureString 'https://example.com/tools.zip'

                { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Not -Throw

                Assert-MockCalled Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*windows64'
                }

                Assert-MockCalled Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 0 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*metadata.json'
                }
            }

            It "Newer version upload updates top-level metadata.json" {
                # Validates: when incoming version is newer than existing highest, top-level metadata update is performed once.
                $IncomingVersion = '12.4.0'
                $ExistingVersion = '12.3.0'
                Initialize-SetToolsRepoScenarioMocks -ToolsShortVersion $IncomingVersion -HighestExistingVersion $ExistingVersion -VersionAlreadyExists $true
                $secureUrl = ConvertTo-TestSecureString 'https://example.com/tools.zip'

                { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Not -Throw

                Assert-MockCalled Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 1 -Exactly -Scope It -ParameterFilter {
                    $Destination -like '*metadata.json'
                }
            }

            It "Version already exists skips copy and overwrite" {
                # Validates: when target version folder already exists, no copy operation is performed.
                $IncomingVersion = '12.4.0'
                $ExistingVersion = '12.4.0'
                Initialize-SetToolsRepoScenarioMocks -ToolsShortVersion $IncomingVersion -HighestExistingVersion $ExistingVersion -VersionAlreadyExists $true
                $secureUrl = ConvertTo-TestSecureString 'https://example.com/tools.zip'

                { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Not -Throw

                Assert-MockCalled Copy-DatastoreItem -ModuleName Microsoft.AVS.Management -Times 0 -Exactly -Scope It
            }
        }
    }

    Context "Error Handling" {
        It "Should wrap original error in descriptive message" {
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock New-Item { throw "Permission denied" } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            { Set-ToolsRepo -ToolsURL $secureUrl } |
                Should -Throw -ExpectedMessage "*Failed to create temporary directory*Permission denied*"
        }

        It "Should re-throw after catching to propagate error" {
            Mock Invoke-WebRequest { throw "Network error" } -ModuleName Microsoft.AVS.Management

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            { Set-ToolsRepo -ToolsURL $secureUrl } | Should -Throw
        }
    }

    Context "PSDrive Cleanup" {
        It "Should attempt PSDrive cleanup even when datastore processing fails" {
            $IncomingVersion = '12.3.0'
            Mock Invoke-WebRequest {
                [PSCustomObject]@{ StatusCode = 200 }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Method -eq 'Head' }
            Mock New-Item {
                [PSCustomObject]@{ FullName = "/tmp/newtools_test" }
            } -ModuleName Microsoft.AVS.Management -ParameterFilter { $ItemType -eq 'Directory' }
            Mock Invoke-WebRequest { } -ModuleName Microsoft.AVS.Management -ParameterFilter { $OutFile }
            Mock Test-Path { $true } -ModuleName Microsoft.AVS.Management
            Mock Get-Item { [PSCustomObject]@{ Length = 1024 } } -ModuleName Microsoft.AVS.Management
            Mock Expand-Archive { } -ModuleName Microsoft.AVS.Management
            Mock Get-ChildItem {
                param($Path, $Filter, [switch]$Directory, [switch]$File, [switch]$Recurse)
                [PSCustomObject]@{ Name = "vmtools-$IncomingVersion" }
            } -ModuleName Microsoft.AVS.Management
            Mock Get-Datastore {
                [PSCustomObject]@{
                    Name = "vsanDatastore"
                    extensionData = [PSCustomObject]@{ Summary = [PSCustomObject]@{ Type = 'vsan' } }
                }
            } -ModuleName Microsoft.AVS.Management
            Mock Get-PSDrive { $true } -ModuleName Microsoft.AVS.Management
            Mock Remove-PSDrive { } -ModuleName Microsoft.AVS.Management
            Mock New-PSDrive { throw "PSDrive creation failed" } -ModuleName Microsoft.AVS.Management -ParameterFilter { $Name -eq 'DS' }

            $secureUrl = ConvertTo-TestSecureString "https://example.com/tools.zip"

            try { Set-ToolsRepo -ToolsURL $secureUrl } catch { }

            # Verify cleanup was attempted
            Should -Invoke Remove-PSDrive -ModuleName Microsoft.AVS.Management -ParameterFilter { $Name -eq 'DS' }
        }
    }
}
