function Get-SecretFromKV 
{
Param
    (
      [Parameter(Mandatory = $true)]
      [string]
      $KeyvaultName,

      [Parameter(Mandatory = $true)]
      [string]
      $SecretName
      )
    Write-Host "The key vault is $KeyvaultName and the secret is $SecretName"
    $secret = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $SecretName).SecretValue
    return $secret
}


function Set-TestEnvironmentVariables 
{
    Connect-AzAccount
    Set-AzContext -Subscription "23995e3f-96a0-4b7a-95a0-c77f91054b52"
    $env:KeyvaultName = "kv-4febfd10-f5c89d1442f7"
    $env:ServerSecretName = "tntnmanagementserver"
    $env:PasswordSecretName = "vcsa"
    $env:tntMgmtNetwork = '10.0.0.0/22'
}

function Connect-SsoServer
{
   #$env:PSModulePath = Join-Path -Path $PSHOME -ChildPath 'Modules'al' -Password $env:ServiceUserPassword
   #$env:PSModulePath = "$env:PSModulePath;$(Split-Path -Path $PSModuleInfo.ModuleBase -Pare
   # The $env:ServiceUserPassword must be set on the container at start up (adminstrator password to tenant vCenter)
   #$vCenterIP = $env:tntMgmtNetwork -replace $env:tntMgmtNetwork.split('.')[-1], '2' 
   # $ServiceUserPassword = Get-SecretFromKV $env:KeyvaultName $env:PasswordSecretName
   
   #$connectedServer= Connect-SsoAdminServer -Server $vCenterIP -User 'administrator@vsphere.local' -Password $ServiceUserPassword -SkipCertificateCheck
	retur
  # return $connectedServer
}


function Connect-vCenterServer
{

   #$env:PSModulePath = Join-Path -Path $PSHOME -ChildPath 'Modules'al' -Password $env:ServiceUserPassword
   #$env:PSModulePath = "$env:PSModulePath;$(Split-Path -Path $PSModuleInfo.ModuleBase -Pare
   # The $env:ServiceUserPassword must be set on the container at start up (adminstrator password to tenant vCenter)
   #$vCenterIP = $env:tntMgmtNetwork -replace $env:tntMgmtNetwork.split('.')[-1], '2' 
   #Set-PowerCLIConfiguration -InvalidCertificateAction Ignore
   #$connectedServer = Connect-VIServer -Server $vCenterIP 

    return "connected"
   #return $connectedServer
}

function Set-AvsDrsClusterGroup {
    [CmdletBinding(PositionalBinding = $false)]
    Param
    (   
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DRSGroupName,
    
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $VMList,
    
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $VMHostList,
  
        [switch] $Add = $false,
        [switch] $Remove = $false
  
    )
  
        if ($Add -And $Remove) {
          $result = "You can't add and remove at the same time. Try again with just one flag"
          return $result
        } elseif ($Add -eq $false -and $Remove -eq $false) {
          $result = "Nothing was done. Please select with either -Add or -Remove"
        }
  
        Set-TestEnvironmentVariables
        Connect-vCenterServer
  
        if ($VMList -And $VMHostList) {
          $result = "Only update the parameter for your DRS Group. Either VM or Host. Nothing done."
          return $result
        } ElseIf ($VMList) {
          If ($Add) {
            Write-Host "Add triggered and VMList: $VMList"
            $result = Set-DrsClusterGroup -DrsClusterGroup $DRSGroupName -VM $VMList -Add 
            return $result
          } ElseIf ($Remove) {
            $result = Set-DrsClusterGroup -DrsClusterGroup $DRSGroupName -VM $VMList -Remove
            Write-Host "Remove triggered and VMList: $VMList"
            return $result
          }
        } ElseIf ($VMHostList) {
          If ($Add) {
            $result = Set-DrsClusterGroup -DrsClusterGroup $DRSGroupName -VMHost $VMHostList -Add 
            Write-Host "Add triggered and VMHostList: $VMHostList"
            $result = Get-DrsClusterGroup -Name $DRSGroupName
            return " $result "
          } ElseIf ($Remove) {
            $result = Set-DrsClusterGroup -DrsClusterGroup $DRSGroupName -VMHost $VMHostList -Remove 
            Write-Host "Remove triggered and VMHostList: $VMHostList"
            return $result
          }
        }
        Else {
          $result = "Please select to add or remove either VMs or VMHosts from the DRS Group"
        }
  }
  
  <#
      .Synopsis
       Edits a DRS Cluster Group
  
      .Example 
      # Create a should run rule named MyDRSRule on Cluster-1 Hosts using the listed VM's and VMHosts
      Set-AvsDRSClusterGroup -DRSGroupName "MyDRSGroup" -Cluster "Cluster-1" -VMList "vm1", "vm2" 
  #>
  function Set-AvsDrsElevationRule {
  [CmdletBinding(PositionalBinding = $false)]
  Param
  (   
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]
      $DrsRuleName,
  
      [Parameter(Mandatory = $false)]
      [Nullable[boolean]]
      $Enabled,
  
      [Parameter(Mandatory = $false)]
      [ValidateNotNullOrEmpty()]
      [string]
      $Name
  )
      Write-Host "Enabled: $Enabled"

      Write-Host "Enabled is ne null:" + ($Enabled -ne $null) 
      #Set-TestEnvironmentVariables
      #Connect-vCenterServer
  
      if (($Enabled -ne $null) -And $Name) {
        Write-Host "Enabled $Enabled and Name: $Name"
        $result = Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $true -Name $Name
        return $result
      } ElseIf ($Enabled -ne $null) {
        $result = Set-DrsVMHostRule -Rule $DrsRuleName -Enabled $true 
        Write-Host "Enabled $enabled "
        return $result
      } ElseIf ($Name) {
        $result = Set-DrsVMHostRule -Rule $DrsRuleName -Name $Name
        Write-Host "no Enabled $enabled just Name $Name "
        return $result
      } Else {
        $result = Get-DrsVMHostRule -Name $DrsRuleName
        Write-Host "Nothing done  "
        return $result
      }
  
  }

Set-AzContext -Subscription "23995e3f-96a0-4b7a-95a0-c77f91054b52"
<#
#$result = Set-AvsDrsClusterGroup -DRSGroupName "test" -VMList "VM1" -Add 
#Write-Host "Test 1: $result"
#$result = Set-AvsDrsClusterGroup -DRSGroupName "test" -VMList "VM1" -Add -Remove
#Write-Host "Test 2: $result"
#$result = Set-AvsDrsClusterGroup -DRSGroupName "test" -VMList "VM1" -Remove
#Write-Host "Test 3: $result"
$result = Set-AvsDrsClusterGroup -DRSGroupName "test" -VMHostList "esx05-r16.p01.20a9db6cda924fa3ab83f5.eastus.avslab.azure.com" -Add
Write-Host "Test 4: $result"
#$result = Set-AvsDrsClusterGroup -DRSGroupName "testHost" -VMHostList "esx05-r16.p01.20a9db6cda924fa3ab83f5.eastus.avslab.azure.com" -Add
#Write-Host "Test 5: $result"
#$result = Set-AvsDrsClusterGroup -DRSGroupName "testHost" -VMHostList "esx05-r16.p01.20a9db6cda924fa3ab83f5.eastus.avslab.azure.com" -Remove
#Write-Host "Test 6: $result"
Write-Host "Before anything Enabled: $Enabled"
Write-Host "Test Enabled and Name changed: $result"
$result = Set-AvsDrsElevationRule -DRSRuleName "dabecherTest" -Enabled $true -Name "dabecherTest1"
Write-Host "Test Just disable: $result"
$result = Set-AvsDrsElevationRule -DRSRuleName "dabecherTest1" -Enabled $false
Write-Host "Test Just get the value/Do nothing: $testnine"
$Env:Enabled = $null 
$testnine = Set-AvsDrsElevationRule -DRSRuleName "dabecherTest1"
Write-Host "Test chagnge just the name"
$testnine = Set-AvsDrsElevationRule -DRSRuleName "dabecherTest1" -Name "dabecherTest"
#>

Set-AvsDrsElevationRule -DrsRuleName "dabecherTest1"

