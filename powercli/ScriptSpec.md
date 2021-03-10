# Scripts Available

## PowerCLI Scripts (Accessible to CloudAdmin)

- Get-VM: Returns a list of the VMs (does not include the service VMs)
- Get-SpbmStoragePolicy: Returns a list of storage policies
- Get-Cluster: Returns the list of the Cluster Names
- Get-VMHost: Returns information about the VM Hosts
- Get-DrsClusterGroup: Returns information about the cluster group
- Get-DrsVMHostRule: Returns information about cluster rules

## AD Integration
###Add-ActiveDirectoryIdentitySource
**Functionality** Allow customers to add an external identity source (Active Directory over LDAP) for use with single sign on to vCenter.

**Example**
	Add-ActiveDirectoryIdentitySource -Name 'dabecher' -DomainName 'dabecher.local' -DomainAlias 'dabecher' -PrimaryUrl 'ldap://10.40.0.5:389' -BaseDNUsers 'dc=dabecher, dc=local' -BaseDNGroups 'dc=dabecher, dc=local' -Username 'dabecher@dabecher.local' -Password 'PlaceholderPassword'

**Inputs**
Customer will need to provide the following:
| Parameter Name | Type         | Description                                                   | Example                 |
| :------------- | :----------: | :-----------------------------------------------------------: | ----------------------: |
| Name           | String       | Name of the identity source that will show up in vCenter      | "OurADServer"           |
| DomainName     | String       | Domain name of the AD server                                  | "dabecher.local"        |
| DomainAlias    | String       | Domain alias of the AD server                                 | "dabecher"              |
| PrimaryURL     | String       | URL to reach the AD server                                    | "ldap://10.40.0.5:389"  |
| BaseDNUsers    | String       | Base Distinguished Name for Users                             | "dc=dabecher, dc=local" |
| BaseDNGroups   | String       | Base Distinguished Name for Groups                            | "dc=dabecher, dc=local" |
| Username       | String       | Username of the account to authenticate to customer AD Server | admin@dabecher.local    |
| Password       | SecureString | Password to the account to authenticate to customer AD Server | "myp@$$w0rd"            |

**Outputs**
The added external identity source object. 

## DRS Role Elevation
### New-AvsDrsElevationRule
**Functionality** Creates a DRS Cluster Host Group, a DRS Cluster VM Group, and a DRS Cluster Virtual Machine to Host Rule between the two. Currently, we only allow "ShouldRunOn" rules so that rule type cannot be configured by the customer. *Need to ensure that they cannot select Service VM's*

**Examples** 
	New-DRSElevationRule -DRSGroupName "MyDRSGroup" -DRSRuleName "MyDRSRule" -Cluster "Cluster-1" -VMList "vm1", "vm2" -VMHostList "esx01", "esx02"

**Inputs**
Customer will need to provide the following:
| Parameter Name | Type         | Description                                                                        | Example                                      |
| :------------- | :----------: | :-----------------------------------------------------------:                      | ----------------------:                      |
| DRSRuleName    | String       | Name of the DRS Rule to be created                                                 | "MyDRSRuleName"                              |
| DRSGroupName   | String       | Name of the DRS Group to be created                                                | "MyDRSGroupName"                             |
| Cluster        | String       | Existing cluster name to create the rule and groups on                             | "Cluster-1"                                  |
| VMList         | String []    | Comma separated list of existing VMs to be added to the DRS Cluster VM Group       | "TNT79-EVM01", "TNT79-EVM02"                 |
| VMHostList     | String []    | Comma separated list of existing VMHosts to be added to the DRS Cluster Host Group | "esx05-r16.azure.com", "esx12-r08.azure.com" |


**Outputs**
The final DRS rule that was created.

### Set-AvsDrsClusterGroup
**Functionality** Edit a DRS Cluster Host Group or a DRS Cluster VM Group

**Examples** 
	Set-DRSElevationRule -DRSGroupName "MyDRSGroup" -VMList "vm1", "vm2" -Add
	Set-DRSElevationRule -DRSGroupName "MyDRSGroup" -VMHostList "vm1", "vm2" -Remove

**Inputs**
Customer will need to provide the following:
| Parameter Name | Type         | Description                                                                        | Example                                      |
| :------------- | :----------: | :-----------------------------------------------------------:                      | ----------------------:                      |
| DRSGroupName   | String       | Name of the DRS Group to be created                                                | "MyDRSGroupName"                             |
| VMList         | String []    | Comma separated list of existing VMs to be added to the DRS Cluster VM Group       | "TNT79-EVM01", "TNT79-EVM02"                 |
| VMHostList     | String []    | Comma separated list of existing VMHosts to be added to the DRS Cluster Host Group | "esx05-r16.azure.com", "esx12-r08.azure.com" |
| Add            | Switch       | To add VMs or VMHosts to that particular group   									 | 												|
| Remove         | Switch       | To remove VMs or VMHosts to that particular group   								 | 												|


**Outputs**
The Edited DRS Group and its members

### Set-AvsDrsElevationRule
**Functionality** Edit a DRS Cluster Virtual Machine to Host Rule between the two. Currently, we only allow "ShouldRunOn" rules so that rule type cannot be configured by the customer.

**Examples** 
	Set-DRSElevationRule -DRSRuleName "MyDRSRule" -Enabled $true -Name "MyNewDRSRuleName

**Inputs**
Customer will need to provide the following:
| Parameter Name | Type                | Description                                                                        | Example                                      |
| :------------- | :----------:        | :-----------------------------------------------------------:                      | ----------------------:                      |
| DRSRuleName    | String              | Name of the DRS Rule to be created                                                 | "MyDRSRuleName"                              |
| Enabled        | Boolean optional    | Set the status of the rule to enabled or disabled                                  | "$true"                                      |
| NewName        | String optional     | Name to change the DRS rule to                                                     | "MyNewDRSRuleName"                           |


**Outputs**
The edited DRS rule.

## Storage Policy Setting

### Get-SpbmStoragePolicy 
**Functionality** This is a PowerCLI command that returns the names back of the current default StoragePolicies. Customer has permission to run this as cloudadmin

**Examples** 
	Get-SpbmStoragePolicy 
	Get-SpbmStoragePolicy | Select Name

**Outputs**
Storage Policy Object, including the name they will need to pass into Set-AvsStoragePolicy

### Set-AvsStoragePolicy
**Functionality** Set the storage policy of a VM to the specified StoragePolicy. *Need to ensure that they cannot select Service VM's*

**Examples** 
	Set-AvsStoragePolicy -StoragePolicyName "RAID-1 FTT-1" -VMName "TNT79-EVM02"

**Inputs**
Customer will need to provide the following:
For VMName or Cluster, only one should be provided. Attempting to set both at the same time will result in an error.

| Parameter Name    | Type              | Description                                                     | Example           |
| :-------------    | :----------:      | :-----------------------------------------------------------:   | ----------------: |
| StoragePolicyName | String            | Existing storage policy name (default storag policies only)     | "RAID-1 FTT-1"    |
| VMName            | String optional   | Name of the existing VM to apply the storage policy to          | "TNT-79-EVM02"    |
| Cluster           | String optional   | Name of the exisitng Cluster to apply the storage policy to     | "Cluster-1"       |

**Outputs**
Properties about the VM/Cluster that had its policies changed.
