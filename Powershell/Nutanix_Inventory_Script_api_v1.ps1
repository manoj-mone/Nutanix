<#
.SYNOPSIS
Creates a complete inventory of an Nutanix environment by using APIs.
.DESCRIPTION
Creates a complete inventory of a Nutanix Cluster configuration using CSV and PowerShell.
.PARAMETER nxIP
IP address of the Nutanix Prism Central you're making a connection too.
.PARAMETER nxUser
Username for the connection to the Nutanix Prism Central
.PARAMETER nxPassword
Password for the connection to the Nutanix Prism Central
.EXAMPLE
PS C:\PSScript > .\Nutanix_Inventory_Script_api.ps1
.INPUTS
None.  You cannot pipe objects to this script.
.OUTPUTS
No objects are output from this script.  
This script creates three CSV file.
.NOTES
NAME: Nutanix_Inventory_Script_api.ps1
VERSION: 1.0
Author: Manoj Mone, Nutanix
Complete API based inventory rendering. Based on an original Cmdlet based script written by: Kees Baggerman
Created On: June 25, 2021
LASTEDIT: July 8, 2021
#>

# Setting parameters for the connection
[CmdletBinding(SupportsShouldProcess = $False, ConfirmImpact = "None") ]
Param(
# Nutanix cluster IP address
[Parameter(Mandatory = $true)]
[Alias('IP')] [string] $nxIP,    
# Nutanix cluster username
[Parameter(Mandatory = $true)]
[Alias('User')] [string] $nxUser,
# Nutanix cluster password
[Parameter(Mandatory = $true)]
[Alias('Password')] [string] $nxPassword
)
# Converting the password to a secure string
#$nxPasswordSec = ConvertTo-SecureString $nxPassword -AsPlainText -Force
Function write-log {
<#
.Synopsis
Write logs for debugging purposes
.Description
This function writes logs based on the message including a time stamp for debugging purposes.
#>
param (
$message,
$sev = "INFO"
)
if ($sev -eq "INFO") {
write-host "$(get-date -format "hh:mm:ss") | INFO | $message"
}
elseif ($sev -eq "WARN") {
write-host "$(get-date -format "hh:mm:ss") | WARN | $message"
}
elseif ($sev -eq "ERROR") {
write-host "$(get-date -format "hh:mm:ss") | ERROR | $message"
}
elseif ($sev -eq "CHAPTER") {
write-host "`n`n### $message`n`n"
}
} 


$debug = 2
Function Get-Clusters {
    <#
    .Synopsis
    This function will collect the clusters within the specified Prism Central.
    .Description
    This function will collect the hosts within the specified cluster using REST API call based on Invoke-RestMethod
    #>
    Param (
    [string] $debug
    )
    $credPair = "$($nxUser):$($nxPassword)"
    #$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))
    $headers = @{ Authorization = "Basic $encodedCredentials" }
    $URL = "https://$($nxIP):9440//api/nutanix/v3/clusters/list"
    $Payload = @{
        kind="cluster"
        offset=0
        length=200
    } 
    $JSON = $Payload | convertto-json
    try {
    $task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers;
    }
    catch {
        $saved_error = $_.Exception.Message
        write-log -message "Error - Please check your credentials - $($saved_error)"
        exit

    }
    write-log -message "We found $($task.entities.count) clusters in this Prism Central."
    Return $task
    } 
Function Get-Hosts {
<#
.Synopsis
This function will collect the hosts within the specified cluster.
.Description
This function will collect the hosts within the specified cluster using REST API call based on Invoke-RestMethod
#>
Param (
[string] $debug
)
$credPair = "$($nxUser):$($nxPassword)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
#$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))

$headers = @{ Authorization = "Basic $encodedCredentials" }
$URL = "https://$($nxIP):9440/api/nutanix/v3/hosts/list"
$Payload = @{
kind   = "host"
offset = 0
length = 2500
} 
$JSON = $Payload | convertto-json
try {
$task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers;
}
catch {
write-log -message "Error extracting Host Information"
}
write-log -message "We found $($task.entities.count) hosts on this Prism Central."
Return $task
} 


Function Get-VMs {
<#
.Synopsis
This function will collect the VMs within the specified cluster.
.Description
This function will collect the VMs within the specified cluster using REST API call based on Invoke-RestMethod
#>
Param (
[string] $debug
)
$credPair = "$($nxUser):$($nxPassword)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
#$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))

$headers = @{ Authorization = "Basic $encodedCredentials" }
write-log -message "Executing VM List Query"
$URL = "https://$($nxIP):9440/api/nutanix/v3/vms/list"
$Payload = @{
kind   = "vm"
offset = 0
length = 999
} 
$JSON = $Payload | convertto-json
try {
$task = Invoke-RestMethod -Uri $URL -method "post" -body $JSON -ContentType 'application/json' -headers $headers;
}
catch {
write-log -message "Error extracting VM Information"
}
write-log -message "We found $($task.entities.count) VMs."
Return $task
} 


Function Get-DetailVM {
<#
.Synopsis
This function will collect the speficics of the VM we've specified using the Get-VMs function as input.
.Description
This function will collect the speficics of the VM we've specified using the Get-VMs function as input using REST API call based on Invoke-RestMethod
#>
Param (
[string] $uuid,
[string] $debug
)
$credPair = "$($nxUser):$($nxPassword)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
#$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))
$headers = @{ Authorization = "Basic $encodedCredentials" }
$URL = "https://$($nxIP):9440/api/nutanix/v3/vms/$($uuid)"
try {
$task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers;
}
catch {
write-log -message "Error extracting VM details for VM with uuid $($uuid)"
# $task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers;
}  
Return $task
} 
Function Get-DetailHosts {
Param (
[string] $uuid,
[string] $debug
)
$credPair = "$($nxUser):$($nxPassword)"
#$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credPair))

$headers = @{ Authorization = "Basic $encodedCredentials" }
$URL = "https://$($nxIP):9440/api/nutanix/v3/hosts/$($uuid)"
try {
$task = Invoke-RestMethod -Uri $URL -method "get" -headers $headers;
}
catch {
write-log -message "Error extracting details of Host having uuid $($uuid)"
}  
Return $task
} 


#Main Program
#Step 1 - Collect Cluster Information
$pcClusters = Get-Clusters -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug
$ClusterFullReport = @()
Foreach ($entity in $pcClusters.entities) {
    write-log -message "Collecting information about Cluster $($entity.status.name) with uuid $($entity.metadata.uuid)"            
    $props = [ordered]@{
    "Cluster Name"                          = $entity.status.name
    "Cluster uuid"                          = $entity.metadata.uuid
    "NOS Version"                           = $entity.status.resources.config.software_map.NOS.version
    "Redundancy Factor"                     = $entity.status.resources.config.redundancy_factor
    "Domain Awareness Level"                = $entity.status.resources.config.domain_awareness_level
    "Long Term Support"                     = $entity.status.resources.config.build.is_long_term_support
    "Timezone"                              = $entity.status.resources.config.timezone
    "External Ip"                           = $entity.status.resources.network.external_ip
    "Hypervisor"                            = $entity.status.resources.nodes.hypervisor_server_list.type | Select-Object -Unique
    }
    $ClusterReportobject = New-Object PSObject -Property $props
    $Clusterfullreport += $ClusterReportobject
}
$ClusterCsvFile = "~\Desktop\NutanixClusterInventory$(Get-Date -UFormat "%Y_%m_%d_%H_%M_").csv"
# $Clusterfullreport | Export-Csv -Path ~\Desktop\NutanixClusterInventory$(Get-Date -UFormat "%Y_%m_%d_%H_%M_").csv -NoTypeInformation -UseCulture -verbose:$false
$Clusterfullreport | Export-Csv -Path $ClusterCsvFile -NoTypeInformation -UseCulture -verbose:$false

write-log -message "Writing the Cluster information to the CSV file: $ClusterCsvFile"

#Step 2 - Collect Host Information

$pcHosts = Get-Hosts -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug
$HostsFullReport = @()
Foreach ($entity in $pcHosts.entities) {
    write-log -message "Collecting information about Host $($entity.status.name) with uuid $($entity.metadata.uuid)"            
    $props = [ordered]@{
    "Host Name"                     =$entity.status.name
    "Host uuid"                     =$entity.metadata.uuid
    "State"                         =$entity.status.state
    "Serial Number"                 =$entity.status.resources.serial_number
    "IP"                            =$entity.status.resources.ipmi.ip
    "Host Type"                     =$entity.status.resources.host_type
    "CPU Model"                     =$entity.status.resources.cpu_model 
    "Number of CPU Sockets"         =$entity.status.resources.num_cpu_sockets 
    "Number of CPU Cores"           =$entity.status.resources.num_cpu_cores 
    "Rackable Unit Ref uuid"        =$entity.status.resources.rackable_unit_reference.uuid
    "Cluster Kind"                  =$entity.status.cluster_reference.kind 
    "Cluster uuid"                  =$entity.status.cluster_reference.uuid
    "CVM Oplog Disk Size"           =$entity.spec.resources.controller_vm.oplog_usage.oplog_disk_size
    }
    $HostsReportobject = New-Object PSObject -Property $props
    $Hostsfullreport += $HostsReportobject
}
$HostCsvFile = "~\Desktop\NutanixHostInventory$(Get-Date -UFormat "%Y_%m_%d_%H_%M_").csv"
$Hostsfullreport | Export-Csv -Path $HostCsvFile -NoTypeInformation -UseCulture -verbose:$false
write-log -message "Writing the Host information to the CSV file: ~\Desktop\NutanixHostInventory$(Get-Date -UFormat "%Y_%m_%d_%H_%M_").csv "



# Fetching VM data and putting into CSV
$vms = Get-VMs -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug
# write-log -message "We found $($vms.entities.count) VMs."

# $vms = @(get-ntnxvm | Where-Object {$_.controllerVm -Match "false"}) 
write-log -message "Grabbing VM information"

$FullReport = @()
foreach ($vm in $vms.entities) {      
        write-log -message "Currently grabbing information about VM uuid $($vm.metadata.uuid)"            
        $myvmdetails = Get-DetailVM -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug -uuid $vm.metadata.uuid
        if ($null -eq ($myvmdetails.status.resources.host_reference.uuid)) {
            write-log -message "Host information isn't available for VM $($vm.spec.Name)"
            $hostname = ""
            }
            else {
                $myhostdetails = Get-DetailHosts -ClusterPC_IP $nxIP -nxPassword $nxPassword -clusername $nxUser -debug $debug -uuid $myvmdetails.status.resources.host_reference.uuid
                write-log -message "Retriving host information for VM $($vm.spec.Name)"
                $hostname = $myhostdetails.status.name
            
        }
$props = [ordered]@{
"VM Name"                       = $vm.spec.Name
"VM uuid"                       = $vm.metadata.uuid
"VM Host"                       = $hostname
"VM Host uuid"                  = $myvmdetails.status.resources.host_reference.uuid
"Cluster Name"                  = $myvmdetails.status.cluster_reference.name
"Cluster UUID"                  = $myvmdetails.spec.cluster_reference.uuid
"Power State"                   = $myvmdetails.status.resources.power_state
"Network Name"                  = $myvmdetails.status.resources.nic_list.subnet_reference.name
"IP Address(es)"                = $myvmdetails.status.resources.nic_list.ip_endpoint_list.ip -join ","
"Number of Cores"               = $myvmdetails.spec.resources.num_sockets
"Number of vCPUs per core"      = $myvmdetails.spec.resources.num_vcpus_per_socket
"VM Time Zone"                  = $myvmdetails.spec.resources.hardware_clock_timezone
} #End properties
$Reportobject = New-Object PSObject -Property $props
$fullreport += $Reportobject
}
$fullreport | Export-Csv -Path ~\Desktop\NutanixVMInventory$(Get-Date -UFormat "%Y_%m_%d_%H_%M_").csv -NoTypeInformation -UseCulture -verbose:$false
write-log -message "Writing VM list to CSV file: ~\Desktop\NutanixVMInventory$(Get-Date -UFormat "%Y_%m_%d_%H_%M_").csv"
write-log -message "Host information has been written to the CSV file: $HostCsvFile"
write-log -message "Cluster information has been written to the CSV file: $ClusterCsvFile"

# Disconnecting from the Nutanix Cluster
write-log -message "Closing the connection to the Nutanix cluster $($nxIP)"
write-log -message "Processing Complete"

