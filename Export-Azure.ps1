<#
.SYNOPSIS
    Exports Azure resources from one or more subscriptions.

.DESCRIPTION
    This script exports Virtual Machines, Storage Accounts, and Resource Groups from Azure.
    Use the -SubscriptionIds parameter to specify one or more subscription IDs. If omitted,
    the script will export resources from all subscriptions the logged-in user has access to.
    Use the -ResourceTypes parameter to specify which resources to export. Allowed values:
    "VirtualMachines", "StorageAccounts", "ResourceGroups", "All". Default is "All".

.PARAMETER SubscriptionIds
    An optional array of subscription IDs. If not provided, all accessible subscriptions are used.

.PARAMETER ResourceTypes
    An optional array of resource types to export. Allowed values are "VirtualMachines",
    "StorageAccounts", "ResourceGroups", or "All". Default is "All".

.EXAMPLE
    .\Export.ps1 -SubscriptionIds "sub-id-1", "sub-id-2" -ResourceTypes "VirtualMachines", "ResourceGroups"

.NOTES
    Requires the Az PowerShell module.
#>

param (
    [Parameter(Mandatory = $true)]
    [string] $Tenant,

    [Parameter(Mandatory = $true)]
    [string] $Subscription,

    [Parameter(Mandatory = $false)]
    [string[]] $SubscriptionIds,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("VirtualMachines", "StorageAccounts", "ResourceGroups", "All")]
    [string[]] $ResourceTypes = @("All")
)

$ErrorActionPreference = "Stop"

# Ensure the Az module is installed and imported.
if (-not (Get-Module -ListAvailable -Name Az)) {
    Write-Error "Az module is not installed. Install it with: Install-Module -Name Az -Repository PSGallery -Force -AllowClobber"
    exit
}

# Ensure the user is logged in.
Connect-AzAccount -Tenant $Tenant -Subscription $Subscription | Out-Null

##########################################################
# Helper Function: Export-ResourcesToJson
##########################################################
function Export-ResourcesToJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceType,
        
        [Parameter(Mandatory = $true)]
        [object[]]$Resources
    )
    
    if (-not $Resources) {
        Write-Host "  No $ResourceType found in subscription: $SubscriptionId"
    }
    else {
        $json = $Resources | ConvertTo-Json -Depth 100
        $fileName = "$SubscriptionId`_$ResourceType" + "_export.json"
        $json | Out-File -FilePath $fileName -Encoding utf8
        Write-Host "  Exported $ResourceType from subscription $SubscriptionId to $fileName"
    }
}

##########################################
# Strategy Interface and Export Strategies
##########################################

# Interface defining the Export() method.
class IAzureResourceExporter {
    [void] Export([string] $subscriptionId) {
        throw [System.NotImplementedException] "Export method is not implemented."
    }
}

# Export all Virtual Machines in the current subscription.
class VirtualMachineExporter : IAzureResourceExporter {
    [void] Export([string] $subscriptionId) {
        Write-Host "Exporting all Azure Virtual Machines in subscription: $subscriptionId"
        $vms = Get-AzVM
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "VirtualMachines" -Resources $vms
    }
}

# Export all Storage Accounts in the current subscription.
class StorageAccountExporter : IAzureResourceExporter {
    [void] Export([string] $subscriptionId) {
        Write-Host "Exporting all Azure Storage Accounts in subscription: $subscriptionId"
        $storageAccounts = Get-AzStorageAccount
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "StorageAccounts" -Resources $storageAccounts
    }
}

# Export all Resource Groups in the current subscription.
class ResourceGroupExporter : IAzureResourceExporter {
    [void] Export([string] $subscriptionId) {
        Write-Host "Exporting all Azure Resource Groups in subscription: $subscriptionId"
        $resourceGroups = Get-AzResourceGroup
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ResourceGroups" -Resources $resourceGroups
    }
}

##########################################
# Manager (Context) Class
##########################################

# Manages one or more exporters and iterates over one or more subscriptions.
class AzureExporterManager {
    [IAzureResourceExporter[]] $Exporters
    [string] $SubscriptionId

    AzureExporterManager([string] $subscriptionId) {
        $this.Exporters = @()
        $this.SubscriptionId = $subscriptionId
    }

    # Add an exporter strategy.
    [void] AddExporter([IAzureResourceExporter] $exporter) {
        $this.Exporters += $exporter
    }

    # Run all registered exporters for each subscription.
    [void] RunExporters() {
        if ($this.Exporters.Count -eq 0) {
            Write-Host "No exporters to run."
            return
        }
        foreach ($exporter in $this.Exporters) {
            $exporter.Export($this.SubscriptionId)
        }
    }
}

##########################################
# Main Execution
##########################################

# Create an instance of the AzureExporterManager with the provided subscription IDs.
$exporterManager = [AzureExporterManager]::new($Subscription)

# Add exporters based on the user's selection.
if ($ResourceTypes -contains "All") {
    # Add all exporters.
    $exporterManager.AddExporter([VirtualMachineExporter]::new())
    $exporterManager.AddExporter([StorageAccountExporter]::new())
    $exporterManager.AddExporter([ResourceGroupExporter]::new())
}
else {
    if ($ResourceTypes -contains "VirtualMachines") {
        $exporterManager.AddExporter([VirtualMachineExporter]::new())
    }
    if ($ResourceTypes -contains "StorageAccounts") {
        $exporterManager.AddExporter([StorageAccountExporter]::new())
    }
    if ($ResourceTypes -contains "ResourceGroups") {
        $exporterManager.AddExporter([ResourceGroupExporter]::new())
    }
}

# Execute the export process.
$exporterManager.RunExporters()
