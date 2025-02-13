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
    Write-Error "Az module is not installed. Install it with: Install-Module -Name Az"
    exit
}

# Ensure the user is logged in.
Connect-AzAccount -Tenant $Tenant -Subscription $Subscription

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
        if (-not $vms) {
            Write-Host "  No Virtual Machines found."
        }
        else {
            foreach ($vm in $vms) {
                $fileName = "$($subscriptionId)_$($vm.Name)_VM_export.xml"
                $vm | Export-CliXml -Path $fileName
                Write-Host "  Exported VM '$($vm.Name)' to $fileName"
            }
        }
    }
}

# Export all Storage Accounts in the current subscription.
class StorageAccountExporter : IAzureResourceExporter {
    [void] Export([string] $subscriptionId) {
        Write-Host "Exporting all Azure Storage Accounts in subscription: $subscriptionId"
        $storageAccounts = Get-AzStorageAccount
        if (-not $storageAccounts) {
            Write-Host "  No Storage Accounts found."
        }
        else {
            foreach ($account in $storageAccounts) {
                $accountName = $account.StorageAccountName
                $fileName = "$($subscriptionId)_$($accountName)_Storage_export.xml"
                $account | Export-CliXml -Path $fileName
                Write-Host "  Exported Storage Account '$($accountName)' to $fileName"
            }
        }
    }
}

# Export all Resource Groups in the current subscription.
class ResourceGroupExporter : IAzureResourceExporter {
    [void] Export([string] $subscriptionId) {
        Write-Host "Exporting all Azure Resource Groups in subscription: $subscriptionId"
        $resourceGroups = Get-AzResourceGroup
        if (-not $resourceGroups) {
            Write-Host "  No Resource Groups found."
        }
        else {
            foreach ($rg in $resourceGroups) {
                $rgName = $rg.ResourceGroupName
                $fileName = "$($subscriptionId)_$($rgName)_RG_export.xml"
                $rg | Export-CliXml -Path $fileName
                Write-Host "  Exported Resource Group '$($rgName)' to $fileName"
            }
        }
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
