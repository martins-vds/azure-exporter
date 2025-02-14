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
    [ValidateSet(
        "All",
        "ApiManagement", 
        "AppConfigurations", 
        "ApplicationGateways", 
        "AppServices", 
        "AzureBackup", 
        "AzureBastion", 
        "AzureContainerInstances", 
        "AzureDatabaseForMySQL", 
        "AzureDatabaseForPostgres", 
        "AzureDataFactory", 
        "AzureDdosProtection", 
        "AzureDnsZones", 
        "AzureExpressRouteCircuits", 
        "AzureFirewall", 
        "AzureFrontDoors", 
        "AzureFunctions", 
        "AzureKubernetesService", 
        "AzurePrivateLinkServices", 
        "AzureSpotVirtualMachines", 
        "AzureSQL", 
        "AzureVaultRecoveryServices", 
        "AzureVirtualDesktop", 
        "BatchAccounts", 
        "KeyVault", 
        "LogicApps", 
        "MicrosoftDefenderForCloud", 
        "MicrosoftSentinel", 
        "NetworkSecurityGroups", 
        "ResourceGroups", 
        "Roles", 
        "ServiceBus", 
        "SqlManagedInstances", 
        "SqlServerOnAzureVMs", 
        "StorageAccounts", 
        "TrafficManagerProfiles", 
        "VirtualMachines", 
        "VirtualNetworks", 
        "VirtualWans", 
        "VpnGateways", 
        "WebApplicationFirewallPolicies"        
    )]
    [string[]] $ResourceTypes = @("All")
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Ensure the Az module is installed and imported.
if (-not (Get-Module -ListAvailable -Name Az)) {
    Write-Error "Az module is not installed. Install it with: Install-Module -Name Az -Repository PSGallery -Force -AllowClobber"
    exit
}

# Ensure the user is logged in. 
Connect-AzAccount -Tenant $Tenant -Subscription $Subscription | Out-Null

# Some azure resources can only be exported through Az cli.
az login --tenant $Tenant
az account set --subscription $Subscription

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
        [AllowNull()]
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

# Exporter for Microsoft Defender for Cloud
class MicrosoftDefenderForCloudExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Microsoft Defender for Cloud for subscription: $subscriptionId"
        $resources = Get-AzSecurityCenter  # Placeholder cmdlet
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "MicrosoftDefenderForCloud" -Resources $resources
    }
}

# Exporter for Azure DDoS Protection
class AzureDdosProtectionExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure DDoS Protection for subscription: $subscriptionId"
        $resources = Get-AzDdosProtectionPlan
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDdosProtection" -Resources $resources
    }
}

# Exporter for Key Vault
class KeyVaultExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Key Vaults for subscription: $subscriptionId"
        $resources = Get-AzKeyVault
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "KeyVault" -Resources $resources
    }
}

# Exporter for Microsoft Sentinel
class MicrosoftSentinelExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Microsoft Sentinel for subscription: $subscriptionId"
        $resources = Get-AzSentinel   # Placeholder cmdlet
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "MicrosoftSentinel" -Resources $resources
    }
}

# Exporter for Roles (Custom and Built-in) for Entra ID and Azure Resources
class RolesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Roles for subscription: $subscriptionId"
        $resources = Get-AzRoleDefinition
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "Roles" -Resources $resources
    }
}

# Exporter for Azure Spot Virtual Machines
class AzureSpotVirtualMachinesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Spot Virtual Machines for subscription: $subscriptionId"
        $resources = Get-AzVM | Where-Object { $_.Priority -eq "Spot" }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureSpotVirtualMachines" -Resources $resources
    }
}

# Exporter for Batch Accounts
class BatchAccountsExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Batch Accounts for subscription: $subscriptionId"
        $resources = Get-AzBatchAccount
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "BatchAccounts" -Resources $resources
    }
}

# Exporter for Azure Virtual Desktop
class AzureVirtualDesktopExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Virtual Desktop for subscription: $subscriptionId"
        $resources = Get-AzWvdHostPool   # Using host pools as a proxy for AVD resources
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureVirtualDesktop" -Resources $resources
    }
}

# Exporter for Azure Kubernetes Service
class AzureKubernetesServiceExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Kubernetes Service for subscription: $subscriptionId"
        $resources = Get-AzAksCluster
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureKubernetesService" -Resources $resources
    }
}

# Exporter for Azure Container Instances
class AzureContainerInstancesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Container Instances for subscription: $subscriptionId"
        $resources = Get-AzContainerInstance
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureContainerInstances" -Resources $resources
    }
}

# Exporter for Logic Apps
class LogicAppsExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Logic Apps for subscription: $subscriptionId"
        $resources = Get-AzLogicApp
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "LogicApps" -Resources $resources
    }
}

# Exporter for Azure Functions
class AzureFunctionsExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Functions for subscription: $subscriptionId"
        $resources = Get-AzFunctionApp
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureFunctions" -Resources $resources
    }
}

# Exporter for Service Bus
class ServiceBusExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Service Bus for subscription: $subscriptionId"
        $resources = Get-AzServiceBusNamespace
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ServiceBus" -Resources $resources
    }
}

# Exporter for API Management
class ApiManagementExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting API Management for subscription: $subscriptionId"
        $resources = Get-AzApiManagement
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ApiManagement" -Resources $resources
    }
}

# Exporter for Azure Data Factory
class AzureDataFactoryExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Data Factory for subscription: $subscriptionId"
        $resources = Get-AzDataFactory
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDataFactory" -Resources $resources
    }
}

# Exporter for Azure Database for MySQL
class AzureDatabaseForMySQLExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Database for MySQL for subscription: $subscriptionId"
        $resources = Get-AzMySqlServer
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDatabaseForMySQL" -Resources $resources
    }
}

# Exporter for Azure SQL
class AzureSQLExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure SQL for subscription: $subscriptionId"
        $resources = Get-AzSqlServer
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureSQL" -Resources $resources
    }
}

# Exporter for Azure Database for Postgres
class AzureDatabaseForPostgresExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Database for Postgres for subscription: $subscriptionId"
        $resources = Get-AzPostgreSqlServer
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDatabaseForPostgres" -Resources $resources
    }
}

# Exporter for SQL Managed Instances
class SqlManagedInstancesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting SQL Managed Instances for subscription: $subscriptionId"
        $resources = Get-AzSqlInstance
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "SqlManagedInstances" -Resources $resources
    }
}

# Exporter for SQL Server on Azure Virtual Machines
class SqlServerOnAzureVMsExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting SQL Server on Azure Virtual Machines for subscription: $subscriptionId"
        $resources = az sql vm list | ConvertFrom-Json
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "SqlServerOnAzureVMs" -Resources $resources
    }
}

# Exporter for Azure Vault Recovery Services
class AzureVaultRecoveryServicesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Vault Recovery Services for subscription: $subscriptionId"
        $resources = Get-AzRecoveryServicesVault
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureVaultRecoveryServices" -Resources $resources
    }
}

# Exporter for Azure Backup
class AzureBackupExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Backup for subscription: $subscriptionId"
        $resources = Get-AzRecoveryServicesBackupItem
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureBackup" -Resources $resources
    }
}

# Exporter for Application Gateways
class ApplicationGatewaysExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Application Gateways for subscription: $subscriptionId"
        $resources = Get-AzApplicationGateway
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ApplicationGateways" -Resources $resources
    }
}

# Exporter for Azure Bastion
class AzureBastionExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Bastion for subscription: $subscriptionId"
        $resources = Get-AzBastion
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureBastion" -Resources $resources
    }
}

# Exporter for Azure Firewall
class AzureFirewallExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Firewall for subscription: $subscriptionId"
        $resources = Get-AzFirewall
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureFirewall" -Resources $resources
    }
}

# Exporter for Azure Express Route Circuits
class AzureExpressRouteCircuitsExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Express Route Circuits for subscription: $subscriptionId"
        $resources = Get-AzExpressRouteCircuit
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureExpressRouteCircuits" -Resources $resources
    }
}

# Exporter for Azure DNS Zones
class AzureDnsZonesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure DNS Zones for subscription: $subscriptionId"
        $resources = Get-AzDnsZone
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDnsZones" -Resources $resources
    }
}

# Exporter for Azure Front Doors
class AzureFrontDoorsExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Front Doors for subscription: $subscriptionId"
        $resources = Get-AzFrontDoor
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureFrontDoors" -Resources $resources
    }
}

# Exporter for Azure Private Link Services
class AzurePrivateLinkServicesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Azure Private Link Services for subscription: $subscriptionId"
        $resources = Get-AzPrivateLinkService
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzurePrivateLinkServices" -Resources $resources
    }
}

# Exporter for Virtual Networks
class VirtualNetworksExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Virtual Networks for subscription: $subscriptionId"
        $resources = Get-AzVirtualNetwork
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "VirtualNetworks" -Resources $resources
    }
}

# Exporter for Web Application Firewall Policies
class WebApplicationFirewallPoliciesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Web Application Firewall Policies for subscription: $subscriptionId"
        $resources = Get-AzApplicationGatewayWebApplicationFirewallConfiguration
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "WebApplicationFirewallPolicies" -Resources $resources
    }
}

# Exporter for VPN Gateways
class VpnGatewaysExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting VPN Gateways for subscription: $subscriptionId"
        $resources = Get-AzVirtualNetworkGateway
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "VpnGateways" -Resources $resources
    }
}

# Exporter for Virtual WANs
class VirtualWansExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Virtual WANs for subscription: $subscriptionId"
        $resources = Get-AzVirtualWan
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "VirtualWans" -Resources $resources
    }
}

# Exporter for Traffic Manager Profiles
class TrafficManagerProfilesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Traffic Manager Profiles for subscription: $subscriptionId"
        $resources = Get-AzTrafficManagerProfile
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "TrafficManagerProfiles" -Resources $resources
    }
}

# Exporter for Network Security Groups
class NetworkSecurityGroupsExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting Network Security Groups for subscription: $subscriptionId"
        $resources = Get-AzNetworkSecurityGroup
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "NetworkSecurityGroups" -Resources $resources
    }
}

# Exporter for App Configurations
class AppConfigurationsExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {
        
        Write-Host "Exporting App Configurations for subscription: $subscriptionId"
        $resources = Get-AzAppConfigurationStore
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AppConfigurations" -Resources $resources
    }
}

# Exporter for App Services
class AppServicesExporter : IAzureResourceExporter {
    [void] Export([string]$subscriptionId) {        
        Write-Host "Exporting App Services for subscription: $subscriptionId"
        $resources = Get-AzWebApp
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AppServices" -Resources $resources
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
# Mapping: resource type => exporter class name
# Define a mapping from resource type to a scriptblock that returns a new exporter instance.
$exporterMapping = [ordered]@{
    "ApiManagement"                  = { [ApiManagementExporter]::new() }
    "AppConfigurations"              = { [AppConfigurationsExporter]::new() }
    "ApplicationGateways"            = { [ApplicationGatewaysExporter]::new() }
    "AppServices"                    = { [AppServicesExporter]::new() }
    # "AzureBackup"                    = { [AzureBackupExporter]::new() } - Asks for a container name
    "AzureBastion"                   = { [AzureBastionExporter]::new() }
    # "AzureContainerInstances"        = { [AzureContainerInstancesExporter]::new() } - Find a way to export
    "AzureDatabaseForMySQL"          = { [AzureDatabaseForMySQLExporter]::new() }
    "AzureDatabaseForPostgres"       = { [AzureDatabaseForPostgresExporter]::new() }
    # "AzureDataFactory"               = { [AzureDataFactoryExporter]::new() } - Asks for resource group name
    "AzureDdosProtection"            = { [AzureDdosProtectionExporter]::new() }
    "AzureDnsZones"                  = { [AzureDnsZonesExporter]::new() }
    "AzureExpressRouteCircuits"      = { [AzureExpressRouteCircuitsExporter]::new() }
    "AzureFirewall"                  = { [AzureFirewallExporter]::new() }
    "AzureFrontDoors"                = { [AzureFrontDoorsExporter]::new() }
    "AzureFunctions"                 = { [AzureFunctionsExporter]::new() }
    "AzureKubernetesService"         = { [AzureKubernetesServiceExporter]::new() }
    "AzurePrivateLinkServices"       = { [AzurePrivateLinkServicesExporter]::new() }
    "AzureSpotVirtualMachines"       = { [AzureSpotVirtualMachinesExporter]::new() }
    "AzureSQL"                       = { [AzureSQLExporter]::new() }
    "AzureVaultRecoveryServices"     = { [AzureVaultRecoveryServicesExporter]::new() }
    "AzureVirtualDesktop"            = { [AzureVirtualDesktopExporter]::new() }
    "BatchAccounts"                  = { [BatchAccountsExporter]::new() }
    "KeyVault"                       = { [KeyVaultExporter]::new() }
    "LogicApps"                      = { [LogicAppsExporter]::new() }
    # "MicrosoftDefenderForCloud"      = { [MicrosoftDefenderForCloudExporter]::new() } - Find a way to export
    # "MicrosoftSentinel"              = { [MicrosoftSentinelExporter]::new() } - Find a way to export
    "NetworkSecurityGroups"          = { [NetworkSecurityGroupsExporter]::new() }
    "ResourceGroups"                 = { [ResourceGroupExporter]::new() }
    "Roles"                          = { [RolesExporter]::new() }
    "ServiceBus"                     = { [ServiceBusExporter]::new() }
    "SqlManagedInstances"            = { [SqlManagedInstancesExporter]::new() }
    "SqlServerOnAzureVMs"            = { [SqlServerOnAzureVMsExporter]::new() }
    "StorageAccounts"                = { [StorageAccountExporter]::new() }
    "TrafficManagerProfiles"         = { [TrafficManagerProfilesExporter]::new() }
    "VirtualMachines"                = { [VirtualMachineExporter]::new() }
    "VirtualNetworks"                = { [VirtualNetworksExporter]::new() }
    "VirtualWans"                    = { [VirtualWansExporter]::new() }
    # "VpnGateways"                    = { [VpnGatewaysExporter]::new() } - Asks for resource group name
    # "WebApplicationFirewallPolicies" = { [WebApplicationFirewallPoliciesExporter]::new() } - Find a way to export   
}

# Then add exporters based on the user's input:
if ($ResourceTypes -contains "All") {
    foreach ($exporterCreator in $exporterMapping.Values) {
        $exporterManager.AddExporter((& $exporterCreator))
    }
}
else {
    foreach ($resource in $exporterMapping.Keys) {
        if ($ResourceTypes -contains $resource) {
            $exporterManager.AddExporter((& $exporterMapping[$resource]))
        }
    }
}

# Execute the export process.
$exporterManager.RunExporters()