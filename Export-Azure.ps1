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
        "ADB2CConfiguration",
        "AdministrativeUnits",
        "ApiManagement",
        "AppConfigurations",
        "ApplicationGateways",
        "AppServices",
        "AuthenticationMethodSettings",
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
        "ConditionalAccessPolicies",
        "CrossTenantConfiguration",
        "DelegatedPartnerPermissions",
        "DiagnosticConfiguration",
        "EnterpriseApps",
        "EntitlementManagement",
        "EntraConnectConfiguration",
        "EntraIDLicensing",
        "Groups",
        "KeyVault",
        "LogicApps",
        "ManagedIdentitiesAndServicePrincipals",
        "MFASettings",
        "MicrosoftCopilotForSecurity",
        "MicrosoftDefenderForCloud",
        "MicrosoftSentinel",
        "NetworkSecurityGroups",
        "PasswordProtection",
        "PIMConfiguration",
        "ResourceGroups",
        "RoleAssignments",
        "ServiceBus",
        "SqlManagedInstances",
        "SqlServerOnAzureVMs",
        "SSPRConfiguration",
        "StorageAccounts",
        "TrafficManagerProfiles",
        "UserAndSignInRiskSettings",
        "Users",
        "VirtualMachines",
        "VirtualNetworks",
        "VirtualWans",
        "VpnGateways",
        "WebApplicationFirewallPolicies"              
    )]
    [string[]] $ResourceTypes = @("All"),
    [Parameter(Mandatory = $false)]
    [switch] 
    $SkipLogin
)

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
        return
    }
    
    $json = $Resources | ConvertTo-Json -Depth 100
    $fileName = "$SubscriptionId`_$ResourceType" + "_export.json"
    $json | Out-File -FilePath $fileName -Encoding utf8 -Force

    Write-Host "    Resources exported to $fileName" -ForegroundColor Blue
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
    [void] Export() {
        $logFile = "ExportLog_$($this.SubscriptionId)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

        if ($this.Exporters.Count -eq 0) {
            Write-Host "No exporters to run."
            return
        }
        foreach ($exporter in $this.Exporters) {
            try {
                # Write-Host "Exporting $($exporter.Name)..." -ForegroundColor White
                Tee-Object -FilePath $logFile -Append -InputObject "Exporting $($exporter.Name)..." | Out-Host

                $count = $exporter.Export($this.SubscriptionId)
                
                if ($count -eq 0) {
                    Tee-Object -FilePath $logFile -Append -InputObject "    No $($exporter.Name) exported." | Write-Host -ForegroundColor Yellow
                }
                else {
                    Tee-Object -FilePath $logFile -Append -InputObject "    $count $($exporter.Name) exported." | Write-Host -ForegroundColor Green
                }
            }
            catch {
                Tee-Object -FilePath $logFile -Append -InputObject "    Error exporting $($exporter.Name): $_" | Write-Host -ForegroundColor Red
            }
        }
    }
}

##########################################
# Strategy Interface and Export Strategies
##########################################

# Interface defining the Export() method.
class IAzureResourceExporter {
    [string] $Name

    [int] Export([string] $subscriptionId) {
        throw [System.NotImplementedException] "Export method is not implemented."
    }
}

# Export all Virtual Machines in the current subscription.
class VirtualMachineExporter : IAzureResourceExporter {
    [string] $Name = "Azure Virtual Machines"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzVM
        
        if (-not $resources) {
            return 0
        }

        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "VirtualMachines" -Resources $resources
        return $resources.Count
    }
}

class StorageAccountExporter : IAzureResourceExporter {
    [string] $Name = "Azure Storage Accounts"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzStorageAccount
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "StorageAccounts" -Resources $resources
        return $resources.Count
    }
}

class ResourceGroupExporter : IAzureResourceExporter {
    [string] $Name = "Azure Resource Groups"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzResourceGroup
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ResourceGroups" -Resources $resources
        return $resources.Count
    }
}

class MicrosoftDefenderForCloudExporter : IAzureResourceExporter {
    [string] $Name = "Microsoft Defender for Cloud"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzSecurityCenter  # Placeholder cmdlet
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "MicrosoftDefenderForCloud" -Resources $resources
        return $resources.Count
    }
}

class AzureDdosProtectionExporter : IAzureResourceExporter {
    [string] $Name = "Azure DDoS Protection"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzDdosProtectionPlan
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDdosProtection" -Resources $resources
        return $resources.Count
    }
}

class KeyVaultExporter : IAzureResourceExporter {
    [string] $Name = "Key Vaults"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzKeyVault
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "KeyVault" -Resources $resources
        return $resources.Count
    }
}

class MicrosoftSentinelExporter : IAzureResourceExporter {
    [string] $Name = "Microsoft Sentinel"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzSentinel   # Placeholder cmdlet
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "MicrosoftSentinel" -Resources $resources
        return $resources.Count
    }
}

class RolesExporter : IAzureResourceExporter {
    [string] $Name = "Roles"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzRoleDefinition
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "Roles" -Resources $resources
        return $resources.Count
    }
}

class AzureSpotVirtualMachinesExporter : IAzureResourceExporter {
    [string] $Name = "Azure Spot Virtual Machines"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzVM | Where-Object { $_.Priority -eq "Spot" }
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureSpotVirtualMachines" -Resources $resources
        return $resources.Count
    }
}

class BatchAccountsExporter : IAzureResourceExporter {
    [string] $Name = "Batch Accounts"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzBatchAccount
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "BatchAccounts" -Resources $resources
        return $resources.Count
    }
}

class AzureVirtualDesktopExporter : IAzureResourceExporter {
    [string] $Name = "Azure Virtual Desktop"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzWvdHostPool   # Using host pools as a proxy for AVD resources
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureVirtualDesktop" -Resources $resources
        return $resources.Count
    }
}

class AzureKubernetesServiceExporter : IAzureResourceExporter {
    [string] $Name = "Azure Kubernetes Service"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzAksCluster
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureKubernetesService" -Resources $resources
        return $resources.Count
    }
}

class AzureContainerInstancesExporter : IAzureResourceExporter {
    [string] $Name = "Azure Container Instances"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzContainerInstance
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureContainerInstances" -Resources $resources
        return $resources.Count
    }
}

class LogicAppsExporter : IAzureResourceExporter {
    [string] $Name = "Logic Apps"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzLogicApp
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "LogicApps" -Resources $resources
        return $resources.Count
    }
}

class AzureFunctionsExporter : IAzureResourceExporter {
    [string] $Name = "Azure Functions"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzFunctionApp
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureFunctions" -Resources $resources
        return $resources.Count
    }
}

class ServiceBusExporter : IAzureResourceExporter {
    [string] $Name = "Service Bus"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzServiceBusNamespace
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ServiceBus" -Resources $resources
        return $resources.Count
    }
}

class ApiManagementExporter : IAzureResourceExporter {
    [string] $Name = "API Management"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzApiManagement
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ApiManagement" -Resources $resources
        return $resources.Count
    }
}

class AzureDataFactoryExporter : IAzureResourceExporter {
    [string] $Name = "Azure Data Factory"

    [int] Export([string] $subscriptionId) {
        $resources = @()

        Get-AzResourceGroup | ForEach-Object {
            $resourceGroup = $_.ResourceGroupName
            $dataFactories = Get-AzDataFactoryV2 -ResourceGroupName $resourceGroup
            if ($dataFactories) {
                $resources += $dataFactories
            }
        }
        
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDataFactory" -Resources $resources
        return $resources.Count
    }
}

class AzureDatabaseForMySQLExporter : IAzureResourceExporter {
    [string] $Name = "Azure Database for MySQL"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzMySqlServer
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDatabaseForMySQL" -Resources $resources
        return $resources.Count
    }
}

class AzureSQLExporter : IAzureResourceExporter {
    [string] $Name = "Azure SQL"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzSqlServer
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureSQL" -Resources $resources
        return $resources.Count
    }
}

class AzureDatabaseForPostgresExporter : IAzureResourceExporter {
    [string] $Name = "Azure Database for Postgres"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzPostgreSqlServer
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDatabaseForPostgres" -Resources $resources
        return $resources.Count
    }
}

class SqlManagedInstancesExporter : IAzureResourceExporter {
    [string] $Name = "SQL Managed Instances"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzSqlInstance
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "SqlManagedInstances" -Resources $resources
        return $resources.Count
    }
}

class SqlServerOnAzureVMsExporter : IAzureResourceExporter {
    [string] $Name = "SQL Server on Azure Virtual Machines"

    [int] Export([string] $subscriptionId) {
        
        $resources = az sql vm list | ConvertFrom-Json
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "SqlServerOnAzureVMs" -Resources $resources
        return $resources.Count
    }
}

class AzureVaultRecoveryServicesExporter : IAzureResourceExporter {
    [string] $Name = "Azure Vault Recovery Services"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzRecoveryServicesVault
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureVaultRecoveryServices" -Resources $resources
        return $resources.Count
    }
}

class AzureBackupExporter : IAzureResourceExporter {
    [string] $Name = "Azure Backup"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzRecoveryServicesBackupItem
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureBackup" -Resources $resources
        return $resources.Count
    }
}

class ApplicationGatewaysExporter : IAzureResourceExporter {
    [string] $Name = "Application Gateways"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzApplicationGateway
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ApplicationGateways" -Resources $resources
        return $resources.Count
    }
}

class AzureBastionExporter : IAzureResourceExporter {
    [string] $Name = "Azure Bastion"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzBastion
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureBastion" -Resources $resources
        return $resources.Count
    }
}

class AzureFirewallExporter : IAzureResourceExporter {
    [string] $Name = "Azure Firewall"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzFirewall
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureFirewall" -Resources $resources
        return $resources.Count
    }
}

class AzureExpressRouteCircuitsExporter : IAzureResourceExporter {
    [string] $Name = "Azure Express Route Circuits"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzExpressRouteCircuit
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureExpressRouteCircuits" -Resources $resources
        return $resources.Count
    }
}

class AzureDnsZonesExporter : IAzureResourceExporter {
    [string] $Name = "Azure DNS Zones"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzDnsZone
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureDnsZones" -Resources $resources
        return $resources.Count
    }
}

class AzureFrontDoorsExporter : IAzureResourceExporter {
    [string] $Name = "Azure Front Doors"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzFrontDoor
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzureFrontDoors" -Resources $resources
        return $resources.Count
    }
}

class AzurePrivateLinkServicesExporter : IAzureResourceExporter {
    [string] $Name = "Azure Private Link Services"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzPrivateLinkService
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AzurePrivateLinkServices" -Resources $resources
        return $resources.Count
    }
}

class VirtualNetworksExporter : IAzureResourceExporter {
    [string] $Name = "Virtual Networks"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzVirtualNetwork
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "VirtualNetworks" -Resources $resources
        return $resources.Count
    }
}

class WebApplicationFirewallPoliciesExporter : IAzureResourceExporter {
    [string] $Name = "Web Application Firewall Policies"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzApplicationGatewayWebApplicationFirewallConfiguration
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "WebApplicationFirewallPolicies" -Resources $resources
        return $resources.Count
    }
}

class VpnGatewaysExporter : IAzureResourceExporter {
    [string] $Name = "VPN Gateways"

    [int] Export([string] $subscriptionId) {
        $resources = @()

        Get-AzResourceGroup | ForEach-Object {
            $resourceGroup = $_.ResourceGroupName
            $vpnGateways = Get-AzVirtualNetworkGateway -ResourceGroupName $resourceGroup
            if ($vpnGateways) {
                $resources += $vpnGateways
            }
        }

        if (-not $resources) {
            return 0
        }

        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "VpnGateways" -Resources $resources
        return $resources.Count
    }
}

class VirtualWansExporter : IAzureResourceExporter {
    [string] $Name = "Virtual WANs"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzVirtualWan
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "VirtualWans" -Resources $resources
        return $resources.Count
    }
}

class TrafficManagerProfilesExporter : IAzureResourceExporter {
    [string] $Name = "Traffic Manager Profiles"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzTrafficManagerProfile
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "TrafficManagerProfiles" -Resources $resources
        return $resources.Count
    }
}

class NetworkSecurityGroupsExporter : IAzureResourceExporter {
    [string] $Name = "Network Security Groups"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzNetworkSecurityGroup
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "NetworkSecurityGroups" -Resources $resources
        return $resources.Count
    }
}

class AppConfigurationsExporter : IAzureResourceExporter {
    [string] $Name = "App Configurations"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzAppConfigurationStore
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AppConfigurations" -Resources $resources
        return $resources.Count
    }
}

class AppServicesExporter : IAzureResourceExporter {
    [string] $Name = "App Services"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzWebApp
        if (-not $resources) {
            return 0
        }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AppServices" -Resources $resources
        return $resources.Count
    }
}

##########################################
# Experimental Export Strategies
##########################################

class ConditionalAccessPoliciesExporter : IAzureResourceExporter {
    [string] $Name = "Conditional Access Policies"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzConditionalAccessPolicy  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ConditionalAccessPolicies" -Resources $resources
        return $resources.Count
    }
}

# TODO: Select only assigned licenses and UPNs.
class EntraIDLicensingExporter : IAzureResourceExporter {
    [string] $Name = "Entra ID Licensing"

    [int] Export([string] $subscriptionId) {
        $resources = Get-MgUser -All
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "EntraIDLicensing" -Resources $resources
        return $resources.Count
    }
}

class UsersExporter : IAzureResourceExporter {
    [string] $Name = "Users"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-MgUser -All
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "Users" -Resources $resources
        return $resources.Count
    }
}

class GroupsExporter : IAzureResourceExporter {
    [string] $Name = "Groups"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-MgGroup -All
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "Groups" -Resources $resources
        return $resources.Count
    }
}

class PIMConfigurationExporter : IAzureResourceExporter {
    [string] $Name = "PIM Configuration"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "PIMConfiguration" -Resources $resources
        return $resources.Count
    }
}

class RoleAssignmentsExporter : IAzureResourceExporter {
    [string] $Name = "Role Assignments"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzRoleAssignment
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "RoleAssignments" -Resources $resources
        return $resources.Count
    }
}

class EnterpriseAppsExporter : IAzureResourceExporter {
    [string] $Name = "Enterprise Apps"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-MgApplication -All
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "EnterpriseApps" -Resources $resources
        return $resources.Count
    }
}

class ManagedIdentitiesAndServicePrincipalsExporter : IAzureResourceExporter {
    [string] $Name = "Managed Identities and Service Principals"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-MgServicePrincipal -All
        $resources += Get-AzSystemAssignedIdentity -Scope "/subscriptions/$subscriptionId"
        $resources += Get-AzUserAssignedIdentity

        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ManagedIdentitiesAndServicePrincipals" -Resources $resources
        return $resources.Count
    }
}

class DiagnosticConfigurationExporter : IAzureResourceExporter {
    [string] $Name = "Diagnostic Configuration"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzDiagnosticSetting  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "DiagnosticConfiguration" -Resources $resources
        return $resources.Count
    }
}

class MFASettingsExporter : IAzureResourceExporter {
    [string] $Name = "MFA Settings"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzMfaSettings  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "MFASettings" -Resources $resources
        return $resources.Count
    }
}

# Should this export all risky users and sign-ins?
class UserAndSignInRiskSettingsExporter : IAzureResourceExporter {
    [string] $Name = "User and Sign-In Risk Settings"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-MgRiskyUser -All
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "UserAndSignInRiskSettings" -Resources $resources
        return $resources.Count
    }
}

class AuthenticationMethodSettingsExporter : IAzureResourceExporter {
    [string] $Name = "Authentication Method Settings"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzAuthenticationMethodSettings  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AuthenticationMethodSettings" -Resources $resources
        return $resources.Count
    }
}

class PasswordProtectionExporter : IAzureResourceExporter {
    [string] $Name = "Password Protection"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzPasswordProtection  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "PasswordProtection" -Resources $resources
        return $resources.Count
    }
}

class EntitlementManagementExporter : IAzureResourceExporter {
    [string] $Name = "Entitlement Management"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-MgEntitlementManagementAccessPackage -All
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "EntitlementManagement" -Resources $resources
        return $resources.Count
    }
}

class CrossTenantConfigurationExporter : IAzureResourceExporter {
    [string] $Name = "Cross-Tenant Configuration"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzCrossTenantConfiguration  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "CrossTenantConfiguration" -Resources $resources
        return $resources.Count
    }
}

class DelegatedPartnerPermissionsExporter : IAzureResourceExporter {
    [string] $Name = "Delegated Partner Permissions"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzDelegatedPartnerPermission  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "DelegatedPartnerPermissions" -Resources $resources
        return $resources.Count
    }
}

class SSPRConfigurationExporter : IAzureResourceExporter {
    [string] $Name = "SSPR Configuration"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzSSPRConfiguration  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "SSPRConfiguration" -Resources $resources
        return $resources.Count
    }
}

class AdministrativeUnitsExporter : IAzureResourceExporter {
    [string] $Name = "Administrative Units"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzAdministrativeUnit  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "AdministrativeUnits" -Resources $resources
        return $resources.Count
    }
}

class EntraConnectConfigurationExporter : IAzureResourceExporter {
    [string] $Name = "Entra Connect Configuration"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzEntraConnectConfiguration  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "EntraConnectConfiguration" -Resources $resources
        return $resources.Count
    }
}

class ADB2CConfigurationExporter : IAzureResourceExporter {
    [string] $Name = "AD B2C Configuration"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzADB2CConfiguration  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "ADB2CConfiguration" -Resources $resources
        return $resources.Count
    }
}


$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Ensure the Az module is installed and imported.
if (-not (Get-Module -ListAvailable -Name Az)) {
    Write-Error "Az module is not installed. Install it with: Install-Module -Name Az -Repository PSGallery -Force -AllowClobber"
    exit
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Error "Microsoft.Graph module is not installed. Install it with: Install-Module -Name Microsoft.Graph -Repository PSGallery -Force -AllowClobber"    
    exit
}

if ($SkipLogin -eq $false) {
    # Ensure the user is logged in. 
    Connect-AzAccount -Tenant $Tenant -Subscription $Subscription -Scope CurrentUser | Out-Null

    # Connect to Microsoft Graph for Azure AD resources. Need to consent to the permissions.
    Connect-MgGraph -Scopes EntitlementManagement.Read.All,IdentityRiskEvent.Read.All, IdentityRiskyUser.ReadWrite.All, Directory.Read.All, RoleManagement.Read.Directory, Application.Read.All, User.Read.All, Organization.Read.All, Group.ReadWrite.All -NoWelcome | Out-Null

    # Some azure resources can only be exported through Az cli.
    az login --tenant $Tenant | Out-Null
    az account set --subscription $Subscription | Out-Null
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
    # "ADB2CConfiguration"                    = { [ADB2CConfigurationExporter]::new() } - Find a way to export
    # "AdministrativeUnits"                   = { [AdministrativeUnitsExporter]::new() } - Find a way to export
    "ApiManagement"                         = { [IAzureResourceExporter]([ApiManagementExporter]::new()) }
    "AppConfigurations"                     = { [AppConfigurationsExporter]::new() }
    "AppServices"                           = { [AppServicesExporter]::new() }
    "ApplicationGateways"                   = { [ApplicationGatewaysExporter]::new() }
    # "AzureBackup"              = { [AzureBackupExporter]::new() } - Asks for a container name
    "AzureBastion"                          = { [AzureBastionExporter]::new() }
    # "AzureContainerInstances"   = { [AzureContainerInstancesExporter]::new() } - Find a way to export
    "AzureDatabaseForMySQL"                 = { [AzureDatabaseForMySQLExporter]::new() }
    "AzureDatabaseForPostgres"              = { [AzureDatabaseForPostgresExporter]::new() }
    "AzureDataFactory"                      = { [AzureDataFactoryExporter]::new() }
    "AzureDdosProtection"                   = { [AzureDdosProtectionExporter]::new() }
    "AzureDnsZones"                         = { [AzureDnsZonesExporter]::new() }
    "AzureExpressRouteCircuits"             = { [AzureExpressRouteCircuitsExporter]::new() }
    "AzureFirewall"                         = { [AzureFirewallExporter]::new() }
    "AzureFrontDoors"                       = { [AzureFrontDoorsExporter]::new() }
    "AzureFunctions"                        = { [AzureFunctionsExporter]::new() }
    "AzureKubernetesService"                = { [AzureKubernetesServiceExporter]::new() }
    "AzurePrivateLinkServices"              = { [AzurePrivateLinkServicesExporter]::new() }
    "AzureSQL"                              = { [AzureSQLExporter]::new() }
    "AzureSpotVirtualMachines"              = { [AzureSpotVirtualMachinesExporter]::new() }
    "AzureVaultRecoveryServices"            = { [AzureVaultRecoveryServicesExporter]::new() }
    "AzureVirtualDesktop"                   = { [AzureVirtualDesktopExporter]::new() }
    "BatchAccounts"                         = { [BatchAccountsExporter]::new() }
    # "ConditionalAccessPolicies"             = { [ConditionalAccessPoliciesExporter]::new() } - Find a way to export
    # "CrossTenantConfiguration"              = { [CrossTenantConfigurationExporter]::new() } - Find a way to export
    # "DelegatedPartnerPermissions"           = { [DelegatedPartnerPermissionsExporter]::new() } - Find a way to export
    # "DiagnosticConfiguration"               = { [DiagnosticConfigurationExporter]::new() } - Asks for resource id
    # "EntraConnectConfiguration"             = { [EntraConnectConfigurationExporter]::new() } - Find a way to export. What is this?
    "EntraIDLicensing"                      = { [EntraIDLicensingExporter]::new() }
    "EnterpriseApps"                        = { [EnterpriseAppsExporter]::new() }
    "EntitlementManagement"                 = { [EntitlementManagementExporter]::new() }
    "Groups"                                = { [GroupsExporter]::new() }
    "KeyVault"                              = { [KeyVaultExporter]::new() }
    "LogicApps"                             = { [LogicAppsExporter]::new() }
    "ManagedIdentitiesAndServicePrincipals" = { [ManagedIdentitiesAndServicePrincipalsExporter]::new() }
    # "MFASettings"                           = { [MFASettingsExporter]::new() } - Find a way to export. Should this be exported by user?
    # "MicrosoftDefenderForCloud" = { [MicrosoftDefenderForCloudExporter]::new() } - Find a way to export
    # "MicrosoftSentinel"         = { [MicrosoftSentinelExporter]::new() } - Find a way to export
    "NetworkSecurityGroups"                 = { [NetworkSecurityGroupsExporter]::new() }
    "PIMConfiguration"                      = { [PIMConfigurationExporter]::new() }
    "ResourceGroups"                        = { [ResourceGroupExporter]::new() }
    "Roles"                                 = { [RolesExporter]::new() }
    "RoleAssignments"                       = { [RoleAssignmentsExporter]::new() }
    "ServiceBus"                            = { [ServiceBusExporter]::new() }
    "SqlManagedInstances"                   = { [SqlManagedInstancesExporter]::new() }
    "SqlServerOnAzureVMs"                   = { [SqlServerOnAzureVMsExporter]::new() }
    "StorageAccounts"                       = { [StorageAccountExporter]::new() }
    "TrafficManagerProfiles"                = { [TrafficManagerProfilesExporter]::new() }
    "UserAndSignInRiskSettings"             = { [UserAndSignInRiskSettingsExporter]::new() }
    "Users"                                 = { [UsersExporter]::new() }
    "VirtualMachines"                       = { [VirtualMachineExporter]::new() }
    "VirtualNetworks"                       = { [VirtualNetworksExporter]::new() }
    "VirtualWans"                           = { [VirtualWansExporter]::new() }
    "VpnGateways"                           = { [VpnGatewaysExporter]::new() }
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
$exporterManager.Export()