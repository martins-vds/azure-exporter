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
    $json | Out-File -FilePath $fileName -Encoding utf8

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
        if ($this.Exporters.Count -eq 0) {
            Write-Host "No exporters to run."
            return
        }
        foreach ($exporter in $this.Exporters) {
            try {
                Write-Host "Exporting $($exporter.Name)..." -ForegroundColor White

                $count = $exporter.Export($this.SubscriptionId)
                
                if ($count -eq 0) {
                    Write-Host "    No $($exporter.Name) exported." -ForegroundColor Yellow
                }
                else {
                    Write-Host "    $count $($exporter.Name) exported." -ForegroundColor Green
                }
            }
            catch {
                Write-Host "    Error exporting $($exporter.Name): $_" -ForegroundColor Red
            }
        }
    }
}

##########################################
# Strategy Interface and Export Strategies
##########################################

# Interface defining the Export() method.
class IAzureResourceExporter {
    [string]   $Name

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
        
        $resources = Get-AzDataFactory
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
        
        $resources = Get-AzVirtualNetworkGateway
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

class EntraIDLicensingExporter : IAzureResourceExporter {
    [string] $Name = "Entra ID Licensing"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzEntraIDLicensing  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "EntraIDLicensing" -Resources $resources
        return $resources.Count
    }
}

class UsersExporter : IAzureResourceExporter {
    [string] $Name = "Users"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzEntraUser  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "Users" -Resources $resources
        return $resources.Count
    }
}

class GroupsExporter : IAzureResourceExporter {
    [string] $Name = "Groups"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzEntraGroup  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "Groups" -Resources $resources
        return $resources.Count
    }
}

class PIMConfigurationExporter : IAzureResourceExporter {
    [string] $Name = "PIM Configuration"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzPimConfiguration  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "PIMConfiguration" -Resources $resources
        return $resources.Count
    }
}

class RolesAndAssignmentsExporter : IAzureResourceExporter {
    [string] $Name = "Roles and Assignments"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzEntraRoleAssignment  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "RolesAndAssignments" -Resources $resources
        return $resources.Count
    }
}

class EnterpriseAppsExporter : IAzureResourceExporter {
    [string] $Name = "Enterprise Apps"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzEnterpriseApplication  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "EnterpriseApps" -Resources $resources
        return $resources.Count
    }
}

class ManagedIdentitiesAndServicePrincipalsExporter : IAzureResourceExporter {
    [string] $Name = "Managed Identities and Service Principals"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzServicePrincipal  # Placeholder (combine with managed identities as needed)
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

class UserAndSignInRiskSettingsExporter : IAzureResourceExporter {
    [string] $Name = "User and Sign-In Risk Settings"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzUserRiskSettings  # Placeholder
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

class IdentityProtectionExporter : IAzureResourceExporter {
    [string] $Name = "Identity Protection"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzIdentityProtection  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "IdentityProtection" -Resources $resources
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
        
        $resources = Get-AzEntitlementManagement  # Placeholder
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

class EntraPermissionsManagementExporter : IAzureResourceExporter {
    [string] $Name = "Entra Permissions Management"

    [int] Export([string] $subscriptionId) {
        
        $resources = Get-AzEntraPermissionsManagement  # Placeholder
        if (-not $resources) { return 0 }
        Export-ResourcesToJson -SubscriptionId $subscriptionId -ResourceType "EntraPermissionsManagement" -Resources $resources
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
