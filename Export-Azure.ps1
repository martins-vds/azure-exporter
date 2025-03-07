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
        "EntraPermissionsManagement",
        "Groups",
        "IdentityProtection",
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
        "RolesAndAssignments",
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

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

. $PSScriptRoot\Exporters.ps1

# Ensure the Az module is installed and imported.
if (-not (Get-Module -ListAvailable -Name Az)) {
    Write-Error "Az module is not installed. Install it with: Install-Module -Name Az -Repository PSGallery -Force -AllowClobber"
    exit
}

if ($SkipLogin -eq $false) {
    # Ensure the user is logged in. 
    Connect-AzAccount -Tenant $Tenant -Subscription $Subscription | Out-Null

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
    "ADB2CConfiguration"                    = { [ADB2CConfigurationExporter]::new() }
    "AdministrativeUnits"                   = { [AdministrativeUnitsExporter]::new() }
    "ApiManagement"                         = { [ApiManagementExporter]::new() }
    "AppConfigurations"                     = { [AppConfigurationsExporter]::new() }
    "AppServices"                           = { [AppServicesExporter]::new() }
    "ApplicationGateways"                   = { [ApplicationGatewaysExporter]::new() }
    # "AzureBackup"              = { [AzureBackupExporter]::new() } - Asks for a container name
    "AzureBastion"                          = { [AzureBastionExporter]::new() }
    # "AzureContainerInstances"   = { [AzureContainerInstancesExporter]::new() } - Find a way to export
    "AzureDatabaseForMySQL"                 = { [AzureDatabaseForMySQLExporter]::new() }
    "AzureDatabaseForPostgres"              = { [AzureDatabaseForPostgresExporter]::new() }
    # "AzureDataFactory"          = { [AzureDataFactoryExporter]::new() } - Asks for resource group name
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
    "ConditionalAccessPolicies"             = { [ConditionalAccessPoliciesExporter]::new() }
    "CrossTenantConfiguration"              = { [CrossTenantConfigurationExporter]::new() }
    "DelegatedPartnerPermissions"           = { [DelegatedPartnerPermissionsExporter]::new() }
    "DiagnosticConfiguration"               = { [DiagnosticConfigurationExporter]::new() }
    "EntraConnectConfiguration"             = { [EntraConnectConfigurationExporter]::new() }
    "EntraIDLicensing"                      = { [EntraIDLicensingExporter]::new() }
    "EntraPermissionsManagement"            = { [EntraPermissionsManagementExporter]::new() }
    "EnterpriseApps"                        = { [EnterpriseAppsExporter]::new() }
    "EntitlementManagement"                 = { [EntitlementManagementExporter]::new() }
    "Groups"                                = { [GroupsExporter]::new() }
    "IdentityProtection"                    = { [IdentityProtectionExporter]::new() }
    "KeyVault"                              = { [KeyVaultExporter]::new() }
    "LogicApps"                             = { [LogicAppsExporter]::new() }
    "ManagedIdentitiesAndServicePrincipals" = { [ManagedIdentitiesAndServicePrincipalsExporter]::new() }
    "MFASettings"                           = { [MFASettingsExporter]::new() }
    "MicrosoftCopilotForSecurity"           = { [MicrosoftCopilotForSecurityExporter]::new() }
    # "MicrosoftDefenderForCloud" = { [MicrosoftDefenderForCloudExporter]::new() } - Find a way to export
    # "MicrosoftSentinel"         = { [MicrosoftSentinelExporter]::new() } - Find a way to export
    "NetworkSecurityGroups"                 = { [NetworkSecurityGroupsExporter]::new() }
    "PIMConfiguration"                      = { [PIMConfigurationExporter]::new() }
    "ResourceGroups"                        = { [ResourceGroupExporter]::new() }
    "Roles"                                 = { [RolesExporter]::new() }
    "RolesAndAssignments"                   = { [RolesAndAssignmentsExporter]::new() }
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
    # "VpnGateways"             = { [VpnGatewaysExporter]::new() } - Asks for resource group name
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