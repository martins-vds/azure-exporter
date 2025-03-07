# ------------------------------------------------------------------------------------------------------------------------------------------

# Bootstrap Certificate Authentication

# ------------------------------------------------------------------------------------------------------------------------------------------

# Function: Install and Import PowerShell Modules
function Ensure-Module {
    param ($ModuleName)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "[INFO] Installing module: $ModuleName..."
        Install-Module -Name $ModuleName -Force -Scope CurrentUser
    }
    Import-Module -Name $ModuleName -Force
    Write-Host "[INFO] Module '$ModuleName' loaded successfully."
}

# Load Required Modules
Ensure-Module -ModuleName "Az.KeyVault"
Ensure-Module -ModuleName "Microsoft.Graph.Users"
Ensure-Module -ModuleName "Microsoft.Graph.Authentication"

# Define Parameters
$tenantId = "89d18c6d-c5b4-4956-bc2f-f7947ebbaa25"
$clientId = "409a0db7-b96e-4170-bd4c-0706ef8e739e"
$keyVaultName = "KVS01"  # Key Vault name
$certificateName = "SignInTest" # Certificate stored in Key Vault
$certificateObject = $null

# Function: Authenticate as a User (For Initial Checks & Certificate Retrieval)
function Authenticate-Azure-User {
    try {
        Write-Host "[INFO] Authenticating to Azure as a User..."
        Connect-AzAccount -Tenant $tenantId -ErrorAction Stop
        $context = Get-AzContext
        Write-Host "[SUCCESS] User Authenticated: $($context.Account.Id)"
    } catch {
        Write-Error "[ERROR] Azure authentication (User) failed: $_"
        exit
    }
}

# Function: Sign Out the User
function SignOut-Azure {
    try {
        Write-Host "[INFO] Signing out from Azure..."
        Disconnect-AzAccount -ErrorAction Stop
        Write-Host "[SUCCESS] Signed out successfully."
    } catch {
        Write-Error "[ERROR] Failed to sign out: $_"
        exit
    }
}

# Function: Validate Key Vault Exists
function Validate-KeyVault-Exists {
    try {
        $keyVault = Get-AzKeyVault -VaultName $keyVaultName -ErrorAction Stop
        Write-Host "[SUCCESS] Key Vault '$keyVaultName' exists."
    } catch {
        Write-Error "[ERROR] Key Vault '$keyVaultName' does not exist. Please create it before running the script."
        exit
    }
}

# Function: Retrieve Subscription & Resource Group
function Get-SubscriptionDetails {
    try {
        $subscriptionId = (Get-AzSubscription | Where-Object { $_.TenantId -eq $tenantId }).Id
        $resourceGroup = (Get-AzKeyVault -VaultName $keyVaultName).ResourceGroupName
        if (-not $subscriptionId -or -not $resourceGroup) {
            throw "Failed to retrieve Subscription ID or Resource Group."
        }
        Write-Host "[SUCCESS] Subscription ID: $subscriptionId, Resource Group: $resourceGroup"
    } catch {
        Write-Error "[ERROR] Failed to retrieve subscription/resource group: $_"
        exit
    }
}

# Function: Retrieve the Certificate from Key Vault (Using User Authentication)
function Get-Certificate-Using-User {
    try {
        Write-Host "[INFO] Fetching certificate '$certificateName' from Azure Key Vault..."
        $secret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $certificateName -AsPlainText -ErrorAction Stop
        $pfxBytes = [Convert]::FromBase64String($secret)

        # Convert to Secure X509 Certificate Object
        $certificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certificateObject.Import($pfxBytes, $null, "PersistKeySet")
        
        # Ensure Private Key is Available
        if (-not $certificateObject.HasPrivateKey) {
            throw "The certificate does not have an associated private key."
        }

        Write-Host "[SUCCESS] Certificate retrieved and loaded into memory."
        return $certificateObject
    } catch {
        Write-Error "[ERROR] Failed to retrieve certificate from Key Vault: $_"
        exit
    }
}

# ------------------------------------------------------------------------------------------------------------------------------------------

# Service Principal Certificate Based Authentication

# ------------------------------------------------------------------------------------------------------------------------------------------

# Function: Authenticate the App Using the Retrieved Certificate
function Authenticate-Azure-ServicePrincipal {
    try {
        Write-Host "[INFO] Authenticating as a Service Principal using the certificate (OAuth 2.0 - Client Credentials)..."
        
        # Suppress output and warnings while ensuring successful authentication
        $null = Connect-AzAccount -ServicePrincipal -Tenant $tenantId -ApplicationId $clientId -CertificateThumbprint $certificateObject.Thumbprint -ErrorAction Stop -WarningAction SilentlyContinue
        
        Write-Host "[SUCCESS] Service Principal authenticated successfully using OAuth 2.0."
    } catch {
        Write-Error "[ERROR] Azure authentication using Service Principal failed: $_"
        exit
    }
}

# Function: Authenticate to Microsoft Graph
function Authenticate-MicrosoftGraph {
    param ($CertificateObject)
    try {
        Write-Host "[INFO] Authenticating with Microsoft Graph API using OAuth 2.0 (Certificate-Based Auth)..."
        
        # Suppress welcome message
        $null = Connect-MgGraph -TenantId $tenantId -ClientId $clientId -CertificateThumbprint $CertificateObject.Thumbprint -NoWelcome
        
        Write-Host "[SUCCESS] Connected to Microsoft Graph API successfully."
    } catch {
        Write-Error "[ERROR] Failed to authenticate to Microsoft Graph API: $_"
        exit
    }
}

# ------------------------------------------------------------------------------------------------------------------------------------------

# Data Collection Functions Called By Service Principal

# ------------------------------------------------------------------------------------------------------------------------------------------

# Function: Retrieve Users from Microsoft Graph
function Get-GraphUsers {
    try {
        Write-Host "[INFO] Fetching users from Microsoft Graph API..."
        $users = Get-MgUser -Filter "userType eq 'Member'" -Select DisplayName,UserPrincipalName,Id -ErrorAction Stop
        $users | Format-Table DisplayName, UserPrincipalName, Id
        Write-Host "[SUCCESS] Graph API query completed successfully."
    } catch {
        Write-Error "[ERROR] Failed to retrieve users from Microsoft Graph API: $_"
        exit
    }
}

# ------------------------------------------------------------------------------------------------------------------------------------------

# Execution Flow

# ------------------------------------------------------------------------------------------------------------------------------------------
