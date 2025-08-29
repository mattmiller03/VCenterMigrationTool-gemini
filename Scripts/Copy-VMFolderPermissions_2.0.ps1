<#
.SYNOPSIS
    Copies explicit VM folder permissions from a source vCenter to a target vCenter with detailed logging.
.DESCRIPTION
    This script connects to source and target vCenter Servers, identifies matching VM folder 
    structures, and replicates only the explicit permissions (non-inherited) from source folders 
    to corresponding target folders. Ignores system accounts (vpxd, vcls, stctlvm).
    
    Note: This script copies permissions but does not create users/groups or custom roles.
    Ensure that users, groups, and custom roles exist in the target vCenter before running.
.PARAMETER SourceVCenter
    The FQDN or IP address of the source vCenter Server.
.PARAMETER TargetVCenter
    The FQDN or IP address of the target vCenter Server.
.PARAMETER SourceCredential
    PSCredential object for the source vCenter Server.
.PARAMETER TargetCredential
    PSCredential object for the target vCenter Server.
.PARAMETER SourceDatacenterName
    Optional: The name of the specific Datacenter on the Source vCenter whose folder permissions should be copied.
.PARAMETER TargetDatacenterName
    Optional: The name of the specific Datacenter on the Target vCenter where the folder permissions should be applied.
.PARAMETER CopyAllDatacenters
    Switch parameter: If specified, copies permissions for all VM folders from all matching datacenters.
.PARAMETER SkipMissingPrincipals
    Switch parameter: Skip permissions for users/groups that don't exist in target vCenter instead of failing.
.PARAMETER SkipMissingRoles
    Switch parameter: Skip permissions for roles that don't exist in target vCenter instead of failing.
.PARAMETER WhatIf
    Switch parameter: Show what permissions would be copied without actually applying them.
.PARAMETER CreateReport
    Switch parameter: Generate a detailed CSV report of all permissions being copied.
.PARAMETER ReportPath
    Path for the permissions report CSV file. Default: .\VM-Folder-Explicit-Permissions-Report.csv
.PARAMETER AdditionalIgnorePatterns
    Array of additional principal name patterns to ignore (supports wildcards).
.PARAMETER LogPath
    Custom path for log files. Default: .\Logs\
.PARAMETER LogLevel
    Logging level: Error, Warning, Info, Verbose, Debug. Default: Info
.PARAMETER SourceUser
    Optional: Username for the source vCenter (backward compatibility).
.PARAMETER SourcePassword
    Optional: Password for the source vCenter (backward compatibility).
.PARAMETER TargetUser
    Optional: Username for the target vCenter (backward compatibility).
.PARAMETER TargetPassword
    Optional: Password for the target vCenter (backward compatibility).
.NOTES
    Author: PowerShell VM Management Script
    Version: 1.2 - Explicit Permissions with Detailed Logging
    Requires: VMware.PowerCLI module v13.0 or higher
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SourceVCenter,
    
    [Parameter(Mandatory=$true)]
    [string]$TargetVCenter,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$SourceCredential,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$TargetCredential,
    
    [Parameter(Mandatory=$false)]
    [string]$SourceDatacenterName,
    
    [Parameter(Mandatory=$false)]
    [string]$TargetDatacenterName,

    [Parameter(Mandatory=$false)]
    [switch]$ExportMissingPrincipals,

    [Parameter(Mandatory=$false)]
    [string]$MissingPrincipalsReportPath = ".\Missing-Principals-Report.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$CopyAllDatacenters,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipMissingPrincipals,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipMissingRoles,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateReport,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = ".\VM-Folder-Explicit-Permissions-Report.csv",
    
    [Parameter(Mandatory=$false)]
    [string[]]$AdditionalIgnorePatterns = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Error", "Warning", "Info", "Verbose", "Debug")]
    [string]$LogLevel = "Info",
    
    # Backward compatibility parameters
    [Parameter(Mandatory=$false)]
    [string]$SourceUser,
    
    [Parameter(Mandatory=$false)]
    [securestring]$SourcePassword,
    
    [Parameter(Mandatory=$false)]
    [string]$TargetUser,
    
    [Parameter(Mandatory=$false)]
    [securestring]$TargetPassword
)

# Parameter validation
if ($CopyAllDatacenters -and ($SourceDatacenterName -or $TargetDatacenterName)) {
    Write-Warning "CopyAllDatacenters is specified. SourceDatacenterName and TargetDatacenterName parameters will be ignored."
}

# --- Logging Configuration ---
$script:LogLevels = @{
    "Error" = 1
    "Warning" = 2
    "Info" = 3
    "Verbose" = 4
    "Debug" = 5
}

# Global variables
$script:MissingPrincipals = @()
$script:TargetPrincipalsCache = $null
$script:CurrentLogLevel = $script:LogLevels[$LogLevel]
$script:TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Set default log path if not provided
if ([string]::IsNullOrEmpty($LogPath)) {
    $script:LogDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Logs"
} else {
    $script:LogDirectory = $LogPath.TrimEnd('\', '/')
}

# Create logs directory if it doesn't exist
if (-not (Test-Path -Path $script:LogDirectory)) {
    try {
        New-Item -Path $script:LogDirectory -ItemType Directory -Force | Out-Null
    } catch {
        Write-Error "Failed to create log directory '$($script:LogDirectory)': $($_.Exception.Message)"
        exit 1
    }
}

$script:MainLogFile = Join-Path -Path $script:LogDirectory -ChildPath "VMFolderPermissions_$($script:TimeStamp).log"
$script:ErrorLogFile = Join-Path -Path $script:LogDirectory -ChildPath "VMFolderPermissions_Error_$($script:TimeStamp).log"

# --- Configuration ---
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# Global variables for reporting
$script:PermissionsReport = @()
$script:SkippedPermissions = @()
$script:InheritedPermissionsSkipped = 0
$script:SystemAccountsSkipped = 0

# Default system account patterns to ignore
$script:DefaultIgnorePatterns = @(
    "vpxd-*",
    "vcls-*", 
    "stctlvm-*"
)

# Combine default and additional ignore patterns
$script:AllIgnorePatterns = $script:DefaultIgnorePatterns + $AdditionalIgnorePatterns

# --- Logging Functions ---

function Write-LogMessage {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error", "Warning", "Info", "Verbose", "Debug")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )
    
    # Validate that Message is not null or empty
    if ([string]::IsNullOrEmpty($Message)) {
        $Message = "Empty log message"
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Check if we should log this level
    if ($script:LogLevels[$Level] -le $script:CurrentLogLevel) {
        # Write to main log file
        try {
            Add-Content -Path $script:MainLogFile -Value $logEntry -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write to main log file: $($_.Exception.Message)"
        }
        
        # Write to error log if it's an error
        if ($Level -eq "Error") {
            try {
                Add-Content -Path $script:ErrorLogFile -Value $logEntry -ErrorAction Stop
            } catch {
                Write-Warning "Failed to write to error log file: $($_.Exception.Message)"
            }
        }
        
        # Write to console unless suppressed
        if (-not $NoConsole) {
            switch ($Level) {
                "Error" { Write-Host $Message -ForegroundColor Red }
                "Warning" { Write-Host $Message -ForegroundColor Yellow }
                "Info" { Write-Host $Message -ForegroundColor White }
                "Verbose" { if ($VerbosePreference -ne 'SilentlyContinue') { Write-Host $Message -ForegroundColor Cyan } }
                "Debug" { if ($DebugPreference -ne 'SilentlyContinue') { Write-Host $Message -ForegroundColor Magenta } }
            }
        }
    }
}

function Write-LogError {
    param([string]$Message)
    if (-not [string]::IsNullOrEmpty($Message)) {
        Write-LogMessage -Message $Message -Level "Error"
    }
}

function Write-LogWarning {
    param([string]$Message)
    if (-not [string]::IsNullOrEmpty($Message)) {
        Write-LogMessage -Message $Message -Level "Warning"
    }
}

function Write-LogInfo {
    param([string]$Message)
    if (-not [string]::IsNullOrEmpty($Message)) {
        Write-LogMessage -Message $Message -Level "Info"
    }
}

function Write-LogVerbose {
    param([string]$Message)
    if (-not [string]::IsNullOrEmpty($Message)) {
        Write-LogMessage -Message $Message -Level "Verbose"
    }
}

function Write-LogDebug {
    param([string]$Message)
    if (-not [string]::IsNullOrEmpty($Message)) {
        Write-LogMessage -Message $Message -Level "Debug"
    }
}

function Initialize-Logging {
    Write-LogInfo "==================================================================="
    Write-LogInfo "VM Folder Explicit Permissions Copy Script - Version 1.2"
    Write-LogInfo "Started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-LogInfo "==================================================================="
    Write-LogInfo "Script Parameters:"
    Write-LogInfo "  Source vCenter: $($SourceVCenter)"
    Write-LogInfo "  Target vCenter: $($TargetVCenter)"
    Write-LogInfo "  Source Datacenter: $(if($SourceDatacenterName) { $SourceDatacenterName } else { 'Not specified' })"
    Write-LogInfo "  Target Datacenter: $(if($TargetDatacenterName) { $TargetDatacenterName } else { 'Not specified' })"
    Write-LogInfo "  Copy All Datacenters: $($CopyAllDatacenters)"
    Write-LogInfo "  What-If Mode: $($WhatIf)"
    Write-LogInfo "  Skip Missing Principals: $($SkipMissingPrincipals)"
    Write-LogInfo "  Skip Missing Roles: $($SkipMissingRoles)"
    Write-LogInfo "  Log Level: $($LogLevel)"
    Write-LogInfo "  Log Directory: $($script:LogDirectory)"
    Write-LogInfo "  Main Log File: $($script:MainLogFile)"
    Write-LogInfo "  Error Log File: $($script:ErrorLogFile)"
    Write-LogInfo "==================================================================="
    
    # Log ignore patterns
    Write-LogInfo "System account patterns to ignore:"
    foreach ($pattern in $script:AllIgnorePatterns) {
        Write-LogInfo "  - $($pattern)"
    }
    Write-LogInfo ""
}

function Complete-Logging {
    Write-LogInfo "==================================================================="
    Write-LogInfo "Script completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-LogInfo "==================================================================="
    Write-LogInfo "Final Statistics:"
    Write-LogInfo "  Total Explicit Permissions Processed: $($script:PermissionsReport.Count)"
    Write-LogInfo "  Inherited Permissions Skipped: $($script:InheritedPermissionsSkipped)"
    Write-LogInfo "  System Accounts Skipped: $($script:SystemAccountsSkipped)"
    
    if ($script:PermissionsReport.Count -gt 0) {
        $created = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Created' }).Count
        $updated = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Updated' }).Count
        $alreadyExists = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Already Exists' }).Count
        $failed = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Failed' }).Count
        $skipped = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Skipped' }).Count
        
        Write-LogInfo "  Permissions Created: $($created)"
        Write-LogInfo "  Permissions Updated: $($updated)"
        Write-LogInfo "  Permissions Already Existing: $($alreadyExists)"
        Write-LogInfo "  Permissions Failed: $($failed)"
        Write-LogInfo "  Permissions Skipped: $($skipped)"
    }
    
    Write-LogInfo "Log files location: $($script:LogDirectory)"
    Write-LogInfo "==================================================================="
}

# --- Core Functions ---

# Function to resolve credentials with backward compatibility
function Get-ResolvedCredential {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$User,
        [securestring]$Password,
        [string]$ServerType
    )
    
    Write-LogDebug "Resolving credentials for $($ServerType) vCenter: $($ServerName)"
    
    if ($Credential) {
        Write-LogDebug "Using provided PSCredential object for $($ServerType)"
        return $Credential
    }
    
    if ($User) {
        Write-LogDebug "Using provided username for $($ServerType): $($User)"
        if ($Password) {
            return New-Object System.Management.Automation.PSCredential($User, $Password)
        } else {
            return Get-Credential -UserName $User -Message "Enter password for $($User) on $($ServerName) ($($ServerType))"
        }
    }
    
    Write-LogDebug "Prompting for credentials for $($ServerType)"
    return Get-Credential -Message "Enter credentials for $($ServerName) ($($ServerType))"
}

# Function to check if principal should be ignored
function Test-ShouldIgnorePrincipal {
    param(
        [string]$Principal
    )
    
    foreach ($pattern in $script:AllIgnorePatterns) {
        if ($Principal -like $pattern) {
            Write-LogDebug "Principal '$($Principal)' matches ignore pattern '$($pattern)'"
            return $true
        }
    }
    return $false
}

# Function to get folder path for reporting
function Get-FolderPath {
    param($Folder, $Server)
    
    Write-LogDebug "Getting folder path for folder: $($Folder.Name)"
    
    $path = @()
    $currentFolder = $Folder
    
    while ($currentFolder -and $currentFolder.Name -ne 'vm') {
        $path += $currentFolder.Name
        $parent = Get-View -Id $currentFolder.ParentId -Server $Server -ErrorAction SilentlyContinue
        if ($parent -and $parent.MoRef.Type -eq 'Folder') {
            $currentFolder = Get-Folder -Id $parent.MoRef -Server $Server -ErrorAction SilentlyContinue
        } else {
            break
        }
    }
    
    [array]::Reverse($path)
    $folderPath = "/" + ($path -join "/")
    Write-LogDebug "Folder path resolved to: $($folderPath)"
    return $folderPath
}

# Function to validate principal exists in target vCenter
# Enhanced function to validate principal exists in target vCenter
function Test-PrincipalExists {
    param(
        [string]$Principal,
        [object]$TargetServer
    )
    
    Write-LogDebug "Validating if principal '$($Principal)' exists in target vCenter"
    
    try {
        # Use cached principals list if available to improve performance
        if (-not $script:TargetPrincipalsCache) {
            Write-LogDebug "Building target principals cache..."
            $authMgr = Get-View AuthorizationManager -Server $TargetServer
            $allPermissions = $authMgr.RetrieveAllPermissions()
            $script:TargetPrincipalsCache = $allPermissions | Select-Object -ExpandProperty Principal -Unique
            Write-LogDebug "Cached $($script:TargetPrincipalsCache.Count) unique principals from target"
        }
        
        $exists = $script:TargetPrincipalsCache -contains $Principal
        Write-LogDebug "Principal '$($Principal)' exists in target: $($exists)"
        
        # If principal doesn't exist, add to missing list
        if (-not $exists) {
            Add-MissingPrincipal -Principal $Principal -TargetServer $TargetServer
        }
        
        return $exists
    } catch {
        Write-LogDebug "Error validating principal '$($Principal)': $($_.Exception.Message)"
        # On error, add to missing list to be safe
        Add-MissingPrincipal -Principal $Principal -TargetServer $TargetServer
        return $false
    }
}

# Function to add missing principal to tracking list
function Add-MissingPrincipal {
    param(
        [string]$Principal,
        [object]$TargetServer
    )
    
    # Check if already in the list
    $existing = $script:MissingPrincipals | Where-Object { $_.Principal -eq $Principal }
    if ($existing) {
        $existing.OccurrenceCount++
        $existing.LastSeen = Get-Date
        Write-LogDebug "Updated occurrence count for missing principal: $($Principal)"
    } else {
        # Determine principal type
        $principalType = Get-PrincipalType -Principal $Principal
        
        $missingPrincipalInfo = [PSCustomObject]@{
            Principal = $Principal
            PrincipalType = $principalType
            Domain = Get-PrincipalDomain -Principal $Principal
            AccountName = Get-PrincipalAccountName -Principal $Principal
            OccurrenceCount = 1
            FirstSeen = Get-Date
            LastSeen = Get-Date
            Recommendations = Get-PrincipalRecommendations -Principal $Principal -PrincipalType $principalType
        }
        
        $script:MissingPrincipals += $missingPrincipalInfo
        Write-LogDebug "Added missing principal to tracking list: $($Principal)"
    }
}

# Function to generate recommendations for creating missing principals
function Get-PrincipalRecommendations {
    param(
        [string]$Principal,
        [string]$PrincipalType
    )
    
    $recommendations = @()
    
    switch ($PrincipalType) {
        "User or Group" {
            $recommendations += "Verify if this is a user or group in the source domain"
            $recommendations += "Create/import this principal in target vCenter's identity source"
            $recommendations += "If it's a group, ensure all necessary members are included"
        }
        "Group" {
            $recommendations += "Create this group in target vCenter's identity source"
            $recommendations += "Add appropriate members to the group"
            $recommendations += "Verify group permissions align with source environment"
        }
        "UPN (User Principal Name)" {
            $recommendations += "Create this user account in target vCenter's identity source"
            $recommendations += "Ensure UPN suffix matches target domain configuration"
        }
        "Computer Account" {
            $recommendations += "This appears to be a computer account"
            $recommendations += "Verify if computer account is needed in target environment"
            $recommendations += "Join computer to target domain if required"
        }
        "SID (Security Identifier)" {
            $recommendations += "This is a SID - the original account may have been deleted"
            $recommendations += "Identify the original account name and recreate if needed"
            $recommendations += "Consider if this permission is still required"
        }
        default {
            $recommendations += "Manual review required to determine account type"
            $recommendations += "Check source environment for account details"
        }
    }
    
    return ($recommendations -join "; ")
}

# Function to export missing principals report
function Export-MissingPrincipalsReport {
    param(
        [string]$FilePath
    )
    
    Write-LogInfo "Generating missing principals report..."
    
    if ($script:MissingPrincipals.Count -eq 0) {
        Write-LogInfo "No missing principals found - all principals exist in target vCenter"
        
        # Create empty report file with headers
        $emptyReport = [PSCustomObject]@{
            Principal = "No missing principals found"
            PrincipalType = ""
            Domain = ""
            AccountName = ""
            OccurrenceCount = 0
            FirstSeen = ""
            LastSeen = ""
            Recommendations = "All principals from source exist in target vCenter"
        }
        
        try {
            # Ensure report directory exists
            $reportDir = Split-Path -Path $FilePath -Parent
            if (-not (Test-Path -Path $reportDir)) {
                New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
                Write-LogDebug "Created missing principals report directory: $($reportDir)"
            }
            
            $emptyReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
            Write-LogInfo "Empty missing principals report exported to: $($FilePath)"
        } catch {
            Write-LogError "Failed to export empty missing principals report: $($_.Exception.Message)"
        }
        return
    }
    
    try {
        # Ensure report directory exists
        $reportDir = Split-Path -Path $FilePath -Parent
        if (-not (Test-Path -Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
            Write-LogDebug "Created missing principals report directory: $($reportDir)"
        }
        
        # Sort by occurrence count (most frequent first) then by principal name
        $sortedMissingPrincipals = $script:MissingPrincipals | Sort-Object @{Expression="OccurrenceCount"; Descending=$true}, @{Expression="Principal"; Descending=$false}     

        $sortedMissingPrincipals | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
        Write-LogInfo "Missing principals report exported to: $($FilePath)"
        
        # Display summary
        $totalMissingPrincipals = $script:MissingPrincipals.Count
        $totalOccurrences = ($script:MissingPrincipals | Measure-Object -Property OccurrenceCount -Sum).Sum
        $userAccounts = ($script:MissingPrincipals | Where-Object { $_.PrincipalType -like "*User*" }).Count
        $groupAccounts = ($script:MissingPrincipals | Where-Object { $_.PrincipalType -like "*Group*" }).Count
        $computerAccounts = ($script:MissingPrincipals | Where-Object { $_.PrincipalType -eq "Computer Account" }).Count
        $unknownAccounts = ($script:MissingPrincipals | Where-Object { $_.PrincipalType -eq "Unknown" }).Count
        
        Write-LogInfo "Missing Principals Summary:"
        Write-LogInfo "  Total Missing Principals: $($totalMissingPrincipals)"
        Write-LogInfo "  Total Permission References: $($totalOccurrences)"
        Write-LogInfo "  User Accounts: $($userAccounts)"
        Write-LogInfo "  Group Accounts: $($groupAccounts)"
        Write-LogInfo "  Computer Accounts: $($computerAccounts)"
        Write-LogInfo "  Unknown/SID Accounts: $($unknownAccounts)"
        
        # Log top missing principals
        Write-LogInfo "Top Missing Principals (by occurrence):"
        $topMissing = $sortedMissingPrincipals | Select-Object -First 10
        foreach ($principal in $topMissing) {
            Write-LogInfo "  $($principal.Principal) ($($principal.PrincipalType)) - $($principal.OccurrenceCount) occurrence(s)"
        }
        
        # Console output
        Write-Host "`nMissing Principals Summary:" -ForegroundColor Yellow
        Write-Host "  Total Missing Principals: $($totalMissingPrincipals)" -ForegroundColor White
        Write-Host "  Total Permission References: $($totalOccurrences)" -ForegroundColor White
        Write-Host "  User Accounts: $($userAccounts)" -ForegroundColor Cyan
        Write-Host "  Group Accounts: $($groupAccounts)" -ForegroundColor Cyan
        Write-Host "  Computer Accounts: $($computerAccounts)" -ForegroundColor Cyan
        Write-Host "  Unknown/SID Accounts: $($unknownAccounts)" -ForegroundColor Red
        Write-Host "  Report saved to: $($FilePath)" -ForegroundColor Green
        
    } catch {
        $errorMsg = "Failed to export missing principals report to '$($FilePath)': $($_.Exception.Message)"
        Write-LogError $errorMsg
    }
}

# Function to extract domain from principal
function Get-PrincipalDomain {
    param([string]$Principal)
    
    if ($Principal -contains '\') {
        return $Principal.Split('\')[0]
    } elseif ($Principal -contains '@') {
        return $Principal.Split('@')[1]
    } else {
        return "Unknown"
    }
}

# Function to extract account name from principal
function Get-PrincipalAccountName {
    param([string]$Principal)
    
    if ($Principal -contains '\') {
        return $Principal.Split('\')[1]
    } elseif ($Principal -contains '@') {
        return $Principal.Split('@')[0]
    } else {
        return $Principal
    }
}

# Function to validate role exists in target vCenter
function Test-RoleExists {
    param(
        [string]$RoleName,
        [object]$TargetServer
    )
    
    Write-LogDebug "Validating if role '$($RoleName)' exists in target vCenter"
    
    try {
        $role = Get-VIRole -Name $RoleName -Server $TargetServer -ErrorAction SilentlyContinue
        $exists = $null -ne $role
        Write-LogDebug "Role '$($RoleName)' exists in target: $($exists)"
        return $exists
    } catch {
        Write-LogDebug "Error validating role '$($RoleName)': $($_.Exception.Message)"
        return $false
    }
}

# Function to check if permission is explicitly set (not inherited)
# Function to check if permission is explicitly set (not inherited)
function Test-IsExplicitPermission {
    param(
        $Permission,
        $Entity,
        $Server
    )
    
    Write-LogDebug "Checking if permission is explicit for Principal: '$($Permission.Principal)', Role: '$($Permission.Role)' on entity: '$($Entity.Name)'"
    
    try {
        # Validate inputs
        if (-not $Permission) {
            Write-LogDebug "Permission object is null"
            return $false
        }
        
        if (-not $Entity) {
            Write-LogDebug "Entity object is null"
            return $false
        }
        
        if (-not $Server) {
            Write-LogDebug "Server object is null"
            return $false
        }
        
        # Get the entity view to check for explicit permissions
        Write-LogDebug "Getting entity view for: $($Entity.Name)"
        $entityView = Get-View -Id $Entity.Id -Server $Server -ErrorAction Stop
        
        if (-not $entityView) {
            Write-LogDebug "EntityView is null"
            return $false
        }
        
        # Get AuthorizationManager
        Write-LogDebug "Getting AuthorizationManager"
        $authMgr = Get-View -Id 'AuthorizationManager-AuthorizationManager' -Server $Server -ErrorAction Stop
        
        if (-not $authMgr) {
            Write-LogDebug "AuthorizationManager is null"
            return $false
        }
        
        # Get permissions specifically for this entity (not inherited)
        Write-LogDebug "Retrieving entity permissions for: $($entityView.MoRef.Type):$($entityView.MoRef.Value)"
        $explicitPermissions = $authMgr.RetrieveEntityPermissions($entityView.MoRef, $false)
        
        if (-not $explicitPermissions) {
            Write-LogDebug "No explicit permissions found"
            return $false
        }
        
        Write-LogDebug "Found $($explicitPermissions.Count) explicit permissions"
        
        # Get the role ID for the permission we're checking
        $roleId = $null
        try {
            $role = Get-VIRole -Name $Permission.Role -Server $Server -ErrorAction Stop
            $roleId = $role.Id
            Write-LogDebug "Role '$($Permission.Role)' has ID: $($roleId)"
        } catch {
            Write-LogDebug "Could not get role ID for '$($Permission.Role)': $($_.Exception.Message)"
            return $false
        }
        
        # Check if this specific permission is in the explicit permissions list
        foreach ($explicitPerm in $explicitPermissions) {
            Write-LogDebug "Comparing: Principal='$($explicitPerm.Principal)' vs '$($Permission.Principal)', RoleId='$($explicitPerm.RoleId)' vs '$($roleId)'"
            
            if ($explicitPerm.Principal -eq $Permission.Principal -and 
                $explicitPerm.RoleId -eq $roleId) {
                Write-LogDebug "Permission is explicit"
                return $true
            }
        }
        
        Write-LogDebug "Permission is inherited"
        return $false
        
    } catch [System.Net.WebException] {
        Write-LogDebug "Network error checking explicit permission: $($_.Exception.Message)"
        # On network errors, assume it's explicit to be safe
        return $true
    } catch [System.Management.Automation.RuntimeException] {
        Write-LogDebug "Runtime error checking explicit permission: $($_.Exception.Message)"
        # On runtime errors, assume it's explicit to be safe
        return $true
    } catch {
        Write-LogDebug "Unexpected error checking explicit permission: $($_.Exception.Message)"
        Write-LogDebug "Error type: $($_.Exception.GetType().FullName)"
        # On any other error, assume it's explicit to be safe
        return $true
    }
}

# Function to determine principal type (User, Group, or Unknown)
function Get-PrincipalType {
    param([string]$Principal)
    
    # Common patterns for determining principal type
    if ($Principal -match '^[^\\]+\\.*\$$') {
        return "Computer Account"
    } elseif ($Principal -match '^[^\\]+\\.*\s+(Users|Admins|Operators|Group)$') {
        return "Group"
    } elseif ($Principal -match '^[^\\]+\\[^\\]+$') {
        return "User or Group"
    } elseif ($Principal -match '^.*@.*\..*$') {
        return "UPN (User Principal Name)"
    } elseif ($Principal -match '^S-1-') {
        return "SID (Security Identifier)"
    } else {
        return "Unknown"
    }
}
# Function to copy explicit permissions for a specific folder
function Copy-FolderExplicitPermissions {
    param(
        [Parameter(Mandatory=$true)]
        $SourceFolder,
        [Parameter(Mandatory=$true)]
        $TargetFolder,
        [Parameter(Mandatory=$true)]
        $SourceServer,
        [Parameter(Mandatory=$true)]
        $TargetServer,
        [Parameter(Mandatory=$true)]
        [string]$DatacenterContext
    )
    
    $sourceFolderPath = Get-FolderPath -Folder $SourceFolder -Server $SourceServer
    $targetFolderPath = Get-FolderPath -Folder $TargetFolder -Server $TargetServer
    
    Write-LogInfo "Processing explicit permissions for folder: '$($SourceFolder.Name)' ($($sourceFolderPath))"
    
    try {
        # Get ALL permissions from source folder (including inherited)
        Write-LogDebug "Retrieving all permissions from source folder '$($SourceFolder.Name)'"
        $allSourcePermissions = Get-VIPermission -Entity $SourceFolder -Server $SourceServer -ErrorAction Stop
        
        if (-not $allSourcePermissions) {
            Write-LogVerbose "No permissions found on source folder '$($SourceFolder.Name)'"
            return
        }
        
        Write-LogDebug "Found $($allSourcePermissions.Count) total permissions on source folder"
        
        # Filter for explicit permissions only
        $explicitPermissions = @()
        foreach ($permission in $allSourcePermissions) {
            if (Test-IsExplicitPermission -Permission $permission -Entity $SourceFolder -Server $SourceServer) {
                $explicitPermissions += $permission
                Write-LogDebug "Added explicit permission: Principal='$($permission.Principal)', Role='$($permission.Role)'"
            } else {
                $script:InheritedPermissionsSkipped++
                Write-LogVerbose "Skipping inherited permission: Principal='$($permission.Principal)', Role='$($permission.Role)'"
            }
        }
        
        if ($explicitPermissions.Count -eq 0) {
            Write-LogVerbose "No explicit permissions found on source folder '$($SourceFolder.Name)'"
            return
        }
        
        Write-LogInfo "Found $($explicitPermissions.Count) explicit permission(s) on source folder (filtered from $($allSourcePermissions.Count) total)"
        
        foreach ($permission in $explicitPermissions) {
            # Check if principal should be ignored
            if (Test-ShouldIgnorePrincipal -Principal $permission.Principal) {
                Write-LogInfo "Skipping system account: '$($permission.Principal)'"
                $script:SystemAccountsSkipped++
                continue
            }
            
            $permissionInfo = [PSCustomObject]@{
                Datacenter = $DatacenterContext
                SourceFolder = $SourceFolder.Name
                SourceFolderPath = $sourceFolderPath
                TargetFolder = $TargetFolder.Name
                TargetFolderPath = $targetFolderPath
                Principal = $permission.Principal
                Role = $permission.Role
                Propagate = $permission.Propagate
                PermissionType = "Explicit"
                Status = "Pending"
                ErrorMessage = ""
                PrincipalExists = $false
                RoleExists = $false
                Timestamp = Get-Date
            }
            
            Write-LogInfo "Processing explicit permission: Principal='$($permission.Principal)', Role='$($permission.Role)', Propagate=$($permission.Propagate)"
            
            # Validate role exists in target
            $roleExists = Test-RoleExists -RoleName $permission.Role -TargetServer $TargetServer
            $permissionInfo.RoleExists = $roleExists
            
            if (-not $roleExists) {
                $errorMsg = "Role '$($permission.Role)' does not exist in target vCenter"
                Write-LogWarning $errorMsg
                $permissionInfo.Status = "Skipped - Missing Role"
                $permissionInfo.ErrorMessage = $errorMsg
                
                if (-not $SkipMissingRoles) {
                    Write-LogError "$($errorMsg). Use -SkipMissingRoles to continue with other permissions."
                    $script:SkippedPermissions += $permissionInfo
                    $script:PermissionsReport += $permissionInfo
                    continue
                } else {
                    Write-LogInfo "Skipping permission due to missing role (SkipMissingRoles enabled)"
                    $script:PermissionsReport += $permissionInfo
                    continue
                }
            }
            
            # Validate principal exists in target
            $principalExists = Test-PrincipalExists -Principal $permission.Principal -TargetServer $TargetServer
            $permissionInfo.PrincipalExists = $principalExists
            
            if (-not $principalExists) {
                $errorMsg = "Principal '$($permission.Principal)' does not exist in target vCenter"
                Write-LogWarning $errorMsg
                
                if ($SkipMissingPrincipals) {
                    Write-LogInfo "Skipping permission for missing principal: '$($permission.Principal)'"
                    $permissionInfo.Status = "Skipped - Missing Principal"
                    $permissionInfo.ErrorMessage = $errorMsg
                    $script:PermissionsReport += $permissionInfo
                    continue
                } else {
                    Write-LogWarning "Permission may fail for missing principal. Use -SkipMissingPrincipals to skip these."
                    Write-LogWarning "Attempting to create permission anyway - it may fail during execution."
                    # Continue anyway - let it fail during permission creation and be logged
                }
            } else {
                Write-LogDebug "Principal '$($permission.Principal)' exists in target vCenter"
            }
            
            if ($WhatIf) {
                Write-LogInfo "[WHATIF] Would set explicit permission: Principal='$($permission.Principal)', Role='$($permission.Role)', Propagate=$($permission.Propagate)"
                $permissionInfo.Status = "WhatIf"
                
                # Even in WhatIf mode, note if there would be issues
                if (-not $principalExists) {
                    $permissionInfo.Status = "WhatIf - Would Fail (Missing Principal)"
                    $permissionInfo.ErrorMessage = "Principal does not exist in target"
                }
                
                $script:PermissionsReport += $permissionInfo
            } else {
                try {
                    # Check if permission already exists on target folder
                    Write-LogDebug "Checking for existing permission on target folder for principal '$($permission.Principal)'"
                    $existingPermission = Get-VIPermission -Entity $TargetFolder -Principal $permission.Principal -Server $TargetServer -ErrorAction SilentlyContinue
                    
                    if ($existingPermission) {
                        # Check if existing permission is the same
                        $existingExplicit = $existingPermission | Where-Object { 
                            Test-IsExplicitPermission -Permission $_ -Entity $TargetFolder -Server $TargetServer 
                        }
                        
                        if ($existingExplicit -and $existingExplicit.Role -eq $permission.Role -and $existingExplicit.Propagate -eq $permission.Propagate) {
                            Write-LogInfo "Explicit permission for principal '$($permission.Principal)' already exists with same settings. Skipping."
                            $permissionInfo.Status = "Already Exists"
                        } else {
                            Write-LogInfo "Different permission for principal '$($permission.Principal)' exists on target folder. Updating..."
                            
                            # Remove existing permission first
                            try {
                                $existingPermission | Remove-VIPermission -Confirm:$false -ErrorAction Stop
                                Write-LogDebug "Removed existing permission for principal '$($permission.Principal)'"
                            } catch {
                                Write-LogWarning "Failed to remove existing permission for '$($permission.Principal)': $($_.Exception.Message)"
                                # Continue anyway and try to create new one
                            }
                            
                            # Create new permission
                            try {
                                $newPermission = New-VIPermission -Entity $TargetFolder -Principal $permission.Principal -Role $permission.Role -Propagate:$permission.Propagate -Server $TargetServer -ErrorAction Stop
                                Write-LogInfo "Successfully updated explicit permission for '$($permission.Principal)'"
                                Write-LogDebug "New permission created with ID: $($newPermission.Id)"
                                $permissionInfo.Status = "Updated"
                            } catch {
                                $errorMsg = "Failed to create updated permission for '$($permission.Principal)': $($_.Exception.Message)"
                                Write-LogError $errorMsg
                                $permissionInfo.Status = "Failed - Update"
                                $permissionInfo.ErrorMessage = $errorMsg
                            }
                        }
                    } else {
                        # Create new permission
                        Write-LogDebug "Creating new permission for principal '$($permission.Principal)'"
                        try {
                            $newPermission = New-VIPermission -Entity $TargetFolder -Principal $permission.Principal -Role $permission.Role -Propagate:$permission.Propagate -Server $TargetServer -ErrorAction Stop
                            Write-LogInfo "Successfully created explicit permission for '$($permission.Principal)'"
                            Write-LogDebug "New permission created with ID: $($newPermission.Id)"
                            $permissionInfo.Status = "Created"
                        } catch {
                            $errorMsg = "Failed to create new permission for '$($permission.Principal)': $($_.Exception.Message)"
                            Write-LogError $errorMsg
                            $permissionInfo.Status = "Failed - Create"
                            $permissionInfo.ErrorMessage = $errorMsg
                            
                            # Check if the error is due to missing principal
                            if ($_.Exception.Message -like "*not found*" -or $_.Exception.Message -like "*does not exist*") {
                                $permissionInfo.Status = "Failed - Principal Not Found"
                                Write-LogError "Confirmed: Principal '$($permission.Principal)' does not exist in target vCenter"
                            }
                        }
                    }
                    
                } catch {
                    $errorMsg = "Unexpected error processing permission for '$($permission.Principal)': $($_.Exception.Message)"
                    Write-LogError $errorMsg
                    $permissionInfo.Status = "Failed - Unexpected Error"
                    $permissionInfo.ErrorMessage = $errorMsg
                }
                
                $script:PermissionsReport += $permissionInfo
            }
        }
        
    } catch {
        $errorMsg = "Failed to get permissions from source folder '$($SourceFolder.Name)': $($_.Exception.Message)"
        Write-LogError $errorMsg
        
        # Create error entry in report
        $errorPermissionInfo = [PSCustomObject]@{
            Datacenter = $DatacenterContext
            SourceFolder = $SourceFolder.Name
            SourceFolderPath = $sourceFolderPath
            TargetFolder = $TargetFolder.Name
            TargetFolderPath = $targetFolderPath
            Principal = "ERROR"
            Role = "ERROR"
            Propagate = $false
            PermissionType = "Error"
            Status = "Failed - Source Read Error"
            ErrorMessage = $errorMsg
            PrincipalExists = $false
            RoleExists = $false
            Timestamp = Get-Date
        }
        $script:PermissionsReport += $errorPermissionInfo
    }
}

# Recursive function to process folder structure and copy explicit permissions
function Copy-FolderStructureExplicitPermissions {
    param(
        [Parameter(Mandatory=$true)]
        $SourceParentFolder,
        [Parameter(Mandatory=$true)]
        $TargetParentFolder,
        [Parameter(Mandatory=$true)]
        $SourceServer,
        [Parameter(Mandatory=$true)]
        $TargetServer,
        [Parameter(Mandatory=$true)]
        [string]$DatacenterContext
    )
    
    Write-LogDebug "Processing folder structure for: '$($SourceParentFolder.Name)'"
    
    # Copy explicit permissions for the current folder
    Copy-FolderExplicitPermissions -SourceFolder $SourceParentFolder -TargetFolder $TargetParentFolder -SourceServer $SourceServer -TargetServer $TargetServer -DatacenterContext $DatacenterContext
    
    # Get child folders from source
    Write-LogDebug "Getting child folders from source folder: '$($SourceParentFolder.Name)'"
    $sourceChildFolders = Get-Folder -Location $SourceParentFolder -Type VM -Server $SourceServer -NoRecursion -ErrorAction SilentlyContinue
    
    if ($null -eq $sourceChildFolders) {
        Write-LogVerbose "No child VM folders found under '$($SourceParentFolder.Name)'"
        return
    }
    
    Write-LogDebug "Found $($sourceChildFolders.Count) child folder(s) under '$($SourceParentFolder.Name)'"
    
    foreach ($sourceFolder in $sourceChildFolders) {
        Write-LogDebug "Processing child folder: '$($sourceFolder.Name)'"
        
        # Find corresponding folder in target
        $targetFolder = Get-Folder -Location $TargetParentFolder -Name $sourceFolder.Name -Type VM -Server $TargetServer -NoRecursion -ErrorAction SilentlyContinue
        
        if (-not $targetFolder) {
            Write-LogWarning "Target folder '$($sourceFolder.Name)' not found under '$($TargetParentFolder.Name)'. Skipping explicit permissions copy for this folder and its children."
            continue
        }
        
        Write-LogDebug "Found matching target folder: '$($targetFolder.Name)'"
        
        # Recurse into child folders
        Copy-FolderStructureExplicitPermissions -SourceParentFolder $sourceFolder -TargetParentFolder $targetFolder -SourceServer $SourceServer -TargetServer $TargetServer -DatacenterContext $DatacenterContext
    }
}

# Function to copy explicit permissions for a specific datacenter pair
function Copy-DatacenterExplicitPermissions {
    param(
        [Parameter(Mandatory=$true)]
        $SourceDatacenter,
        [Parameter(Mandatory=$true)]
        $TargetDatacenter,
        [Parameter(Mandatory=$true)]
        $SourceServer,
        [Parameter(Mandatory=$true)]
        $TargetServer
    )
    
    Write-LogInfo "Processing explicit permissions for Datacenter: '$($SourceDatacenter.Name)' -> '$($TargetDatacenter.Name)'"
    
    # Get the root VM folder for the source datacenter
    Write-LogDebug "Getting root VM folder for source datacenter: '$($SourceDatacenter.Name)'"
    $sourceRootVmFolder = Get-Folder -Location $SourceDatacenter -Type VM -Server $SourceServer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'vm' }
    
    if (-not $sourceRootVmFolder) {
        Write-LogWarning "Root VM folder ('vm') not found in Source Datacenter '$($SourceDatacenter.Name)'. Skipping."
        return
    }
    
    Write-LogDebug "Found source root VM folder: '$($sourceRootVmFolder.Name)'"
    
    # Get the root VM folder for the target datacenter
    Write-LogDebug "Getting root VM folder for target datacenter: '$($TargetDatacenter.Name)'"
    $targetRootVmFolder = Get-Folder -Location $TargetDatacenter -Type VM -Server $TargetServer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'vm' }
    
    if (-not $targetRootVmFolder) {
        Write-LogWarning "Root VM folder ('vm') not found in Target Datacenter '$($TargetDatacenter.Name)'. Skipping."
        return
    }
    
    Write-LogDebug "Found target root VM folder: '$($targetRootVmFolder.Name)'"
    
    Write-LogInfo "Starting explicit permissions copy from Source DC '$($SourceDatacenter.Name)' to Target DC '$($TargetDatacenter.Name)'..."
    
    # Start the recursive explicit permissions copy process
    Copy-FolderStructureExplicitPermissions -SourceParentFolder $sourceRootVmFolder -TargetParentFolder $targetRootVmFolder -SourceServer $SourceServer -TargetServer $TargetServer -DatacenterContext $SourceDatacenter.Name
    
    Write-LogInfo "Finished explicit permissions copy for Datacenter '$($SourceDatacenter.Name)' -> '$($TargetDatacenter.Name)'."
}

# Function to generate permissions report
function Export-PermissionsReport {
    param(
        [string]$FilePath
    )
    
    Write-LogInfo "Generating explicit permissions report..."
    
    if ($script:PermissionsReport.Count -eq 0) {
        Write-LogWarning "No explicit permissions data to report."
        return
    }
    
    try {
        # Ensure report directory exists
        $reportDir = Split-Path -Path $FilePath -Parent
        if (-not (Test-Path -Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
            Write-LogDebug "Created report directory: $($reportDir)"
        }
        
        $script:PermissionsReport | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
        Write-LogInfo "Explicit permissions report exported to: $($FilePath)"
        
        # Display detailed summary
        $totalPermissions = $script:PermissionsReport.Count
        $createdPermissions = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Created' }).Count
        $updatedPermissions = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Updated' }).Count
        $alreadyExistsPermissions = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Already Exists' }).Count
        $failedPermissions = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Failed' }).Count
        $skippedPermissions = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Skipped' }).Count
        $whatIfPermissions = ($script:PermissionsReport | Where-Object { $_.Status -eq 'WhatIf' }).Count
        
        Write-LogInfo "Explicit Permissions Summary:"
        Write-LogInfo "  Total Explicit Permissions Processed: $($totalPermissions)"
        Write-LogInfo "  Inherited Permissions Skipped: $($script:InheritedPermissionsSkipped)"
        Write-LogInfo "  System Accounts Skipped: $($script:SystemAccountsSkipped)"
        
        if ($whatIfPermissions -gt 0) {
            Write-LogInfo "  What-If Permissions: $($whatIfPermissions)"
        } else {
            Write-LogInfo "  Created: $($createdPermissions)"
            Write-LogInfo "  Updated: $($updatedPermissions)"
            Write-LogInfo "  Already Exists: $($alreadyExistsPermissions)"
            Write-LogInfo "  Failed: $($failedPermissions)"
            Write-LogInfo "  Skipped: $($skippedPermissions)"
        }
        
        # Log ignored patterns used
        Write-LogInfo "Ignored Principal Patterns:"
        foreach ($pattern in $script:AllIgnorePatterns) {
            Write-LogInfo "  - $($pattern)"
        }
        
        # Log detailed statistics to file
        Write-LogInfo "Detailed statistics logged to: $($script:MainLogFile)"
        
    } catch {
        $errorMsg = "Failed to export report to '$($FilePath)': $($_.Exception.Message)"
        Write-LogError $errorMsg
    }
}

# Function to validate prerequisites
function Test-Prerequisites {
    param(
        $SourceServer,
        $TargetServer
    )
    
    Write-LogInfo "Validating prerequisites..."
    
    # Test if we can read permissions from source
    try {
        Write-LogDebug "Testing source vCenter AuthorizationManager access"
        $testSourcePermissions = Get-View AuthorizationManager -Server $SourceServer -ErrorAction Stop
        Write-LogInfo "Source vCenter: Permission read access confirmed"
    } catch {
        Write-LogError "Source vCenter: Cannot access AuthorizationManager. Check permissions. Error: $($_.Exception.Message)"
        return $false
    }
    
    # Test if we can read permissions and roles from target
    try {
        Write-LogDebug "Testing target vCenter AuthorizationManager and roles access"
        $testTargetPermissions = Get-View AuthorizationManager -Server $TargetServer -ErrorAction Stop
        $testRoles = Get-VIRole -Server $TargetServer -ErrorAction Stop
        Write-LogInfo "Target vCenter: Permission read/write access confirmed"
        Write-LogDebug "Found $($testRoles.Count) roles in target vCenter"
    } catch {
        Write-LogError "Target vCenter: Cannot access AuthorizationManager or Roles. Check permissions. Error: $($_.Exception.Message)"
        return $false
    }
    
    # Test PowerCLI version
    try {
        $powerCLIVersion = Get-Module -Name VMware.PowerCLI -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        if ($powerCLIVersion) {
            Write-LogInfo "PowerCLI Version: $($powerCLIVersion.Version)"
        } else {
            Write-LogWarning "PowerCLI module not found or version cannot be determined"
        }
    } catch {
        Write-LogWarning "Could not determine PowerCLI version: $($_.Exception.Message)"
    }
    
    Write-LogInfo "Prerequisites validation completed successfully"
    return $true
}

# --- Main Script Logic ---
$sourceVIServer = $null
$targetVIServer = $null

try {
    # Initialize logging
    Initialize-Logging
    
    # Display ignore patterns at start
    Write-LogInfo "System account patterns that will be ignored:"
    foreach ($pattern in $script:AllIgnorePatterns) {
        Write-LogInfo "  - $($pattern)"
    }
    
    # Resolve credentials
    Write-LogInfo "Resolving credentials..."
    $resolvedSourceCredential = Get-ResolvedCredential -ServerName $SourceVCenter -Credential $SourceCredential -User $SourceUser -Password $SourcePassword -ServerType "Source"
    $resolvedTargetCredential = Get-ResolvedCredential -ServerName $TargetVCenter -Credential $TargetCredential -User $TargetUser -Password $TargetPassword -ServerType "Target"
    
    if (-not $resolvedSourceCredential -or -not $resolvedTargetCredential) {
        throw "Failed to obtain valid credentials for both source and target vCenters."
    }
    
    Write-LogInfo "Credentials resolved successfully"
    
    # Connect to Source vCenter
    Write-LogInfo "Connecting to Source vCenter: $($SourceVCenter)..."
    $sourceVIServer = Connect-VIServer -Server $SourceVCenter -Credential $resolvedSourceCredential -ErrorAction Stop
    Write-LogInfo "Connected to Source: $($sourceVIServer.Name) ($($sourceVIServer.Version))"
    
    # Connect to Target vCenter
    Write-LogInfo "Connecting to Target vCenter: $($TargetVCenter)..."
    $targetVIServer = Connect-VIServer -Server $TargetVCenter -Credential $resolvedTargetCredential -ErrorAction Stop
    Write-LogInfo "Connected to Target: $($targetVIServer.Name) ($($targetVIServer.Version))"
    
    # Validate prerequisites
    if (-not (Test-Prerequisites -SourceServer $sourceVIServer -TargetServer $targetVIServer)) {
        throw "Prerequisites validation failed. Please check permissions and try again."
    }
    
    if ($WhatIf) {
        Write-LogInfo "*** RUNNING IN WHAT-IF MODE - NO PERMISSIONS WILL BE MODIFIED ***"
        Write-LogInfo "*** ONLY EXPLICIT PERMISSIONS WILL BE ANALYZED ***"
    } else {
        Write-LogInfo "*** COPYING EXPLICIT PERMISSIONS ONLY ***"
        Write-LogInfo "*** INHERITED PERMISSIONS AND SYSTEM ACCOUNTS WILL BE IGNORED ***"
    }
    
    if ($CopyAllDatacenters) {
        # Copy explicit permissions for all datacenters
        Write-LogInfo "Retrieving all datacenters from source vCenter..."
        $sourceDatacenters = Get-Datacenter -Server $sourceVIServer -ErrorAction Stop
        
        if (-not $sourceDatacenters) {
            throw "No datacenters found in source vCenter '$($SourceVCenter)'."
        }
        
        Write-LogInfo "Found $($sourceDatacenters.Count) datacenter(s) in source vCenter."
        
        foreach ($sourceDc in $sourceDatacenters) {
            Write-LogInfo "Processing source datacenter: '$($sourceDc.Name)'"
            
            # Check if target datacenter exists
            $targetDc = Get-Datacenter -Name $sourceDc.Name -Server $targetVIServer -ErrorAction SilentlyContinue
            
            if (-not $targetDc) {
                Write-LogWarning "Target datacenter '$($sourceDc.Name)' not found in target vCenter. Skipping explicit permissions copy for this datacenter."
                continue
            } else {
                Write-LogInfo "Found matching target datacenter: '$($targetDc.Name)'"
            }
            
            # Copy explicit permissions for this datacenter pair
            Copy-DatacenterExplicitPermissions -SourceDatacenter $sourceDc -TargetDatacenter $targetDc -SourceServer $sourceVIServer -TargetServer $targetVIServer
        }
        
        Write-LogInfo "Completed copying explicit permissions for all datacenters."
        
    } else {
        # Copy explicit permissions for specific datacenter(s)
        $sourceDcName = $SourceDatacenterName
        $targetDcName = $TargetDatacenterName
        
        # If datacenter names not provided, prompt user to select
        if (-not $sourceDcName) {
            Write-LogInfo "No source datacenter specified. Retrieving available datacenters..."
            $availableSourceDCs = Get-Datacenter -Server $sourceVIServer -ErrorAction Stop
            
            if (-not $availableSourceDCs) {
                throw "No datacenters found in source vCenter '$($SourceVCenter)'."
            }
            
            Write-LogInfo "Available datacenters in source vCenter:"
            for ($i = 0; $i -lt $availableSourceDCs.Count; $i++) {
                Write-LogInfo "  [$($i+1)] $($availableSourceDCs[$i].Name)"
                Write-Host "  [$($i+1)] $($availableSourceDCs[$i].Name)"
            }
            
            do {
                $selection = Read-Host "Please select source datacenter (1-$($availableSourceDCs.Count))"
                $selectionIndex = [int]$selection - 1
            } while ($selectionIndex -lt 0 -or $selectionIndex -ge $availableSourceDCs.Count)
            
            $sourceDcName = $availableSourceDCs[$selectionIndex].Name
            Write-LogInfo "Selected source datacenter: '$($sourceDcName)'"
        }
        
        if (-not $targetDcName) {
            Write-LogInfo "No target datacenter specified. Retrieving available datacenters..."
            $availableTargetDCs = Get-Datacenter -Server $targetVIServer -ErrorAction Stop
            
            if (-not $availableTargetDCs) {
                throw "No datacenters found in target vCenter '$($TargetVCenter)'."
            }
            
            Write-LogInfo "Available datacenters in target vCenter:"
            for ($i = 0; $i -lt $availableTargetDCs.Count; $i++) {
                Write-LogInfo "  [$($i+1)] $($availableTargetDCs[$i].Name)"
                Write-Host "  [$($i+1)] $($availableTargetDCs[$i].Name)"
            }
            
            do {
                $selection = Read-Host "Please select target datacenter (1-$($availableTargetDCs.Count))"
                $selectionIndex = [int]$selection - 1
            } while ($selectionIndex -lt 0 -or $selectionIndex -ge $availableTargetDCs.Count)
            
            $targetDcName = $availableTargetDCs[$selectionIndex].Name
            Write-LogInfo "Selected target datacenter: '$($targetDcName)'"
        }
        
        # Get the specific source datacenter
        Write-LogInfo "Retrieving Source Datacenter '$($sourceDcName)'..."
        $sourceDc = Get-Datacenter -Name $sourceDcName -Server $sourceVIServer -ErrorAction SilentlyContinue
        if (-not $sourceDc) {
            throw "Source Datacenter '$($sourceDcName)' not found on vCenter '$($SourceVCenter)'."
        }
        Write-LogInfo "Found Source Datacenter: '$($sourceDc.Name)'"
        
        # Get the specific target datacenter
        Write-LogInfo "Retrieving Target Datacenter '$($targetDcName)'..."
        $targetDc = Get-Datacenter -Name $targetDcName -Server $targetVIServer -ErrorAction SilentlyContinue
        if (-not $targetDc) {
            throw "Target Datacenter '$($targetDcName)' not found on vCenter '$($TargetVCenter)'."
        }
        Write-LogInfo "Found Target Datacenter: '$($targetDc.Name)'"
        
        # Copy explicit permissions for the specified datacenter pair
        Copy-DatacenterExplicitPermissions -SourceDatacenter $sourceDc -TargetDatacenter $targetDc -SourceServer $sourceVIServer -TargetServer $targetVIServer
    }
    
    # Generate report if requested
    if ($CreateReport) {
        Write-LogInfo "Generating explicit permissions report..."
        Export-PermissionsReport -FilePath $ReportPath
    }

} catch {
    $errorMsg = "An error occurred: $($_.Exception.Message)"
    Write-LogError $errorMsg
    Write-LogError "Script execution halted."
    if ($VerbosePreference -eq 'Continue' -or $LogLevel -eq 'Debug') {
        Write-LogError "Full error details: $($_.Exception.ToString())"
    }
} finally {
    # Disconnect from vCenters if connections were established
    if ($sourceVIServer) {
        Write-LogInfo "Disconnecting from Source vCenter: $($sourceVIServer.Name)..."
        try {
            Disconnect-VIServer -Server $sourceVIServer -Confirm:$false -Force:$true -ErrorAction Stop
            Write-LogInfo "Successfully disconnected from Source vCenter"
        } catch {
            Write-LogError "Failed to disconnect from Source vCenter: $($_.Exception.Message)"
        }
    }
    
    if ($targetVIServer) {
        Write-LogInfo "Disconnecting from Target vCenter: $($targetVIServer.Name)..."
        try {
            Disconnect-VIServer -Server $targetVIServer -Confirm:$false -Force:$true -ErrorAction Stop
            Write-LogInfo "Successfully disconnected from Target vCenter"
        } catch {
            Write-LogError "Failed to disconnect from Target vCenter: $($_.Exception.Message)"
        }
    }
    
    # Final summary
    if ($script:PermissionsReport.Count -gt 0 -and -not $CreateReport) {
        Write-Host "`nQuick Summary:" -ForegroundColor Cyan
        $totalProcessed = $script:PermissionsReport.Count
        $created = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Created' }).Count
        $updated = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Updated' }).Count
        $alreadyExists = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Already Exists' }).Count
        $failed = ($script:PermissionsReport | Where-Object { $_.Status -eq 'Failed' }).Count
        
        if ($WhatIf) {
            Write-Host "  Total explicit permissions that would be processed: $($totalProcessed)" -ForegroundColor Magenta
            Write-LogInfo "Total explicit permissions that would be processed: $($totalProcessed)"
        } else {
            Write-Host "  Total explicit permissions processed: $($totalProcessed)" -ForegroundColor White
            Write-Host "  Created: $($created)" -ForegroundColor Green
            Write-Host "  Updated: $($updated)" -ForegroundColor Yellow
            Write-Host "  Already Exists: $($alreadyExists)" -ForegroundColor Green
            Write-Host "  Failed: $($failed)" -ForegroundColor Red
            
            Write-LogInfo "Final Summary - Total explicit permissions processed: $($totalProcessed)"
            Write-LogInfo "Final Summary - Created: $($created), Updated: $($updated), Already Exists: $($alreadyExists), Failed: $($failed)"
        }
        
        Write-Host "  Inherited permissions skipped: $($script:InheritedPermissionsSkipped)" -ForegroundColor DarkYellow
        Write-Host "  System accounts skipped: $($script:SystemAccountsSkipped)" -ForegroundColor DarkYellow
        
        if ($failed -gt 0) {
            Write-Host "  Use -CreateReport to get detailed error information" -ForegroundColor Yellow
            Write-LogWarning "There were $($failed) failed permissions. Use -CreateReport for detailed error information"
        }
    }
    
    # Complete logging and display log file locations
    Complete-Logging
    
    Write-Host "`nLog files created:" -ForegroundColor Cyan
    Write-Host "  Main Log: $($script:MainLogFile)" -ForegroundColor Green
    Write-Host "  Error Log: $($script:ErrorLogFile)" -ForegroundColor Green
    
    # Check if error log has content
    if (Test-Path $script:ErrorLogFile) {
        $errorLogContent = Get-Content $script:ErrorLogFile -ErrorAction SilentlyContinue
        if ($errorLogContent -and $errorLogContent.Count -gt 0) {
            Write-Host "  Error log contains $($errorLogContent.Count) error entries" -ForegroundColor Red
        } else {
            Write-Host "  Error log is empty (no errors occurred)" -ForegroundColor Green
        }
    }
    
    Write-Host "`nScript finished." -ForegroundColor Cyan
}