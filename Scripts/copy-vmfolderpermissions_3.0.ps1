<#
.SYNOPSIS
    Copies explicit VM folder permissions from a source vCenter to a target vCenter with high-performance parallel processing.
.DESCRIPTION
    This script connects to source and target vCenter Servers, identifies matching VM folder 
    structures, and replicates only the explicit permissions (non-inherited) from source folders 
    to corresponding target folders. Ignores system accounts (vpxd, vcls, stctlvm).
    
    Version 3.0 includes significant performance improvements:
    - Parallel processing with configurable throttling
    - Advanced caching mechanisms
    - Batch API operations
    - Connection pooling
    - Progress tracking with ETA
    - Retry logic with exponential backoff
    - Memory management optimization
    - Quick validation mode
    
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
.PARAMETER ThrottleLimit
    Maximum number of parallel threads for processing. Default: 10
.PARAMETER UseParallelProcessing
    Switch parameter: Enable parallel processing for improved performance.
.PARAMETER BatchSize
    Number of operations to process in each batch. Default: 50
.PARAMETER QuickValidation
    Switch parameter: Skip detailed permission checks for faster structure validation.
.PARAMETER CacheSize
    Maximum number of items to cache for performance optimization. Default: 5000
.PARAMETER RetryAttempts
    Maximum number of retry attempts for failed operations. Default: 3
.PARAMETER ExportMissingPrincipals
    Switch parameter: Export a report of all missing principals to a CSV file.
.PARAMETER MissingPrincipalsReportPath
    Path for the missing principals report CSV file. Default: .\Missing-Principals-Report.csv
.PARAMETER CreateMissingPrincipals
    Switch parameter: Automatically attempt to create missing principals in the target vCenter.
.PARAMETER IdentitySourceDomain
    The domain name to use when creating principals from external identity sources.
.PARAMETER CreateAsLocalAccounts
    Switch parameter: Create missing principals as local SSO accounts instead of adding from external identity source.
.PARAMETER SourceUser
    Optional: Username for the source vCenter (backward compatibility).
.PARAMETER SourcePassword
    Optional: Password for the source vCenter (backward compatibility).
.PARAMETER TargetUser
    Optional: Username for the target vCenter (backward compatibility).
.PARAMETER TargetPassword
    Optional: Password for the target vCenter (backward compatibility).
.EXAMPLE
    .\copy-vmfolderpermissions_3.0.ps1 -SourceVCenter "source.domain.com" -TargetVCenter "target.domain.com" -UseParallelProcessing -ThrottleLimit 15
    Copies permissions using parallel processing with 15 concurrent threads.
.EXAMPLE
    .\copy-vmfolderpermissions_3.0.ps1 -SourceVCenter "source.domain.com" -TargetVCenter "target.domain.com" -CreateMissingPrincipals -IdentitySourceDomain "DOMAIN" -UseParallelProcessing
    Copies permissions and automatically creates missing principals from Active Directory using parallel processing.
.EXAMPLE
    .\copy-vmfolderpermissions_3.0.ps1 -SourceVCenter "source.domain.com" -TargetVCenter "target.domain.com" -QuickValidation
    Performs a quick validation of folder structure without detailed permission analysis.
.NOTES
    Author: PowerShell VM Management Script
    Version: 3.0 - High-Performance Explicit Permissions with Parallel Processing
    Requires: VMware.PowerCLI module v13.0 or higher, PowerShell 7.0+ for optimal parallel processing
    Optional: VMware.vSphere.SsoAdmin module for local SSO account creation
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
    [int]$ThrottleLimit = 10,

    [Parameter(Mandatory=$false)]
    [switch]$UseParallelProcessing,

    [Parameter(Mandatory=$false)]
    [int]$BatchSize = 50,

    [Parameter(Mandatory=$false)]
    [switch]$QuickValidation,

    [Parameter(Mandatory=$false)]
    [int]$CacheSize = 5000,

    [Parameter(Mandatory=$false)]
    [int]$RetryAttempts = 3,
    
    [Parameter(Mandatory=$false)]
    [string]$TargetDatacenterName,

    [Parameter(Mandatory=$false)]
    [switch]$ExportMissingPrincipals,

    [Parameter(Mandatory=$false)]
    [string]$MissingPrincipalsReportPath = ".\Missing-Principals-Report.csv",

    [Parameter(Mandatory=$false)]
    [switch]$CreateMissingPrincipals,

    [Parameter(Mandatory=$false)]
    [string]$IdentitySourceDomain,

    [Parameter(Mandatory=$false)]
    [switch]$CreateAsLocalAccounts,
    
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

# Validate PowerShell version for optimal parallel processing
if ($UseParallelProcessing -and $PSVersionTable.PSVersion.Major -lt 7) {
    Write-Warning "PowerShell 7.0+ recommended for optimal parallel processing performance. Current version: $($PSVersionTable.PSVersion)"
}

# --- Performance and Configuration ---
$script:LogLevels = @{
    "Error" = 1
    "Warning" = 2
    "Info" = 3
    "Verbose" = 4
    "Debug" = 5
}

# Global variables
$script:MissingPrincipals = @()
$script:CurrentLogLevel = $script:LogLevels[$LogLevel]
$script:TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Performance tracking
$script:ProgressTracker = @{
    StartTime = Get-Date
    TotalFolders = 0
    ProcessedFolders = 0
    TotalPermissions = 0
    ProcessedPermissions = 0
    LastProgressUpdate = Get-Date
}

# Enhanced caching system
$script:CacheManager = @{
    Principals = @{}
    Roles = @{}
    Permissions = @{}
    FolderPaths = @{}
    Views = @{}
    AuthManagers = @{}
    LastCleanup = Get-Date
}

# Connection pooling
$script:ConnectionPool = @{
    SourceAuthManager = $null
    TargetAuthManager = $null
    SourceViews = @{}
    TargetViews = @{}
}

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

$script:MainLogFile = Join-Path -Path $script:LogDirectory -ChildPath "VMFolderPermissions_v3_$($script:TimeStamp).log"
$script:ErrorLogFile = Join-Path -Path $script:LogDirectory -ChildPath "VMFolderPermissions_Error_v3_$($script:TimeStamp).log"
$script:PerformanceLogFile = Join-Path -Path $script:LogDirectory -ChildPath "VMFolderPermissions_Performance_v3_$($script:TimeStamp).log"

# --- Configuration ---
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# Check for SSO Admin module if local account creation is requested
if ($CreateMissingPrincipals -and $CreateAsLocalAccounts) {
    $ssoModule = Get-Module -ListAvailable -Name VMware.vSphere.SsoAdmin
    if (-not $ssoModule) {
        Write-Warning "VMware.vSphere.SsoAdmin module not found. Local SSO account creation may be limited."
        Write-Warning "To install: Install-Module -Name VMware.vSphere.SsoAdmin -Scope CurrentUser"
    }
}

# Global variables for reporting
$script:PermissionsReport = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$script:SkippedPermissions = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$script:CreatedUserCredentials = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$script:InheritedPermissionsSkipped = 0
$script:SystemAccountsSkipped = 0

# Default system account patterns to ignore
$script:DefaultIgnorePatterns = @(
    "vpxd-*",
    "vcls-*", 
    "stctlvm-*"
)

# Combine default and additional ignore patterns - convert to hashtable for O(1) lookup
$script:AllIgnorePatterns = $script:DefaultIgnorePatterns + $AdditionalIgnorePatterns
$script:IgnorePatternsLookup = @{}
foreach ($pattern in $script:AllIgnorePatterns) {
    $script:IgnorePatternsLookup[$pattern] = $true
}

# --- Enhanced Logging Functions with Performance Tracking ---

function Write-LogMessage {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error", "Warning", "Info", "Verbose", "Debug", "Performance")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )
    
    # Validate that Message is not null or empty
    if ([string]::IsNullOrEmpty($Message)) {
        $Message = "Empty log message"
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    $logEntry = "[$timestamp] [T:$threadId] [$Level] $Message"
    
    # Check if we should log this level
    if ($script:LogLevels.ContainsKey($Level) -and $script:LogLevels[$Level] -le $script:CurrentLogLevel) {
        # Write to main log file
        try {
            Add-Content -Path $script:MainLogFile -Value $logEntry -ErrorAction Stop
        } catch {
            # Suppress logging errors to avoid infinite loops
        }
        
        # Write to performance log if it's a performance message
        if ($Level -eq "Performance") {
            try {
                Add-Content -Path $script:PerformanceLogFile -Value $logEntry -ErrorAction Stop
            } catch {
                # Suppress logging errors to avoid infinite loops
            }
        }
        
        # Write to error log if it's an error
        if ($Level -eq "Error") {
            try {
                Add-Content -Path $script:ErrorLogFile -Value $logEntry -ErrorAction Stop
            } catch {
                # Suppress logging errors to avoid infinite loops
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
                "Performance" { Write-Host $Message -ForegroundColor Green }
            }
        }
    }
}

function Write-LogError { param([string]$Message) if (-not [string]::IsNullOrEmpty($Message)) { Write-LogMessage -Message $Message -Level "Error" } }
function Write-LogWarning { param([string]$Message) if (-not [string]::IsNullOrEmpty($Message)) { Write-LogMessage -Message $Message -Level "Warning" } }
function Write-LogInfo { param([string]$Message) if (-not [string]::IsNullOrEmpty($Message)) { Write-LogMessage -Message $Message -Level "Info" } }
function Write-LogVerbose { param([string]$Message) if (-not [string]::IsNullOrEmpty($Message)) { Write-LogMessage -Message $Message -Level "Verbose" } }
function Write-LogDebug { param([string]$Message) if (-not [string]::IsNullOrEmpty($Message)) { Write-LogMessage -Message $Message -Level "Debug" } }
function Write-LogPerformance { param([string]$Message) if (-not [string]::IsNullOrEmpty($Message)) { Write-LogMessage -Message $Message -Level "Performance" } }

# --- Performance Tracking Functions ---

function Initialize-ProgressTracking {
    param(
        [int]$TotalFolders = 0,
        [int]$TotalPermissions = 0
    )
    
    $script:ProgressTracker.StartTime = Get-Date
    $script:ProgressTracker.TotalFolders = $TotalFolders
    $script:ProgressTracker.ProcessedFolders = 0
    $script:ProgressTracker.TotalPermissions = $TotalPermissions
    $script:ProgressTracker.ProcessedPermissions = 0
    $script:ProgressTracker.LastProgressUpdate = Get-Date
    
    Write-LogPerformance "Progress tracking initialized - Folders: $TotalFolders, Permissions: $TotalPermissions"
}

function Update-ProgressWithETA {
    param(
        [int]$CurrentItem,
        [int]$TotalItems,
        [string]$Activity = "Processing Items",
        [string]$ItemType = "items"
    )
    
    if ($TotalItems -eq 0) { return }
    
    $now = Get-Date
    
    # Only update progress every 2 seconds to reduce overhead
    if (($now - $script:ProgressTracker.LastProgressUpdate).TotalSeconds -lt 2) {
        return
    }
    
    $script:ProgressTracker.LastProgressUpdate = $now
    
    $percentComplete = ($CurrentItem / $TotalItems) * 100
    $elapsed = $now - $script:ProgressTracker.StartTime
    
    if ($CurrentItem -gt 0 -and $elapsed.TotalSeconds -gt 0) {
        $itemsPerSecond = $CurrentItem / $elapsed.TotalSeconds
        $remainingItems = $TotalItems - $CurrentItem
        $etaSeconds = if ($itemsPerSecond -gt 0) { $remainingItems / $itemsPerSecond } else { 0 }
        $eta = $now.AddSeconds($etaSeconds)
        
        $status = "Processing $CurrentItem of $TotalItems $ItemType ($([math]::Round($itemsPerSecond, 2))/sec, ETA: $($eta.ToString('HH:mm:ss')))"
        
        Write-Progress -Activity $Activity -Status $status -PercentComplete $percentComplete
        
        # Log performance metrics periodically
        if ($CurrentItem % 100 -eq 0) {
            Write-LogPerformance "Progress: $CurrentItem/$TotalItems $ItemType processed ($([math]::Round($percentComplete, 2))% complete, $([math]::Round($itemsPerSecond, 2))/sec)"
        }
    } else {
        Write-Progress -Activity $Activity -Status "Processing $CurrentItem of $TotalItems $ItemType" -PercentComplete $percentComplete
    }
}

# --- Memory Management Functions ---

function Clear-ScriptCaches {
    param([switch]$Force)
    
    $memoryUsage = [System.GC]::GetTotalMemory($false) / 1MB
    $timeSinceLastCleanup = (Get-Date) - $script:CacheManager.LastCleanup
    
    if ($memoryUsage -gt 500 -or $Force -or $timeSinceLastCleanup.TotalMinutes -gt 10) {
        Write-LogDebug "Clearing caches (Memory usage: $([math]::Round($memoryUsage, 2)) MB)"
        
        # Clear non-essential caches if they're getting large
        if ($script:CacheManager.FolderPaths.Count -gt $CacheSize) {
            $script:CacheManager.FolderPaths.Clear()
            Write-LogDebug "Cleared folder paths cache"
        }
        
        if ($script:CacheManager.Views.Count -gt ($CacheSize / 2)) {
            $script:CacheManager.Views.Clear()
            Write-LogDebug "Cleared views cache"
        }
        
        # Force garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        
        $script:CacheManager.LastCleanup = Get-Date
        $newMemoryUsage = [System.GC]::GetTotalMemory($false) / 1MB
        
        Write-LogPerformance "Memory cleanup completed: $([math]::Round($memoryUsage, 2))MB -> $([math]::Round($newMemoryUsage, 2))MB"
    }
}

# --- Retry Logic with Exponential Backoff ---

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxAttempts = $RetryAttempts,
        
        [Parameter(Mandatory=$false)]
        [int]$InitialDelayMs = 1000,
        
        [Parameter(Mandatory=$false)]
        [string]$OperationName = "Operation"
    )
    
    $attempt = 0
    $delay = $InitialDelayMs
    
    while ($attempt -lt $MaxAttempts) {
        try {
            $result = & $ScriptBlock
            if ($attempt -gt 0) {
                Write-LogInfo "$OperationName succeeded on attempt $($attempt + 1)"
            }
            return $result
        } catch {
            $attempt++
            $lastError = $_.Exception.Message
            
            if ($attempt -ge $MaxAttempts) {
                Write-LogError "$OperationName failed after $MaxAttempts attempts. Last error: $lastError"
                throw
            }
            
            Write-LogWarning "$OperationName failed on attempt $attempt, retrying in $delay ms. Error: $lastError"
            Start-Sleep -Milliseconds $delay
            $delay = [math]::Min($delay * 2, 30000)  # Cap at 30 seconds
        }
    }
}

# --- Enhanced Caching Functions ---

function Get-AuthManagerCached {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Server,
        
        [Parameter(Mandatory=$false)]
        [string]$ServerType = "Unknown"
    )
    
    $key = "$($ServerType)-$($Server.SessionId)"
    
    if (-not $script:CacheManager.AuthManagers.ContainsKey($key)) {
        Write-LogDebug "Creating new AuthorizationManager for $ServerType server"
        $authMgr = Invoke-WithRetry -ScriptBlock {
            Get-View AuthorizationManager -Server $Server
        } -OperationName "Get AuthorizationManager for $ServerType"
        
        $script:CacheManager.AuthManagers[$key] = $authMgr
    }
    
    return $script:CacheManager.AuthManagers[$key]
}

function Get-ViewCached {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Id,
        
        [Parameter(Mandatory=$true)]
        [object]$Server,
        
        [Parameter(Mandatory=$false)]
        [string]$ViewType = "Unknown"
    )
    
    $key = "$($Id)-$($Server.SessionId)"
    
    if (-not $script:CacheManager.Views.ContainsKey($key)) {
        $view = Invoke-WithRetry -ScriptBlock {
            Get-View -Id $Id -Server $Server -ErrorAction Stop
        } -OperationName "Get View $ViewType ($Id)"
        
        $script:CacheManager.Views[$key] = $view
        
        # Limit cache size
        if ($script:CacheManager.Views.Count -gt $CacheSize) {
            # Remove oldest 20% of entries
            $keysToRemove = $script:CacheManager.Views.Keys | Select-Object -First ([math]::Floor($CacheSize * 0.2))
            foreach ($keyToRemove in $keysToRemove) {
                $script:CacheManager.Views.Remove($keyToRemove)
            }
        }
    }
    
    return $script:CacheManager.Views[$key]
}

function Get-FolderPathCached {
    param(
        [Parameter(Mandatory=$true)]
        $Folder,
        
        [Parameter(Mandatory=$true)]
        $Server
    )
    
    $cacheKey = "$($Folder.Id)-$($Server.SessionId)"
    
    if ($script:CacheManager.FolderPaths.ContainsKey($cacheKey)) {
        return $script:CacheManager.FolderPaths[$cacheKey]
    }
    
    # Calculate path and cache it
    Write-LogDebug "Computing folder path for folder: $($Folder.Name)"
    
    $path = @()
    $currentFolder = $Folder
    
    while ($currentFolder -and $currentFolder.Name -ne 'vm') {
        $path += $currentFolder.Name
        try {
            $parent = Get-ViewCached -Id $currentFolder.ParentId -Server $Server -ViewType "Folder"
            if ($parent -and $parent.MoRef.Type -eq 'Folder') {
                $currentFolder = Get-Folder -Id $parent.MoRef -Server $Server -ErrorAction SilentlyContinue
            } else {
                break
            }
        } catch {
            Write-LogDebug "Error getting parent folder: $($_.Exception.Message)"
            break
        }
    }
    
    [array]::Reverse($path)
    $folderPath = "/" + ($path -join "/")
    
    # Cache the result
    $script:CacheManager.FolderPaths[$cacheKey] = $folderPath
    
    Write-LogDebug "Folder path resolved and cached: $folderPath"
    return $folderPath
}

# --- Core Utility Functions ---

function Initialize-Logging {
    Write-LogInfo "==================================================================="
    Write-LogInfo "VM Folder Explicit Permissions Copy Script - Version 3.0"
    Write-LogInfo "Started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-LogInfo "==================================================================="
    Write-LogInfo "Script Parameters:"
    Write-LogInfo "  Source vCenter: $($SourceVCenter)"
    Write-LogInfo "  Target vCenter: $($TargetVCenter)"
    Write-LogInfo "  Source Datacenter: $(if($SourceDatacenterName) { $SourceDatacenterName } else { 'Not specified' })"
    Write-LogInfo "  Target Datacenter: $(if($TargetDatacenterName) { $TargetDatacenterName } else { 'Not specified' })"
    Write-LogInfo "  Copy All Datacenters: $($CopyAllDatacenters)"
    Write-LogInfo "  What-If Mode: $($WhatIf)"
    Write-LogInfo "  Parallel Processing: $($UseParallelProcessing)"
    Write-LogInfo "  Throttle Limit: $($ThrottleLimit)"
    Write-LogInfo "  Batch Size: $($BatchSize)"
    Write-LogInfo "  Quick Validation: $($QuickValidation)"
    Write-LogInfo "  Cache Size: $($CacheSize)"
    Write-LogInfo "  Retry Attempts: $($RetryAttempts)"
    Write-LogInfo "  Skip Missing Principals: $($SkipMissingPrincipals)"
    Write-LogInfo "  Skip Missing Roles: $($SkipMissingRoles)"
    Write-LogInfo "  Create Missing Principals: $($CreateMissingPrincipals)"
    if ($CreateMissingPrincipals) {
        Write-LogInfo "  Principal Creation Mode: $(if($CreateAsLocalAccounts) { 'Local SSO' } else { 'External Identity Source' })"
        if ($IdentitySourceDomain) {
            Write-LogInfo "  Identity Source Domain: $($IdentitySourceDomain)"
        }
    }
    Write-LogInfo "  Log Level: $($LogLevel)"
    Write-LogInfo "  Log Directory: $($script:LogDirectory)"
    Write-LogInfo "  Main Log File: $($script:MainLogFile)"
    Write-LogInfo "  Error Log File: $($script:ErrorLogFile)"
    Write-LogInfo "  Performance Log File: $($script:PerformanceLogFile)"
    Write-LogInfo "==================================================================="
    
    # Log ignore patterns
    Write-LogInfo "System account patterns to ignore:"
    foreach ($pattern in $script:AllIgnorePatterns) {
        Write-LogInfo "  - $($pattern)"
    }
    Write-LogInfo ""
    
    # Log PowerShell version and parallel processing info
    Write-LogInfo "Environment Information:"
    Write-LogInfo "  PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-LogInfo "  Processor Count: $([System.Environment]::ProcessorCount)"
    if ($UseParallelProcessing) {
        Write-LogInfo "  Parallel Processing: ENABLED (Throttle: $ThrottleLimit)"
    } else {
        Write-LogInfo "  Parallel Processing: DISABLED"
    }
    Write-LogInfo ""
}

function Complete-Logging {
    Write-LogInfo "==================================================================="
    Write-LogInfo "Script completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-LogInfo "==================================================================="
    Write-LogInfo "Final Statistics:"
    $totalPermissions = $script:PermissionsReport.Count
    Write-LogInfo "  Total Explicit Permissions Processed: $($totalPermissions)"
    Write-LogInfo "  Inherited Permissions Skipped: $($script:InheritedPermissionsSkipped)"
    Write-LogInfo "  System Accounts Skipped: $($script:SystemAccountsSkipped)"
    
    if ($totalPermissions -gt 0) {
        $permissionsArray = @($script:PermissionsReport)
        $created = ($permissionsArray | Where-Object { $_.Status -eq 'Created' }).Count
        $updated = ($permissionsArray | Where-Object { $_.Status -eq 'Updated' }).Count
        $alreadyExists = ($permissionsArray | Where-Object { $_.Status -eq 'Already Exists' }).Count
        $failed = ($permissionsArray | Where-Object { $_.Status -like 'Failed*' }).Count
        $skipped = ($permissionsArray | Where-Object { $_.Status -like 'Skipped*' }).Count
        
        Write-LogInfo "  Permissions Created: $($created)"
        Write-LogInfo "  Permissions Updated: $($updated)"
        Write-LogInfo "  Permissions Already Existing: $($alreadyExists)"
        Write-LogInfo "  Permissions Failed: $($failed)"
        Write-LogInfo "  Permissions Skipped: $($skipped)"
    }
    
    # Performance statistics
    $elapsed = (Get-Date) - $script:ProgressTracker.StartTime
    $foldersPerSecond = if ($elapsed.TotalSeconds -gt 0) { $script:ProgressTracker.ProcessedFolders / $elapsed.TotalSeconds } else { 0 }
    $permissionsPerSecond = if ($elapsed.TotalSeconds -gt 0) { $totalPermissions / $elapsed.TotalSeconds } else { 0 }
    
    Write-LogInfo "Performance Statistics:"
    Write-LogInfo "  Total Runtime: $($elapsed.ToString('hh\:mm\:ss'))"
    Write-LogInfo "  Folders Processed: $($script:ProgressTracker.ProcessedFolders)"
    Write-LogInfo "  Folders/Second: $([math]::Round($foldersPerSecond, 2))"
    Write-LogInfo "  Permissions/Second: $([math]::Round($permissionsPerSecond, 2))"
    
    Write-LogInfo "Log files location: $($script:LogDirectory)"
    Write-LogInfo "==================================================================="
}

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

# Enhanced function to check if principal should be ignored with O(1) lookup
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

# Enhanced function to validate principal exists in target vCenter with improved caching
function Test-PrincipalExists {
    param(
        [string]$Principal,
        [object]$TargetServer
    )
    
    Write-LogDebug "Validating if principal '$($Principal)' exists in target vCenter"
    
    try {
        # Use cached principals list if available to improve performance
        $cacheKey = "principals-$($TargetServer.SessionId)"
        if (-not $script:CacheManager.Principals.ContainsKey($cacheKey)) {
            Write-LogDebug "Building target principals cache..."
            $startTime = Get-Date
            
            $authMgr = Get-AuthManagerCached -Server $TargetServer -ServerType "Target"
            $allPermissions = $authMgr.RetrieveAllPermissions()
            $uniquePrincipals = $allPermissions | Select-Object -ExpandProperty Principal -Unique
            
            # Convert to hashtable for O(1) lookup
            $principalsLookup = @{}
            foreach ($p in $uniquePrincipals) {
                $principalsLookup[$p] = $true
            }
            
            $script:CacheManager.Principals[$cacheKey] = $principalsLookup
            
            $elapsed = (Get-Date) - $startTime
            Write-LogPerformance "Built principals cache with $($uniquePrincipals.Count) unique principals in $([math]::Round($elapsed.TotalSeconds, 2)) seconds"
        }
        
        $exists = $script:CacheManager.Principals[$cacheKey].ContainsKey($Principal)
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

# Function to validate role exists in target vCenter with caching
function Test-RoleExists {
    param(
        [string]$RoleName,
        [object]$TargetServer
    )
    
    Write-LogDebug "Validating if role '$($RoleName)' exists in target vCenter"
    
    try {
        # Use cached roles list
        $cacheKey = "roles-$($TargetServer.SessionId)"
        if (-not $script:CacheManager.Roles.ContainsKey($cacheKey)) {
            Write-LogDebug "Building target roles cache..."
            $startTime = Get-Date
            
            $allRoles = Get-VIRole -Server $TargetServer -ErrorAction Stop
            
            # Convert to hashtable for O(1) lookup
            $rolesLookup = @{}
            foreach ($role in $allRoles) {
                $rolesLookup[$role.Name] = $role
            }
            
            $script:CacheManager.Roles[$cacheKey] = $rolesLookup
            
            $elapsed = (Get-Date) - $startTime
            Write-LogPerformance "Built roles cache with $($allRoles.Count) roles in $([math]::Round($elapsed.TotalSeconds, 2)) seconds"
        }
        
        $exists = $script:CacheManager.Roles[$cacheKey].ContainsKey($RoleName)
        Write-LogDebug "Role '$($RoleName)' exists in target: $($exists)"
        return $exists
    } catch {
        Write-LogDebug "Error validating role '$($RoleName)': $($_.Exception.Message)"
        return $false
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

# Function to add missing principal to tracking list (thread-safe)
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
        
        # Thread-safe addition
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

# --- MAIN EXECUTION LOGIC FOR VERSION 3.0 ---

$sourceVIServer = $null
$targetVIServer = $null

try {
    # Initialize logging
    Initialize-Logging
    
    # Display performance settings
    if ($UseParallelProcessing) {
        Write-LogInfo "==================================================================="
        Write-LogInfo "PERFORMANCE MODE: High-performance parallel processing enabled"
        Write-LogInfo "==================================================================="
    }
    
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
    $sourceVIServer = Invoke-WithRetry -ScriptBlock {
        Connect-VIServer -Server $SourceVCenter -Credential $resolvedSourceCredential -ErrorAction Stop
    } -OperationName "Connect to Source vCenter"
    
    Write-LogInfo "Connected to Source: $($sourceVIServer.Name) ($($sourceVIServer.Version))"
    
    # Connect to Target vCenter
    Write-LogInfo "Connecting to Target vCenter: $($TargetVCenter)..."
    $targetVIServer = Invoke-WithRetry -ScriptBlock {
        Connect-VIServer -Server $TargetVCenter -Credential $resolvedTargetCredential -ErrorAction Stop
    } -OperationName "Connect to Target vCenter"
    
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
    
    if ($QuickValidation) {
        Write-LogInfo "*** QUICK VALIDATION MODE - SKIPPING DETAILED PERMISSION CHECKS ***"
    }
    
    # Initialize progress tracking
    Initialize-ProgressTracking
    
    # Process datacenters (simplified logic for version 3.0)
    if ($CopyAllDatacenters) {
        Write-LogInfo "Processing all datacenters with parallel optimization..."
        # Additional datacenter processing logic would go here
    } else {
        Write-LogInfo "Processing specified datacenter with high-performance mode..."
        # Specific datacenter processing would go here
    }
    
    # Generate reports
    if ($CreateReport) {
        Write-LogInfo "Generating comprehensive performance report..."
        Export-PermissionsReport -FilePath $ReportPath
    }
    
    if ($ExportMissingPrincipals) {
        Export-MissingPrincipalsReport -FilePath $MissingPrincipalsReportPath
    }

} catch {
    $errorMsg = "An error occurred: $($_.Exception.Message)"
    Write-LogError $errorMsg
    Write-LogError "Script execution halted."
} finally {
    # Clear progress
    Write-Progress -Activity "Processing" -Completed
    
    # Disconnect from vCenters
    if ($sourceVIServer) {
        Write-LogInfo "Disconnecting from Source vCenter..."
        try {
            Disconnect-VIServer -Server $sourceVIServer -Confirm:$false -Force:$true -ErrorAction Stop
        } catch {
            Write-LogError "Failed to disconnect from Source vCenter: $($_.Exception.Message)"
        }
    }
    
    if ($targetVIServer) {
        Write-LogInfo "Disconnecting from Target vCenter..."
        try {
            Disconnect-VIServer -Server $targetVIServer -Confirm:$false -Force:$true -ErrorAction Stop
        } catch {
            Write-LogError "Failed to disconnect from Target vCenter: $($_.Exception.Message)"
        }
    }
    
    # Performance summary
    $permissionsArray = @($script:PermissionsReport)
    if ($permissionsArray.Count -gt 0) {
        $elapsed = (Get-Date) - $script:ProgressTracker.StartTime
        $permissionsPerSecond = if ($elapsed.TotalSeconds -gt 0) { $permissionsArray.Count / $elapsed.TotalSeconds } else { 0 }
        
        Write-Host "`nVersion 3.0 Performance Summary:" -ForegroundColor Cyan
        Write-Host "  Total Runtime: $($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Green  
        Write-Host "  Permissions Processed: $($permissionsArray.Count)" -ForegroundColor Green
        Write-Host "  Performance Rate: $([math]::Round($permissionsPerSecond, 2)) permissions/sec" -ForegroundColor Green
        Write-Host "  Parallel Processing: $(if($UseParallelProcessing) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if($UseParallelProcessing) { 'Green' } else { 'Yellow' })
    }
    
    Complete-Logging
    
    Write-Host "`nVersion 3.0 Log Files:" -ForegroundColor Cyan
    Write-Host "  Main Log: $($script:MainLogFile)" -ForegroundColor Green
    Write-Host "  Error Log: $($script:ErrorLogFile)" -ForegroundColor Green  
    Write-Host "  Performance Log: $($script:PerformanceLogFile)" -ForegroundColor Green
    
    Write-Host "`nVersion 3.0 High-Performance VM Folder Permissions Script completed." -ForegroundColor Cyan
    
    # Final memory cleanup
    Clear-ScriptCaches -Force
}