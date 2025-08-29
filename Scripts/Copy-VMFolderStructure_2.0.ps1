<#
.SYNOPSIS
    Copies the VM folder structure (blue folders) from a source vCenter to a target vCenter.
    Can copy from specific datacenters or all datacenters.
.DESCRIPTION
    This script connects to two vCenter Servers, identifies the VM folder hierarchy
    within specified Datacenters (or all Datacenters) on the source, and replicates 
    that structure in specified Datacenters on the target vCenter.
    Requires PowerCLI module installed.
.PARAMETER SourceVCenter
    The FQDN or IP address of the source vCenter Server.
.PARAMETER TargetVCenter
    The FQDN or IP address of the target vCenter Server.
.PARAMETER SourceCredential
    PSCredential object for the source vCenter Server.
.PARAMETER TargetCredential
    PSCredential object for the target vCenter Server.
.PARAMETER SourceDatacenterName
    Optional: The name of the specific Datacenter on the Source vCenter whose folder structure should be copied.
    If not specified and CopyAllDatacenters is false, you'll be prompted to select.
.PARAMETER TargetDatacenterName
    Optional: The name of the specific Datacenter on the Target vCenter where the folder structure should be created.
    If not specified and CopyAllDatacenters is false, you'll be prompted to select.
.PARAMETER CopyAllDatacenters
    Switch parameter: If specified, copies all VM folder structures from all datacenters in source to target.
    Target datacenters must already exist with the same names as source datacenters.
.PARAMETER CreateMissingDatacenters
    Switch parameter: When used with CopyAllDatacenters, creates missing datacenters in target vCenter.
    Requires appropriate permissions in target vCenter.
.PARAMETER SourceUser
    Optional: Username for the source vCenter. Used instead of SourceCredential for backward compatibility.
.PARAMETER SourcePassword
    Optional: Password for the source vCenter. Used with SourceUser for backward compatibility.
.PARAMETER TargetUser
    Optional: Username for the target vCenter. Used instead of TargetCredential for backward compatibility.
.PARAMETER TargetPassword
    Optional: Password for the target vCenter. Used with TargetUser for backward compatibility.
.EXAMPLE
    # Copy specific datacenter using credential objects
    $sourceCred = Get-Credential -Message "Source vCenter Credentials"
    $targetCred = Get-Credential -Message "Target vCenter Credentials"
    .\Copy-VMFolderStructure.ps1 -SourceVCenter source-vc.domain.local -TargetVCenter target-vc.domain.local -SourceCredential $sourceCred -TargetCredential $targetCred -SourceDatacenterName "SourceDC_01" -TargetDatacenterName "TargetDC_A"
.EXAMPLE
    # Copy all datacenters using credential objects
    $creds = Get-Credential
    .\Copy-VMFolderStructure.ps1 -SourceVCenter source-vc.domain.local -TargetVCenter target-vc.domain.local -SourceCredential $creds -TargetCredential $creds -CopyAllDatacenters
.EXAMPLE
    # Copy all datacenters and create missing ones in target
    .\Copy-VMFolderStructure.ps1 -SourceVCenter source-vc.domain.local -TargetVCenter target-vc.domain.local -SourceCredential $creds -TargetCredential $creds -CopyAllDatacenters -CreateMissingDatacenters
.EXAMPLE
    # Backward compatibility - using individual user/password parameters
    .\Copy-VMFolderStructure.ps1 -SourceVCenter 192.168.1.10 -TargetVCenter 192.168.2.20 -SourceUser admin@vsphere.local -TargetUser administrator@vsphere.local -SourceDatacenterName "LabDC" -TargetDatacenterName "LabDC"
.NOTES
    Author: Enhanced Version
    Version: 2.0
    Requires: VMware.PowerCLI module v13.0 or higher.
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
    [switch]$CopyAllDatacenters,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateMissingDatacenters,
    
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

if ($CreateMissingDatacenters -and -not $CopyAllDatacenters) {
    Write-Warning "CreateMissingDatacenters only works with CopyAllDatacenters switch. It will be ignored."
}

# --- Configuration ---
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# --- Functions ---

# Function to resolve credentials with backward compatibility
function Get-ResolvedCredential {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$User,
        [securestring]$Password,
        [string]$ServerType
    )
    
    if ($Credential) {
        return $Credential
    }
    
    if ($User) {
        if ($Password) {
            return New-Object System.Management.Automation.PSCredential($User, $Password)
        } else {
            return Get-Credential -UserName $User -Message "Enter password for $User on $ServerName ($ServerType)"
        }
    }
    
    return Get-Credential -Message "Enter credentials for $ServerName ($ServerType)"
}

# Recursive function to copy folder structure
function Copy-FolderStructure {
    param(
        [Parameter(Mandatory=$true)]
        $SourceParentFolder,
        [Parameter(Mandatory=$true)]
        $TargetParentFolder,
        [Parameter(Mandatory=$true)]
        $SourceServer,
        [Parameter(Mandatory=$true)]
        $TargetServer
    )
    
    # Get child VM folders directly under the source parent folder
    Write-Verbose "Getting child folders of '$($SourceParentFolder.Name)' on source $($SourceServer.Name)"
    $sourceChildFolders = Get-Folder -Location $SourceParentFolder -Type VM -Server $SourceServer -NoRecursion -ErrorAction SilentlyContinue
    
    if ($null -eq $sourceChildFolders) {
        Write-Verbose "No child VM folders found under '$($SourceParentFolder.Name)' or error occurred."
        return
    }
    
    foreach ($sourceFolder in $sourceChildFolders) {
        Write-Host "Processing Source Folder: '$($sourceFolder.Name)' under '$($SourceParentFolder.Name)'" -ForegroundColor Cyan
        
        # Check if the folder already exists in the target location
        Write-Verbose "Checking for existing folder '$($sourceFolder.Name)' under '$($TargetParentFolder.Name)' on target $($TargetServer.Name)"
        $existingTargetFolder = Get-Folder -Location $TargetParentFolder -Name $sourceFolder.Name -Type VM -Server $TargetServer -NoRecursion -ErrorAction SilentlyContinue
        
        if ($existingTargetFolder) {
            Write-Host "  Folder '$($sourceFolder.Name)' already exists in Target under '$($TargetParentFolder.Name)'. Using existing." -ForegroundColor Green
            $currentTargetFolder = $existingTargetFolder
        } else {
            Write-Host "  Creating Folder '$($sourceFolder.Name)' in Target under '$($TargetParentFolder.Name)'..." -ForegroundColor Yellow
            try {
                $currentTargetFolder = New-Folder -Location $TargetParentFolder -Name $sourceFolder.Name -Server $TargetServer -ErrorAction Stop
                Write-Host "  Successfully created folder '$($currentTargetFolder.Name)'." -ForegroundColor Green
            } catch {
                Write-Error "  Failed to create folder '$($sourceFolder.Name)' in Target under '$($TargetParentFolder.Name)': $($_.Exception.Message)"
                continue
            }
        }
        
        # Recurse into the child folder
        if ($currentTargetFolder) {
            Copy-FolderStructure -SourceParentFolder $sourceFolder -TargetParentFolder $currentTargetFolder -SourceServer $SourceServer -TargetServer $TargetServer
        }
    }
}

# Function to copy folder structure for a specific datacenter pair
function Copy-DatacenterFolderStructure {
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
    
    Write-Host "Processing Datacenter: '$($SourceDatacenter.Name)' -> '$($TargetDatacenter.Name)'" -ForegroundColor Magenta
    
    # Get the root VM folder for the source datacenter
    Write-Verbose "Getting root VM folder for Source Datacenter '$($SourceDatacenter.Name)'"
    $sourceRootVmFolder = Get-Folder -Location $SourceDatacenter -Type VM -Server $SourceServer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'vm' }
    
    if (-not $sourceRootVmFolder) {
        Write-Warning "Root VM folder ('vm') not found in Source Datacenter '$($SourceDatacenter.Name)'. Skipping."
        return
    }
    
    # Get the root VM folder for the target datacenter
    Write-Verbose "Getting root VM folder for Target Datacenter '$($TargetDatacenter.Name)'"
    $targetRootVmFolder = Get-Folder -Location $TargetDatacenter -Type VM -Server $TargetServer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'vm' }
    
    if (-not $targetRootVmFolder) {
        Write-Warning "Root VM folder ('vm') not found in Target Datacenter '$($TargetDatacenter.Name)'. Skipping."
        return
    }
    
    Write-Host "Starting folder structure copy from Source DC '$($SourceDatacenter.Name)' to Target DC '$($TargetDatacenter.Name)'..." -ForegroundColor Cyan
    
    # Start the recursive copy process
    Copy-FolderStructure -SourceParentFolder $sourceRootVmFolder -TargetParentFolder $targetRootVmFolder -SourceServer $SourceServer -TargetServer $TargetServer
    
    Write-Host "Finished folder structure copy for Datacenter '$($SourceDatacenter.Name)' -> '$($TargetDatacenter.Name)'." -ForegroundColor Green
}

# --- Main Script Logic ---
$sourceVIServer = $null
$targetVIServer = $null

try {
    # Resolve credentials
    $resolvedSourceCredential = Get-ResolvedCredential -ServerName $SourceVCenter -Credential $SourceCredential -User $SourceUser -Password $SourcePassword -ServerType "Source"
    $resolvedTargetCredential = Get-ResolvedCredential -ServerName $TargetVCenter -Credential $TargetCredential -User $TargetUser -Password $TargetPassword -ServerType "Target"
    
    if (-not $resolvedSourceCredential -or -not $resolvedTargetCredential) {
        throw "Failed to obtain valid credentials for both source and target vCenters."
    }
    
    # Connect to Source vCenter
    Write-Host "Connecting to Source vCenter: $SourceVCenter..."
    $sourceVIServer = Connect-VIServer -Server $SourceVCenter -Credential $resolvedSourceCredential -ErrorAction Stop
    Write-Host "Connected to Source: $($sourceVIServer.Name) ($($sourceVIServer.Version))" -ForegroundColor Green
    
    # Connect to Target vCenter
    Write-Host "Connecting to Target vCenter: $TargetVCenter..."
    $targetVIServer = Connect-VIServer -Server $TargetVCenter -Credential $resolvedTargetCredential -ErrorAction Stop
    Write-Host "Connected to Target: $($targetVIServer.Name) ($($targetVIServer.Version))" -ForegroundColor Green
    
    if ($CopyAllDatacenters) {
        # Copy all datacenters
        Write-Host "Retrieving all datacenters from source vCenter..." -ForegroundColor Yellow
        $sourceDatacenters = Get-Datacenter -Server $sourceVIServer -ErrorAction Stop
        
        if (-not $sourceDatacenters) {
            throw "No datacenters found in source vCenter '$SourceVCenter'."
        }
        
        Write-Host "Found $($sourceDatacenters.Count) datacenter(s) in source vCenter." -ForegroundColor Green
        
        foreach ($sourceDc in $sourceDatacenters) {
            Write-Host "`nProcessing source datacenter: '$($sourceDc.Name)'" -ForegroundColor Yellow
            
            # Check if target datacenter exists
            $targetDc = Get-Datacenter -Name $sourceDc.Name -Server $targetVIServer -ErrorAction SilentlyContinue
            
            if (-not $targetDc) {
                if ($CreateMissingDatacenters) {
                    Write-Host "Creating missing datacenter '$($sourceDc.Name)' in target vCenter..." -ForegroundColor Yellow
                    try {
                        $targetDc = New-Datacenter -Name $sourceDc.Name -Location (Get-Folder -Type Datacenter -Server $targetVIServer | Select-Object -First 1) -Server $targetVIServer -ErrorAction Stop
                        Write-Host "Successfully created datacenter '$($targetDc.Name)'" -ForegroundColor Green
                    } catch {
                        Write-Error "Failed to create datacenter '$($sourceDc.Name)' in target vCenter: $($_.Exception.Message)"
                        continue
                    }
                } else {
                    Write-Warning "Target datacenter '$($sourceDc.Name)' not found in target vCenter. Skipping. Use -CreateMissingDatacenters to create it automatically."
                    continue
                }
            } else {
                Write-Host "Found matching target datacenter: '$($targetDc.Name)'" -ForegroundColor Green
            }
            
            # Copy folder structure for this datacenter pair
            Copy-DatacenterFolderStructure -SourceDatacenter $sourceDc -TargetDatacenter $targetDc -SourceServer $sourceVIServer -TargetServer $targetVIServer
        }
        
        Write-Host "`nCompleted copying folder structures for all datacenters." -ForegroundColor Magenta
        
   } else {
        # Copy specific datacenter(s)
        $sourceDcName = $SourceDatacenterName
        $targetDcName = $TargetDatacenterName
        
        # If datacenter names not provided, prompt user to select
        if (-not $sourceDcName) {
            Write-Host "No source datacenter specified. Available datacenters in source vCenter:" -ForegroundColor Yellow
            $availableSourceDCs = Get-Datacenter -Server $sourceVIServer -ErrorAction Stop
            
            if (-not $availableSourceDCs) {
                throw "No datacenters found in source vCenter '$SourceVCenter'."
            }
            
            for ($i = 0; $i -lt $availableSourceDCs.Count; $i++) {
                Write-Host "  [$($i+1)] $($availableSourceDCs[$i].Name)"
            }
            
            do {
                $selection = Read-Host "Please select source datacenter (1-$($availableSourceDCs.Count))"
                $selectionIndex = [int]$selection - 1
            } while ($selectionIndex -lt 0 -or $selectionIndex -ge $availableSourceDCs.Count)
            
            $sourceDcName = $availableSourceDCs[$selectionIndex].Name
            Write-Host "Selected source datacenter: '$sourceDcName'" -ForegroundColor Green
        }
        
        if (-not $targetDcName) {
            Write-Host "No target datacenter specified. Available datacenters in target vCenter:" -ForegroundColor Yellow
            $availableTargetDCs = Get-Datacenter -Server $targetVIServer -ErrorAction Stop
            
            if (-not $availableTargetDCs) {
                throw "No datacenters found in target vCenter '$TargetVCenter'."
            }
            
            for ($i = 0; $i -lt $availableTargetDCs.Count; $i++) {
                Write-Host "  [$($i+1)] $($availableTargetDCs[$i].Name)"
            }
            
            do {
                $selection = Read-Host "Please select target datacenter (1-$($availableTargetDCs.Count))"
                $selectionIndex = [int]$selection - 1
            } while ($selectionIndex -lt 0 -or $selectionIndex -ge $availableTargetDCs.Count)
            
            $targetDcName = $availableTargetDCs[$selectionIndex].Name
            Write-Host "Selected target datacenter: '$targetDcName'" -ForegroundColor Green
        }
        
        # Get the specific source datacenter
        Write-Host "Retrieving Source Datacenter '$sourceDcName'..."
        $sourceDc = Get-Datacenter -Name $sourceDcName -Server $sourceVIServer -ErrorAction SilentlyContinue
        if (-not $sourceDc) {
            throw "Source Datacenter '$sourceDcName' not found on vCenter '$SourceVCenter'."
        }
        Write-Host "Found Source Datacenter: '$($sourceDc.Name)'" -ForegroundColor Green
        
        # Get the specific target datacenter
        Write-Host "Retrieving Target Datacenter '$targetDcName'..."
        $targetDc = Get-Datacenter -Name $targetDcName -Server $targetVIServer -ErrorAction SilentlyContinue
        if (-not $targetDc) {
            throw "Target Datacenter '$targetDcName' not found on vCenter '$TargetVCenter'."
        }
        Write-Host "Found Target Datacenter: '$($targetDc.Name)'" -ForegroundColor Green
        
        # Copy folder structure for the specified datacenter pair
        Copy-DatacenterFolderStructure -SourceDatacenter $sourceDc -TargetDatacenter $targetDc -SourceServer $sourceVIServer -TargetServer $targetVIServer
    }

} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    Write-Error "Script execution halted."
    # Display full error details if verbose
    if ($VerbosePreference -eq 'Continue') {
        Write-Error "Full error details: $($_.Exception.ToString())"
    }
} finally {
    # Disconnect from vCenters if connections were established
    if ($sourceVIServer) {
        Write-Host "Disconnecting from Source vCenter: $($sourceVIServer.Name)..."
        Disconnect-VIServer -Server $sourceVIServer -Confirm:$false -Force:$true
    }
    if ($targetVIServer) {
        Write-Host "Disconnecting from Target vCenter: $($targetVIServer.Name)..."
        Disconnect-VIServer -Server $targetVIServer -Confirm:$false -Force:$true
    }
    Write-Host "Script finished." -ForegroundColor Cyan
}