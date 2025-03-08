<# 
.SYNOPSIS
    Synchronizes SAP BTP default users and roles with custom IdP users.

.DESCRIPTION
    This script loads configuration from a YAML file (config.yaml), obtains an OAuth token using client credentials,
    and then synchronizes users and roles between the “sap.default” and “sap.custom” origins.
    Optionally you can synchronize a single user (with --user) or copy role assignments from one user to another 
    (with --copy-source and --copy-dest).
    If the client credentials (clientid and clientsecret) are not present in the YAML configuration file, the script 
    attempts to retrieve them from the environment variables SAP_BTP_CLIENTID and SAP_BTP_CLIENTSECRET respectively.
.PARAMETER user
    Email address of a user to synchronize exclusively.

.PARAMETER copy_source
    Email of the default user to copy roles from.

.PARAMETER copy_dest
    Email of the destination user to copy roles to.

.NOTES
    - This script uses only built-in PowerShell cmdlets (using Invoke-RestMethod for REST calls).
    - A very simple YAML importer is defined here so that no extra modules are needed. 
      (It supports a limited YAML syntax expected in the configuration file.)
    - This script is licensed under the MIT License.
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory=$false)]
    [string]$user,

    [Parameter(Mandatory=$false)]
    [string]$copy_source,

    [Parameter(Mandatory=$false)]
    [string]$copy_dest
)

#----------------------------------------
# Helper: Basic logging function
function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timestamp - $Level - $Message"
}

#----------------------------------------
# Helper: Very basic YAML importer for simple key/value and list structures.
function Import-Yaml {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        throw "Configuration file '$Path' not found."
    }
    $content = Get-Content $Path -Raw
    $lines = $content -split "`r?`n"
    $obj = @{}
    $currentKey = $null

    foreach ($line in $lines) {
        # Skip comments and blank lines
        if ($line.Trim() -match '^(#|$)') { continue }
        if ($line -match '^\s*([^:]+):\s*(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            # Remove surrounding quotes if present
            if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            if ($value -eq "") {
                $obj[$key] = @()
                $currentKey = $key
            }
            else {
                if ($value.StartsWith('[') -and $value.EndsWith(']')) {
                    $inner = $value.TrimStart('[').TrimEnd(']')
                    $list = $inner -split ','
                    $obj[$key] = $list | ForEach-Object { $_.Trim() }
                }
                else {
                    $obj[$key] = $value
                }
                $currentKey = $null
            }
        }
        elseif ($line -match '^\s*-\s*(.+)$') {
            if ($currentKey) {
                $obj[$currentKey] += $matches[1].Trim()
            }
        }
    }
    return $obj
}

#----------------------------------------
# Global configuration variable (loaded later)
$Global:Config = $null
$Global:AccessToken = $null
$Global:RoleCollections = @{}

#----------------------------------------
# Function: Get OAuth token using client credentials
function Get-OAuthToken {
    try {
        # Check and use environment variables if clientid or clientsecret are missing or empty
        if (-not $Global:Config.clientid -or $Global:Config.clientid -eq "") {
            $Global:Config.clientid = $env:SAP_BTP_CLIENTID
        }
        if (-not $Global:Config.clientsecret -or $Global:Config.clientsecret -eq "") {
            $Global:Config.clientsecret = $env:SAP_BTP_CLIENTSECRET
        }
        $pair = "$($Global:Config.clientid):$($Global:Config.clientsecret)"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
        $headers = @{
            "Authorization" = "Basic $encoded"
            "Accept"        = "application/json"
            "Content-Type"  = "application/x-www-form-urlencoded"
        }
        $body = "grant_type=client_credentials"
        $response = Invoke-RestMethod -Uri $Global:Config.access_token_url -Method Post -Headers $headers -Body $body
        $Global:AccessToken = $response.access_token
        Write-Log "INFO" "Token obtained: $Global:AccessToken"
        Write-Log "INFO" "Successfully obtained OAuth token"
    }
    catch {
        Write-Log "ERROR" "Failed to obtain OAuth token: $_"
        throw
    }
}

#----------------------------------------
# Function: Return headers with the Bearer token
function Get-Headers {
    return @{
        "Authorization" = "Bearer $Global:AccessToken"
        "Accept"      = "application/json"
    }
}

#----------------------------------------
# Function: Get users for a given origin (sap.default or sap.custom)
function Get-Users {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Origin
    )
    try {
        $url = "$($Global:Config.apiurl.TrimEnd('/'))/Users"
        $filter = "origin eq `"$Origin`""
        $encodedFilter = [System.Web.HttpUtility]::UrlEncode($filter)
        # Use concatenation to build the full request URI
        $uri = $url + "?filter=" + $encodedFilter
        $headers = Get-Headers
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        $users = @{}
        foreach ($user in $response.resources) {
            if ($user.emails -and $user.emails.Count -gt 0) {
                $email = $user.emails[0].value.Trim().ToLower()
                $users[$email] = $user
            }
        }
        Write-Log "INFO" "Retrieved $($users.Keys.Count) users from $Origin"
        return $users
    }
    catch {
        Write-Log "ERROR" "Failed to retrieve users from ${Origin}: $($_.Exception.Message)"
        throw
    }
}

#----------------------------------------
# Function: Create a custom user based on a default user
function Create-CustomUser {
    param(
        [Parameter(Mandatory=$true)]
        $DefaultUser
    )
    try {
        $userData = @{
            userName = $DefaultUser.userName
            emails   = @(@{ value = $DefaultUser.emails[0].value; primary = $false })
            origin   = "sap.custom"
            zoneId   = $Global:Config.subaccountid
            schemas  = @("urn:scim:schemas:core:1.0")
        }
        $headers = Get-Headers
        $headers["Content-Type"] = "application/json"
        $url = "$($Global:Config.apiurl)/Users"
        $jsonBody = $userData | ConvertTo-Json -Depth 5
        Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $jsonBody | Out-Null
        Write-Log "INFO" "Created custom user: $($DefaultUser.userName)"
    }
    catch {
        Write-Log "ERROR" "Failed to create custom user $($DefaultUser.userName): $_"
        throw
    }
}

#----------------------------------------
# Function: Retrieve all role collections
function Get-RoleCollections {
    try {
        $url = "$($Global:Config.apiurl)/Groups"
        $headers = Get-Headers
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        $roleCollections = @{}
        foreach ($role in $response.resources) {
            $roleCollections[$role.id] = $role
        }
        Write-Log "INFO" "Retrieved $($roleCollections.Keys.Count) role collections"
        $Global:RoleCollections = $roleCollections
    }
    catch {
        Write-Log "ERROR" "Failed to retrieve role collections: $_"
        throw
    }
}

#----------------------------------------
# Function: Assign a role to a user
function Assign-RoleToUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RoleId,
        [Parameter(Mandatory=$true)]
        [string]$UserId,
        [Parameter(Mandatory=$true)]
        [string]$UserEmail
    )
    try {
        $memberData = @{
            origin = "sap.custom"
            type   = "USER"
            value  = $UserId
        }
        $headers = Get-Headers
        $headers["Content-Type"] = "application/json"
        $url = "$($Global:Config.apiurl)/Groups/$RoleId/members"
        $jsonBody = $memberData | ConvertTo-Json -Depth 5
        Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $jsonBody | Out-Null
        Write-Log "INFO" "Assigned role $RoleId to user $UserEmail ($UserId)"
    }
    catch {
        Write-Log "ERROR" "Failed to assign role $RoleId to user $UserEmail ($UserId): $_"
    }
}

#----------------------------------------
# Function: Remove a role from a user
function Remove-RoleFromUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RoleId,
        [Parameter(Mandatory=$true)]
        [string]$UserId,
        [Parameter(Mandatory=$true)]
        [string]$UserEmail
    )
    try {
        $url = "$($Global:Config.apiurl)/Groups/$RoleId/members/$UserId"
        $headers = Get-Headers
        Invoke-RestMethod -Uri $url -Method Delete -Headers $headers | Out-Null
        Write-Log "INFO" "Removed role $RoleId from user $UserEmail ($UserId)"
    }
    catch {
        Write-Log "ERROR" "Failed to remove role $RoleId from user $UserEmail ($UserId): $_"
    }
}

#----------------------------------------
# Function: Main synchronization process
function Sync-UsersAndRoles {
    param(
        [string]$TargetEmail
    )
    try {
        if ($TargetEmail) {
            $TargetEmail = $TargetEmail.Trim().ToLower()
        }
        
        # Build a hashtable of skip users (remove extra quotes)
        $skip = @{} 
        if ($Global:Config.skip_users) {
            foreach ($u in $Global:Config.skip_users) {
                $cleanEmail = $u.Trim().Trim('"')
                $skip[$cleanEmail.ToLower()] = $true
            }
        }
        
        # Get users from both origins
        $defaultUsers = Get-Users -Origin "sap.default"
        $customUsers  = Get-Users -Origin "sap.custom"
        
        if ($TargetEmail) {
            if ($skip.ContainsKey($TargetEmail)) {
                Write-Log "INFO" "Skipping synchronization for target user: $TargetEmail"
                return
            }
            if ($defaultUsers.ContainsKey($TargetEmail)) {
                $defaultUsers = @{ $TargetEmail = $defaultUsers[$TargetEmail] }
            }
            else {
                $defaultUsers = @{}
            }
            if ($customUsers.ContainsKey($TargetEmail)) {
                $customUsers = @{ $TargetEmail = $customUsers[$TargetEmail] }
            }
            else {
                $customUsers = @{}
            }
        }
        else {
            # Rebuild the hash tables using GetEnumerator to ensure keys are exactly matched
            $newDefault = @{}
            foreach ($entry in $defaultUsers.GetEnumerator()) {
                if (-not $skip.ContainsKey($entry.Key)) {
                    $newDefault[$entry.Key] = $entry.Value
                }
            }
            $defaultUsers = $newDefault

            $newCustom = @{}
            foreach ($entry in $customUsers.GetEnumerator()) {
                if (-not $skip.ContainsKey($entry.Key)) {
                    $newCustom[$entry.Key] = $entry.Value
                }
            }
            $customUsers = $newCustom
        }
        
        # Create missing custom users (those present in default but not in custom)
        foreach ($email in $defaultUsers.Keys) {
            if (-not $customUsers.ContainsKey($email)) {
                Create-CustomUser -DefaultUser $defaultUsers[$email]
            }
        }
        
        # Refresh custom users list and re-filter as above
        $customUsers = Get-Users -Origin "sap.custom"
        if ($TargetEmail) {
            if ($customUsers.ContainsKey($TargetEmail)) {
                $customUsers = @{ $TargetEmail = $customUsers[$TargetEmail] }
            }
            else {
                $customUsers = @{}
            }
        }
        else {
            $newCustom = @{}
            foreach ($entry in $customUsers.GetEnumerator()) {
                if (-not $skip.ContainsKey($entry.Key)) {
                    $newCustom[$entry.Key] = $entry.Value
                }
            }
            $customUsers = $newCustom
        }
        
        # Retrieve role collections before role sync
        Get-RoleCollections
        
        # Role synchronization loop
        foreach ($email in $defaultUsers.Keys) {
            if ($customUsers.ContainsKey($email)) {
                $defaultUser = $defaultUsers[$email]
                $customUser  = $customUsers[$email]

                $defaultRoles = @{}
                if ($defaultUser.groups) {
                    foreach ($g in $defaultUser.groups) {
                        $defaultRoles[$g.value] = $true
                    }
                }
                $customRoles = @{}
                if ($customUser.groups) {
                    foreach ($g in $customUser.groups) {
                        $customRoles[$g.value] = $true
                    }
                }

                foreach ($role in $defaultRoles.Keys) {
                    if (-not $customRoles.ContainsKey($role) -and $Global:RoleCollections.ContainsKey($role)) {
                        Assign-RoleToUser -RoleId $role -UserId $customUser.id -UserEmail $email
                    }
                }
                foreach ($role in $customRoles.Keys) {
                    if (-not $defaultRoles.ContainsKey($role) -and $Global:RoleCollections.ContainsKey($role)) {
                        Remove-RoleFromUser -RoleId $role -UserId $customUser.id -UserEmail $email
                    }
                }
            }
        }
    }
    catch {
        Write-Log "ERROR" "Synchronization failed: $_"
        throw
    }
}

#----------------------------------------
# Function: Copy role assignments from one user to another
function Copy-RoleAssignments {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourceEmail,
        [Parameter(Mandatory=$true)]
        [string]$DestEmail
    )
    try {
        $SourceEmail = $SourceEmail.Trim().ToLower()
        $DestEmail   = $DestEmail.Trim().ToLower()

        $defaultUsersAll = Get-Users -Origin "sap.default"
        $customUsersAll  = Get-Users -Origin "sap.custom"

        if (-not $defaultUsersAll.ContainsKey($SourceEmail)) {
            Write-Log "ERROR" "Source default user $SourceEmail not found"
            return
        }
        if (-not $defaultUsersAll.ContainsKey($DestEmail)) {
            Write-Log "ERROR" "Destination default user $DestEmail not found"
            return
        }

        $sourceDefault = $defaultUsersAll[$SourceEmail]
        $destDefault   = $defaultUsersAll[$DestEmail]

        # Update destination default user roles
        $sourceRolesDefault = @{}
        if ($sourceDefault.groups) {
            foreach ($g in $sourceDefault.groups) { $sourceRolesDefault[$g.value] = $true }
        }
        $destRolesDefault = @{}
        if ($destDefault.groups) {
            foreach ($g in $destDefault.groups) { $destRolesDefault[$g.value] = $true }
        }
        Get-RoleCollections
        foreach ($role in $sourceRolesDefault.Keys) {
            if (-not $destRolesDefault.ContainsKey($role)) {
                if ($Global:RoleCollections.ContainsKey($role)) {
                    Assign-RoleToUser -RoleId $role -UserId $destDefault.id -UserEmail $DestEmail
                }
            }
        }
        foreach ($role in $destRolesDefault.Keys) {
            if (-not $sourceRolesDefault.ContainsKey($role)) {
                if ($Global:RoleCollections.ContainsKey($role)) {
                    Remove-RoleFromUser -RoleId $role -UserId $destDefault.id -UserEmail $DestEmail
                }
            }
        }

        # Ensure destination custom user exists
        if (-not $customUsersAll.ContainsKey($DestEmail)) {
            Create-CustomUser -DefaultUser $destDefault
            $customUsersAll = Get-Users -Origin "sap.custom"
        }
        if (-not $customUsersAll.ContainsKey($DestEmail)) {
            Write-Log "ERROR" "Destination custom user $DestEmail not found even after creation"
            return
        }
        $destCustom = $customUsersAll[$DestEmail]

        # Update destination custom user roles
        $sourceRolesCustom = @{}
        if ($sourceDefault.groups) {
            foreach ($g in $sourceDefault.groups) { $sourceRolesCustom[$g.value] = $true }
        }
        $destRolesCustom = @{}
        if ($destCustom.groups) {
            foreach ($g in $destCustom.groups) { $destRolesCustom[$g.value] = $true }
        }
        foreach ($role in $sourceRolesCustom.Keys) {
            if (-not $destRolesCustom.ContainsKey($role)) {
                if ($Global:RoleCollections.ContainsKey($role)) {
                    Assign-RoleToUser -RoleId $role -UserId $destCustom.id -UserEmail $DestEmail
                }
            }
        }
        foreach ($role in $destRolesCustom.Keys) {
            if (-not $sourceRolesCustom.ContainsKey($role)) {
                if ($Global:RoleCollections.ContainsKey($role)) {
                    Remove-RoleFromUser -RoleId $role -UserId $destCustom.id -UserEmail $DestEmail
                }
            }
        }
    }
    catch {
        Write-Log "ERROR" "Copy role assignments failed: $_"
    }
}

#----------------------------------------
# Main execution
try {
    # Load configuration from config.yaml
    $Global:Config = Import-Yaml -Path "config.yaml"
    # Obtain OAuth token
    Get-OAuthToken

    if ($copy_source -and $copy_dest) {
        Copy-RoleAssignments -SourceEmail $copy_source -DestEmail $copy_dest
    }
    else {
        Sync-UsersAndRoles -TargetEmail $user
    }

    Write-Log "INFO" "Synchronization completed successfully"
}
catch {
    Write-Log "ERROR" "Synchronization failed: $_"
    throw
}