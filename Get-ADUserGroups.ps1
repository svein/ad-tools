#requires -Version 7.0
<#
.SYNOPSIS
    Lists the Active Directory groups a user belongs to.

.DESCRIPTION
    Uses the Windows-only System.DirectoryServices LDAP client and the current
    Windows logon credentials. Returns direct and nested group memberships, as
    well as the user's primary group. Searches the current domain and requires
    network connectivity and read access to the relevant objects. The
    ActiveDirectory module and administrative rights are not required.

.PARAMETER User
    A user's sAMAccountName, userPrincipalName, or distinguished name. If the
    value matches more than one user, pass the distinguished name.

.EXAMPLE
    .\Get-ADUserGroups.ps1 -User jsmith

.EXAMPLE
    .\Get-ADUserGroups.ps1 -User jsmith@example.com |
        Export-Csv -Path .\groups.csv -NoTypeInformation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $User
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory)][string] $Value)

    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function New-Searcher {
    param(
        [Parameter(Mandatory)][string] $SearchRoot,
        [Parameter(Mandatory)][string] $Filter
    )

    $root = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$SearchRoot")
    $searcher = [System.DirectoryServices.DirectorySearcher]::new($root)
    $searcher.Filter = $Filter
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.PageSize = 500
    $searcher.CacheResults = $false
    return $searcher
}

function Find-User {
    param(
        [Parameter(Mandatory)][string] $SearchRoot,
        [Parameter(Mandatory)][string] $Identity
    )

    $escaped = ConvertTo-LdapFilterValue $Identity
    $filter = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$escaped)(userPrincipalName=$escaped)(distinguishedName=$escaped)))"
    $searcher = New-Searcher -SearchRoot $SearchRoot -Filter $filter
    try {
        foreach ($property in @('distinguishedName', 'cn', 'displayName', 'sAMAccountName', 'memberOf', 'primaryGroupID', 'objectSid')) {
            $null = $searcher.PropertiesToLoad.Add($property)
        }
        $results = $searcher.FindAll()
        try {
            if ($results.Count -eq 0) {
                throw "No user matched '$Identity' in '$SearchRoot'. Use the exact sAMAccountName, UPN, or distinguished name."
            }
            if ($results.Count -gt 1) {
                $matches = @($results | ForEach-Object { [string]$_.Properties['distinguishedname'][0] })
                throw "The user identity '$Identity' is ambiguous. Matches:`n$($matches -join "`n")`nPass the user's distinguished name."
            }
            $userResult = $results[0]
            return [pscustomobject]@{
                DistinguishedName = [string]$userResult.Properties['distinguishedname'][0]
                PrimaryGroupID   = [int]$userResult.Properties['primarygroupid'][0]
                ObjectSid        = [byte[]]$userResult.Properties['objectsid'][0]
            }
        }
        finally {
            $results.Dispose()
        }
    }
    finally {
        $searcher.Dispose()
    }
}

function Get-RangedValues {
    param(
        [Parameter(Mandatory)][string] $SearchRoot,
        [Parameter(Mandatory)][string] $DistinguishedName,
        [Parameter(Mandatory)][string] $Attribute
    )

    $start = 0
    while ($true) {
        $escapedDn = ConvertTo-LdapFilterValue $DistinguishedName
        $searcher = New-Searcher -SearchRoot $SearchRoot -Filter "(distinguishedName=$escapedDn)"
        try {
            $null = $searcher.PropertiesToLoad.Add("${Attribute};range=$start-*")
            $result = $searcher.FindOne()
            if ($null -eq $result) {
                throw "Could not read '$Attribute' from '$DistinguishedName'."
            }

            $propertyName = @($result.Properties.PropertyNames | Where-Object { $_ -match "^$([regex]::Escape($Attribute))(;range=\d+-\d+|;range=\d+-\*)?$" }) | Select-Object -First 1
            if (-not $propertyName) { return }

            foreach ($value in $result.Properties[$propertyName]) { $value }

            if ($propertyName -match ';range=\d+-(\d+)$') {
                $start = [int]$Matches[1] + 1
            } else {
                return
            }
        }
        finally {
            $searcher.Dispose()
        }
    }
}

function ConvertTo-GroupRecord {
    param([Parameter(Mandatory)] $SearchResult)

    $classes = @($SearchResult.Properties['objectclass'] | ForEach-Object { [string]$_ })
    $leafClass = if ($classes.Count -gt 0) { $classes[-1] } else { 'unknown' }
    $name = if ($SearchResult.Properties['displayname'].Count -gt 0) {
        [string]$SearchResult.Properties['displayname'][0]
    } elseif ($SearchResult.Properties['cn'].Count -gt 0) {
        [string]$SearchResult.Properties['cn'][0]
    } else { '(unnamed)' }
    $sam = if ($SearchResult.Properties['samaccountname'].Count -gt 0) {
        [string]$SearchResult.Properties['samaccountname'][0]
    } else { $null }

    [pscustomobject]@{
        Name              = $name
        SamAccountName    = $sam
        ObjectClass       = $leafClass
        MembershipType    = $null
        DistinguishedName = [string]$SearchResult.Properties['distinguishedname'][0]
    }
}

try {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'This script requires PowerShell 7 or later on Windows.'
    }
    Add-Type -AssemblyName System.DirectoryServices

    $rootDse = [System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE')
    try {
        $searchRoot = [string]$rootDse.Properties['defaultNamingContext'][0]
    }
    finally {
        $rootDse.Dispose()
    }
    if ([string]::IsNullOrWhiteSpace($searchRoot)) {
        throw 'Could not read the domain naming context. Confirm this client can contact an Active Directory domain controller.'
    }

    $userResult = Find-User -SearchRoot $searchRoot -Identity $User
    $userDn = $userResult.DistinguishedName
    $directDns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($dn in (Get-RangedValues -SearchRoot $searchRoot -DistinguishedName $userDn -Attribute 'memberOf')) {
        $null = $directDns.Add([string]$dn)
    }

    # AD's matching-rule-in-chain returns groups reached through nested groups.
    $escapedUserDn = ConvertTo-LdapFilterValue $userDn
    $groupSearcher = New-Searcher -SearchRoot $searchRoot -Filter "(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=$escapedUserDn))"
    $groups = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        foreach ($property in @('distinguishedName', 'cn', 'displayName', 'sAMAccountName', 'objectClass')) {
            $null = $groupSearcher.PropertiesToLoad.Add($property)
        }
        $groupResults = $groupSearcher.FindAll()
        try {
            foreach ($groupResult in $groupResults) {
                $record = ConvertTo-GroupRecord -SearchResult $groupResult
                $record.MembershipType = if ($directDns.Contains($record.DistinguishedName)) { 'Direct' } else { 'Nested' }
                $groups[$record.DistinguishedName] = $record
            }
        }
        finally {
            $groupResults.Dispose()
        }
    }
    finally {
        $groupSearcher.Dispose()
    }

    # primaryGroupID is not represented in the user's memberOf attribute.
    $primaryGroupId = [int]$userResult.PrimaryGroupID
    $userSid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$userResult.ObjectSid, 0)
    $domainSid = $userSid.AccountDomainSid
    if ($null -eq $domainSid) {
        throw "Could not determine the domain SID for '$userDn'."
    }
    $primarySid = [System.Security.Principal.SecurityIdentifier]::new("$($domainSid.Value)-$primaryGroupId")
    $sidBytes = [byte[]]::new($primarySid.BinaryLength)
    $primarySid.GetBinaryForm($sidBytes, 0)
    $sidFilter = ($sidBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''

    $primarySearcher = New-Searcher -SearchRoot $searchRoot -Filter "(&(objectCategory=group)(objectSid=$sidFilter))"
    try {
        foreach ($property in @('distinguishedName', 'cn', 'displayName', 'sAMAccountName', 'objectClass')) {
            $null = $primarySearcher.PropertiesToLoad.Add($property)
        }
        $primaryResult = $primarySearcher.FindOne()
        if ($null -eq $primaryResult) {
            throw "Could not resolve primary group SID '$primarySid'."
        }
        $primaryRecord = ConvertTo-GroupRecord -SearchResult $primaryResult
        $primaryRecord.MembershipType = 'Primary'
        $groups[$primaryRecord.DistinguishedName] = $primaryRecord
    }
    finally {
        $primarySearcher.Dispose()
    }

    $groups.Values | Sort-Object Name, DistinguishedName
}
catch {
    Write-Error $_
    exit 1
}
