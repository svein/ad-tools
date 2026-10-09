#requires -Version 7.0
<#
.SYNOPSIS
    Lists the members of an Active Directory group.

.DESCRIPTION
    Uses the Windows-only System.DirectoryServices LDAP client and the current
    Windows logon credentials. Direct membership is returned by default. Use
    -Recursive to include members of nested groups. Searches the current domain
    and requires network connectivity and read access to the relevant objects.
    The ActiveDirectory module and administrative rights are not required.

.PARAMETER Group
    A group's sAMAccountName, common name, name, or distinguished name. If the
    value matches more than one group, pass its distinguished name.

.PARAMETER Recursive
    Includes members of nested groups. Groups are included in the output.

.EXAMPLE
    .\Get-ADGroupMembers.ps1 -Group 'Finance Readers'

.EXAMPLE
    .\Get-ADGroupMembers.ps1 -Group 'finance-readers' -Recursive

.EXAMPLE
    .\Get-ADGroupMembers.ps1 -Group 'CN=Finance Readers,OU=Groups,DC=example,DC=com' |
        Export-Csv -Path .\members.csv -NoTypeInformation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $Group,

    [Parameter()]
    [switch] $Recursive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory)][string] $Value)

    # RFC 4515 escaping for LDAP filter assertion values.
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

function Find-Group {
    param(
        [Parameter(Mandatory)][string] $SearchRoot,
        [Parameter(Mandatory)][string] $Identity
    )

    $escaped = ConvertTo-LdapFilterValue $Identity
    $filter = "(&(objectCategory=group)(|(sAMAccountName=$escaped)(cn=$escaped)(name=$escaped)(distinguishedName=$escaped)))"
    $searcher = New-Searcher -SearchRoot $SearchRoot -Filter $filter
    try {
        $null = $searcher.PropertiesToLoad.Add('distinguishedName')
        $null = $searcher.PropertiesToLoad.Add('cn')
        $results = $searcher.FindAll()
        try {
            if ($results.Count -eq 0) {
                throw "No AD group matched '$Identity' in '$SearchRoot'. Use its exact sAMAccountName, name, or distinguished name."
            }
            if ($results.Count -gt 1) {
                $matches = @($results | ForEach-Object { [string]$_.Properties['distinguishedname'][0] })
                throw "The group identity '$Identity' is ambiguous. Matches:`n$($matches -join "`n")`nPass the group's distinguished name."
            }
            return [string]$results[0].Properties['distinguishedname'][0]
        }
        finally {
            $results.Dispose()
        }
    }
    finally {
        $searcher.Dispose()
    }
}

function Get-ObjectInfo {
    param(
        [Parameter(Mandatory)][string] $SearchRoot,
        [Parameter(Mandatory)][string] $DistinguishedName
    )

    $escapedDn = ConvertTo-LdapFilterValue $DistinguishedName
    $searcher = New-Searcher -SearchRoot $SearchRoot -Filter "(distinguishedName=$escapedDn)"
    try {
        foreach ($property in @('distinguishedName', 'cn', 'displayName', 'sAMAccountName', 'objectClass')) {
            $null = $searcher.PropertiesToLoad.Add($property)
        }
        $result = $searcher.FindOne()
        if ($null -eq $result) { return $null }

        $classes = @($result.Properties['objectclass'] | ForEach-Object { [string]$_ })
        $leafClass = if ($classes.Count -gt 0) { $classes[-1] } else { 'unknown' }
        $displayName = if ($result.Properties['displayname'].Count -gt 0) {
            [string]$result.Properties['displayname'][0]
        } elseif ($result.Properties['cn'].Count -gt 0) {
            [string]$result.Properties['cn'][0]
        } else {
            $DistinguishedName
        }
        $sam = if ($result.Properties['samaccountname'].Count -gt 0) {
            [string]$result.Properties['samaccountname'][0]
        } else { $null }
        $dn = if ($result.Properties['distinguishedname'].Count -gt 0) {
            [string]$result.Properties['distinguishedname'][0]
        } else { $DistinguishedName }

        [pscustomobject]@{
            Name              = $displayName
            SamAccountName    = $sam
            ObjectClass       = $leafClass
            DistinguishedName = $dn
        }
    }
    finally {
        $searcher.Dispose()
    }
}

function Get-GroupMemberDns {
    param(
        [Parameter(Mandatory)][string] $SearchRoot,
        [Parameter(Mandatory)][string] $GroupDn
    )

    # AD limits large multivalued attributes. Range retrieval handles groups
    # whose member attribute is returned in chunks.
    $start = 0
    while ($true) {
        $escapedDn = ConvertTo-LdapFilterValue $GroupDn
        $searcher = New-Searcher -SearchRoot $SearchRoot -Filter "(distinguishedName=$escapedDn)"
        try {
            $requested = "member;range=$start-*"
            $null = $searcher.PropertiesToLoad.Add($requested)
            $result = $searcher.FindOne()
            if ($null -eq $result) {
                throw "Could not read group '$GroupDn'. It may have been deleted or you may not have read access."
            }

            $memberPropertyName = @($result.Properties.PropertyNames | Where-Object { $_ -match '^member(;range=\d+-\d+|;range=\d+-\*)?$' }) | Select-Object -First 1
            if (-not $memberPropertyName) { return }

            foreach ($memberDn in $result.Properties[$memberPropertyName]) {
                [string]$memberDn
            }

            if ($memberPropertyName -match ';range=\d+-(\d+)$') {
                $start = [int]$Matches[1] + 1
            } else {
                # No range suffix, or a terminal * range: all values were returned.
                return
            }
        }
        finally {
            $searcher.Dispose()
        }
    }
}

try {
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
    if (-not ('System.DirectoryServices.DirectoryEntry' -as [type])) {
        throw 'System.DirectoryServices is unavailable. Run this script on Windows with PowerShell 7 or later.'
    }

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

    $groupDn = Find-Group -SearchRoot $searchRoot -Identity $Group
    $seenMembers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $visitedGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $output = [System.Collections.Generic.List[object]]::new()

    function Add-GroupMembers {
        param([string] $CurrentGroupDn)

        if (-not $visitedGroups.Add($CurrentGroupDn)) { return }
        foreach ($memberDn in (Get-GroupMemberDns -SearchRoot $searchRoot -GroupDn $CurrentGroupDn)) {
            if (-not $seenMembers.Add($memberDn)) { continue }
            $info = Get-ObjectInfo -SearchRoot $searchRoot -DistinguishedName $memberDn
            if ($null -ne $info) {
                $output.Add($info)
                if ($Recursive -and $info.ObjectClass -eq 'group') {
                    Add-GroupMembers -CurrentGroupDn $info.DistinguishedName
                }
            } else {
                # Preserve the member DN if the object cannot be resolved in this domain.
                $output.Add([pscustomobject]@{
                    Name              = $memberDn
                    SamAccountName    = $null
                    ObjectClass       = 'unresolved'
                    DistinguishedName = $memberDn
                })
            }
        }
    }

    Add-GroupMembers -CurrentGroupDn $groupDn
    $output | Sort-Object Name, DistinguishedName
}
catch {
    Write-Error $_
    exit 1
}
