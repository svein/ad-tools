#requires -Version 7.0
<#
.SYNOPSIS
    Gets Active Directory user details from usernames.

.DESCRIPTION
    Looks up one username or usernames from a text file, with one value per
    line. Accepts sAMAccountName, DOMAIN\sAMAccountName, or user principal
    name (UPN). Returns the input value, display name, username, UPN, status,
    and any per-input error message. Searches the current domain using the
    current Windows logon credentials. Requires read access and domain
    connectivity; the ActiveDirectory module and administrative rights are
    not required.

.PARAMETER Username
    A sAMAccountName, DOMAIN\sAMAccountName, or UPN.

.PARAMETER InputFile
    A text file containing one username per line. Blank lines are ignored.

.EXAMPLE
    .\Get-ADUserDetailsByUsername.ps1 -Username 'jsmith'

.EXAMPLE
    .\Get-ADUserDetailsByUsername.ps1 -InputFile .\usernames.txt

.EXAMPLE
    .\Get-ADUserDetailsByUsername.ps1 -InputFile .\usernames.txt |
        Where-Object Status -eq 'Found' |
        Select-Object InputValue, Name, Username

.EXAMPLE
    .\Get-ADUserDetailsByUsername.ps1 -InputFile .\usernames.txt |
        Export-Csv -Path .\results.csv -NoTypeInformation -Encoding UTF8
#>
[CmdletBinding(DefaultParameterSetName = 'Single')]
param (
    [Parameter(
        Mandatory = $true,
        Position = 0,
        ParameterSetName = 'Single'
    )]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'File'
    )]
    [ValidateNotNullOrEmpty()]
    [string]$InputFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop

function ConvertTo-LdapFilterValue {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $builder = [System.Text.StringBuilder]::new()

    foreach ($character in $Value.ToCharArray()) {
        $characterCode = [int][char]$character

        switch ($characterCode) {
            0  { [void]$builder.Append('\00') }
            40 { [void]$builder.Append('\28') }
            41 { [void]$builder.Append('\29') }
            42 { [void]$builder.Append('\2a') }
            92 { [void]$builder.Append('\5c') }
            default {
                [void]$builder.Append($character)
            }
        }
    }

    return $builder.ToString()
}

function Get-SearchResultProperty {
    param (
        [Parameter(Mandatory = $true)]
        $Result,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $propertyValues = $Result.Properties[$PropertyName]

    if ($null -ne $propertyValues -and $propertyValues.Count -gt 0) {
        return [string]$propertyValues[0]
    }

    return $null
}

# Build a list of input records.
$inputRecords = @()

if ($PSCmdlet.ParameterSetName -eq 'File') {
    try {
        $file = Get-Item -LiteralPath $InputFile -ErrorAction Stop

        if ($file.PSIsContainer) {
            throw "'$InputFile' is a directory, not a text file."
        }

        $lineNumber = 0

        $inputRecords = @(
            foreach ($line in Get-Content -LiteralPath $file.FullName `
                                             -ErrorAction Stop) {
                $lineNumber++

                $value = ([string]$line).Trim()

                # Blank lines are ignored.
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    [pscustomobject][ordered]@{
                        Value      = $value
                        LineNumber = $lineNumber
                    }
                }
            }
        )
    }
    catch {
        throw "Could not read input file '$InputFile': $($_.Exception.Message)"
    }
}
else {
    $value = $Username.Trim()

    if ([string]::IsNullOrWhiteSpace($value)) {
        throw 'Username cannot be empty or contain only spaces.'
    }

    $inputRecords = @(
        [pscustomobject][ordered]@{
            Value      = $value
            LineNumber = $null
        }
    )
}

if ($inputRecords.Count -eq 0) {
    throw 'The input file contains no non-empty lines.'
}

$rootDse    = $null
$searchRoot = $null
$searcher   = $null

try {
    $rootDse = [System.DirectoryServices.DirectoryEntry]::new(
        'LDAP://RootDSE'
    )

    $defaultNamingContext = [string](
        $rootDse.Properties['defaultNamingContext'][0]
    )

    if ([string]::IsNullOrWhiteSpace($defaultNamingContext)) {
        throw 'Could not determine the current Active Directory domain.'
    }

    $searchRoot = [System.DirectoryServices.DirectoryEntry]::new(
        "LDAP://$defaultNamingContext"
    )

    $searcher = [System.DirectoryServices.DirectorySearcher]::new(
        $searchRoot
    )

    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.SizeLimit = 1
    $searcher.ClientTimeout = [TimeSpan]::FromSeconds(30)
    $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds(30)

    @(
        'displayName'
        'givenName'
        'sn'
        'name'
        'sAMAccountName'
        'userPrincipalName'
    ) | ForEach-Object {
        [void]$searcher.PropertiesToLoad.Add($_)
    }

    foreach ($inputRecord in $inputRecords) {
        $originalIdentity = $inputRecord.Value

        try {
            $lookupIdentity = $originalIdentity

            # Convert DOMAIN\username to username.
            if ($lookupIdentity -match '^[^\\]+\\(.+)$') {
                $lookupIdentity = $Matches[1]
            }

            $escapedIdentity = ConvertTo-LdapFilterValue `
                -Value $lookupIdentity

            if ($lookupIdentity.Contains('@')) {
                $identityFilter = (
                    "(userPrincipalName=$escapedIdentity)"
                )
            }
            else {
                $identityFilter = (
                    "(sAMAccountName=$escapedIdentity)"
                )
            }

            $searcher.Filter = (
                '(&(objectCategory=person)' +
                '(objectClass=user)' +
                $identityFilter +
                ')'
            )

            $result = $searcher.FindOne()

            if ($null -eq $result) {
                [pscustomobject][ordered]@{
                    InputValue        = $originalIdentity
                    LineNumber        = $inputRecord.LineNumber
                    Name              = $null
                    Username          = $null
                    UserPrincipalName = $null
                    Status            = 'NotFound'
                    ErrorMessage      = $null
                }

                continue
            }

            $displayName = Get-SearchResultProperty `
                -Result $result `
                -PropertyName 'displayname'

            # Fall back to givenName plus surname when displayName is empty.
            if ([string]::IsNullOrWhiteSpace($displayName)) {
                $givenName = Get-SearchResultProperty `
                    -Result $result `
                    -PropertyName 'givenname'

                $surname = Get-SearchResultProperty `
                    -Result $result `
                    -PropertyName 'sn'

                $displayName = @(
                    $givenName
                    $surname
                ) |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    ForEach-Object {
                        $_.Trim()
                    }

                $displayName = $displayName -join ' '
            }

            # Final fallback to the AD object name.
            if ([string]::IsNullOrWhiteSpace($displayName)) {
                $displayName = Get-SearchResultProperty `
                    -Result $result `
                    -PropertyName 'name'
            }

            [pscustomobject][ordered]@{
                InputValue = $originalIdentity
                LineNumber = $inputRecord.LineNumber
                Name       = $displayName

                Username = Get-SearchResultProperty `
                    -Result $result `
                    -PropertyName 'samaccountname'

                UserPrincipalName = Get-SearchResultProperty `
                    -Result $result `
                    -PropertyName 'userprincipalname'

                Status       = 'Found'
                ErrorMessage = $null
            }
        }
        catch {
            # Return an error record for this line, then continue.
            [pscustomobject][ordered]@{
                InputValue        = $originalIdentity
                LineNumber        = $inputRecord.LineNumber
                Name              = $null
                Username          = $null
                UserPrincipalName = $null
                Status            = 'Error'
                ErrorMessage      = $_.Exception.Message
            }
        }
    }
}
catch {
    throw "Active Directory lookup failed: $($_.Exception.Message)"
}
finally {
    if ($null -ne $searcher) {
        $searcher.Dispose()
    }

    if ($null -ne $searchRoot) {
        $searchRoot.Dispose()
    }

    if ($null -ne $rootDse) {
        $rootDse.Dispose()
    }
}