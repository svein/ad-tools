#requires -Version 7.0
<#
.SYNOPSIS
    Finds Active Directory users by full or partial name.

.DESCRIPTION
    Looks up one name or names from a text file, with one value per line. Each
    search term is split into words; every word must match at least one of the
    user's display name, name, given name, surname, or sAMAccountName fields.
    Returns matching names, usernames, UPNs, and a status for each input.
    Searches the current domain using the current Windows logon credentials.
    Requires read access and domain connectivity; the ActiveDirectory module
    and administrative rights are not required.

.PARAMETER PartialName
    One or more name terms to search for.

.PARAMETER InputFile
    A text file containing one name per line. Blank lines are ignored.

.PARAMETER MaxResults
    Maximum number of matching users returned per input value (1–1000).

.EXAMPLE
    .\Get-ADUserByName.ps1 -PartialName 'John Smith'

.EXAMPLE
    .\Get-ADUserByName.ps1 -InputFile .\names.txt

.EXAMPLE
    .\Get-ADUserByName.ps1 -InputFile .\names.txt -MaxResults 20

.EXAMPLE
    .\Get-ADUserByName.ps1 -InputFile .\names.txt |
        Where-Object Status -eq 'Found' |
        Select-Object InputValue, Name, Username
#>
[CmdletBinding(DefaultParameterSetName = 'Single')]
param (
    [Parameter(
        Mandatory = $true,
        Position = 0,
        ParameterSetName = 'Single'
    )]
    [ValidateNotNullOrEmpty()]
    [string]$PartialName,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'File'
    )]
    [ValidateNotNullOrEmpty()]
    [string]$InputFile,

    [Parameter()]
    [ValidateRange(1, 1000)]
    [int]$MaxResults = 50
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
    $value = $PartialName.Trim()

    if ([string]::IsNullOrWhiteSpace($value)) {
        throw 'PartialName cannot be empty or contain only spaces.'
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
    # Discover the current Active Directory domain.
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
    $searcher.PageSize = 500
    $searcher.SizeLimit = $MaxResults
    $searcher.ClientTimeout = [TimeSpan]::FromSeconds(30)
    $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds(30)

    @(
        'displayName'
        'name'
        'sAMAccountName'
        'userPrincipalName'
    ) | ForEach-Object {
        [void]$searcher.PropertiesToLoad.Add($_)
    }

    foreach ($inputRecord in $inputRecords) {
        $searchValue = $inputRecord.Value
        $results = $null

        try {
            # Every word in the input must match at least one name-related
            # Active Directory attribute.
            $tokens = @(
                $searchValue -split '\s+' |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
            )

            $tokenFilters = foreach ($token in $tokens) {
                $escapedToken = ConvertTo-LdapFilterValue -Value $token

                '(|' +
                    "(displayName=*$escapedToken*)" +
                    "(name=*$escapedToken*)" +
                    "(givenName=*$escapedToken*)" +
                    "(sn=*$escapedToken*)" +
                    "(sAMAccountName=*$escapedToken*)" +
                ')'
            }

            $combinedTokenFilter = $tokenFilters -join ''

            $searcher.Filter = (
                '(&(objectCategory=person)' +
                '(objectClass=user)' +
                $combinedTokenFilter +
                ')'
            )

            $results = $searcher.FindAll()

            $users = @(
                foreach ($result in $results) {
                    $name = Get-SearchResultProperty `
                        -Result $result `
                        -PropertyName 'displayname'

                    if ([string]::IsNullOrWhiteSpace($name)) {
                        $name = Get-SearchResultProperty `
                            -Result $result `
                            -PropertyName 'name'
                    }

                    [pscustomobject][ordered]@{
                        Name = $name

                        Username = Get-SearchResultProperty `
                            -Result $result `
                            -PropertyName 'samaccountname'

                        UserPrincipalName = Get-SearchResultProperty `
                            -Result $result `
                            -PropertyName 'userprincipalname'
                    }
                }
            )

            if ($users.Count -eq 0) {
                [pscustomobject][ordered]@{
                    InputValue        = $searchValue
                    LineNumber        = $inputRecord.LineNumber
                    Name              = $null
                    Username          = $null
                    UserPrincipalName = $null
                    ResultCount       = 0
                    Status            = 'NotFound'
                    ErrorMessage      = $null
                }

                continue
            }

            foreach (
                $user in (
                    $users |
                        Sort-Object -Property Name, Username
                )
            ) {
                [pscustomobject][ordered]@{
                    InputValue        = $searchValue
                    LineNumber        = $inputRecord.LineNumber
                    Name              = $user.Name
                    Username          = $user.Username
                    UserPrincipalName = $user.UserPrincipalName
                    ResultCount       = $users.Count
                    Status            = 'Found'
                    ErrorMessage      = $null
                }
            }
        }
        catch {
            # Return an error record for this line, then continue.
            [pscustomobject][ordered]@{
                InputValue        = $searchValue
                LineNumber        = $inputRecord.LineNumber
                Name              = $null
                Username          = $null
                UserPrincipalName = $null
                ResultCount       = 0
                Status            = 'Error'
                ErrorMessage      = $_.Exception.Message
            }
        }
        finally {
            if ($null -ne $results) {
                $results.Dispose()
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