<#
.SYNOPSIS
Connects to Security & Compliance PowerShell (IPPS) and exports all RBAC Role Group memberships to CSV.

.DESCRIPTION
- Uses Connect-IPPSSession (modern auth; supports MFA). 【1-859f73】
- Lists role groups via Get-RoleGroup.
- Lists role group members via Get-RoleGroupMember. 【2-d59546】
- Exports to: C:\Scripts Output\RoleGroupsforSentinel.csv

.NOTES
This script DOES NOT grant access. The signed-in user must already have RBAC permissions
to run these cmdlets in the tenant.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName,

    # UPDATED DEFAULT OUTPUT LOCATION
    [Parameter(Mandatory = $false)]
    [string]$OutputFile = "C:\Scripts Output\RoleGroupsforSentinel.csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-ExchangeOnlineManagementModule {
    # Connect-IPPSSession is provided by the ExchangeOnlineManagement module. 【1-859f73】
    $mod = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
           Sort-Object Version -Descending |
           Select-Object -First 1

    if (-not $mod) {
        Write-Host "ExchangeOnlineManagement module not found. Installing (CurrentUser)..." -ForegroundColor Yellow
        Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop
}

function Get-FirstExistingPropertyValue {
    param(
        [Parameter(Mandatory=$true)] $Object,
        [Parameter(Mandatory=$true)] [string[]] $PropertyNames
    )
    foreach ($p in $PropertyNames) {
        if ($Object.PSObject.Properties.Name -contains $p) {
            $v = $Object.$p
            if ($null -ne $v -and "$v".Trim().Length -gt 0) { return $v }
        }
    }
    return $null
}

try {
    Ensure-ExchangeOnlineManagementModule

    Write-Host "Connecting to Security & Compliance PowerShell (IPPS)..." -ForegroundColor Cyan
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        Connect-IPPSSession -ShowBanner:$false
    }
    else {
        Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ShowBanner:$false
    }

    # Ensure output directory exists
    $outDir = Split-Path -Path $OutputFile -Parent
    if (-not (Test-Path -Path $outDir)) {
        Write-Host "Creating output folder: $outDir" -ForegroundColor Yellow
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    }

    Write-Host "Retrieving role groups..." -ForegroundColor Cyan
    $roleGroups = Get-RoleGroup -ResultSize Unlimited

    $rows  = New-Object System.Collections.Generic.List[object]
    $total = @($roleGroups).Count
    $i = 0

    foreach ($rg in $roleGroups) {
        $i++
        $pct = 0
        if ($total -gt 0) { $pct = [math]::Round((($i / [double]$total) * 100), 0) }

        Write-Progress -Activity "Exporting Role Group Members" `
            -Status "$($rg.Name) ($i of $total)" `
            -PercentComplete $pct

        try {
            $members = Get-RoleGroupMember -Identity $rg.Name -ResultSize Unlimited  # 【2-d59546】
        }
        catch {
            $rows.Add([pscustomobject]@{
                RoleGroupName            = $rg.Name
                RoleGroupIdentity        = $rg.Identity
                MemberName               = $null
                MemberType               = $null
                MemberPrimarySmtpAddress = $null
                MemberExternalObjectId   = $null
                Status                   = "FAILED_TO_READ_MEMBERS"
                Error                    = $_.Exception.Message
            })
            continue
        }

        if (-not $members -or @($members).Count -eq 0) {
            $rows.Add([pscustomobject]@{
                RoleGroupName            = $rg.Name
                RoleGroupIdentity        = $rg.Identity
                MemberName               = $null
                MemberType               = $null
                MemberPrimarySmtpAddress = $null
                MemberExternalObjectId   = $null
                Status                   = "NO_MEMBERS"
                Error                    = $null
            })
            continue
        }

        foreach ($m in $members) {
            $memberType = Get-FirstExistingPropertyValue -Object $m -PropertyNames @(
                "RecipientTypeDetails","RecipientType","ObjectClass"
            )

            $smtp = Get-FirstExistingPropertyValue -Object $m -PropertyNames @(
                "PrimarySmtpAddress","WindowsEmailAddress"
            )

            $extId = Get-FirstExistingPropertyValue -Object $m -PropertyNames @(
                "ExternalDirectoryObjectId"
            )

            $rows.Add([pscustomobject]@{
                RoleGroupName            = $rg.Name
                RoleGroupIdentity        = $rg.Identity
                MemberName               = $m.Name
                MemberType               = $memberType
                MemberPrimarySmtpAddress = $smtp
                MemberExternalObjectId   = $extId
                Status                   = "OK"
                Error                    = $null
            })
        }
    }

    Write-Host "Writing CSV to: $OutputFile" -ForegroundColor Green
    $rows | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host "Done. Exported $($rows.Count) rows." -ForegroundColor Green
}
finally {
    Write-Progress -Activity "Exporting Role Group Members" -Completed
}