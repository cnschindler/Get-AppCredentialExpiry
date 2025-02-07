<#
    .SYNOPSIS
    Monitors Microsoft 365 App Secret expiration

    .DESCRIPTION
    Using MS Graph this Script shows the Microsoft 365 App Secret expiration

    Copy this script to the PRTG probe EXEXML scripts folder (${env:ProgramFiles(x86)}\PRTG Network Monitor\Custom Sensors\EXEXML)
    and create a "EXE/Script Advanced. Choose this script from the dropdown and set at least:

    + Parameters: TenantID, ApplicationID, AccessSecret
    + Scanning Interval: minimum 15 minutes

    .PARAMETER TenantID
    Provide the TenantID or TenantName (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx or contoso.onmicrosoft.com)

    .PARAMETER ApplicationID
    Provide the ApplicationID

    .PARAMETER AccessSecret
    Provide the Application Secret

    .PARAMETER IncludeSecretName
    Regular expression to exclude/include secrets on DisplayName or AppName
    Example: ^(PRTG-APP)$ = matches "PRTG-APP" but not "PRTG-APP1"
    Example2: ^(PRTG-.*|TestApp123)$ matches "PRTG-*" and "TestApp123"
    #https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER ExcludeSecretName
    Regular expression to exclude/include secrets on DisplayName or AppName
    Example: ^(PRTG-APP)$ = matches "PRTG-APP" but not "PRTG-APP1"
    Example2: ^(PRTG-.*|TestApp123)$ matches "PRTG-*" and "TestApp123"
    #https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER IncludeAppName
    Regular expression to exclude/include secrets on DisplayName or AppName
    Example: ^(PRTG-APP)$ = matches "PRTG-APP" but not "PRTG-APP1"
    Example2: ^(PRTG-.*|TestApp123)$ matches "PRTG-*" and "TestApp123"
    #https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER ExcludeAppName
    Regular expression to exclude/include secrets on DisplayName or AppName
    Example: ^(PRTG-APP)$ = matches "PRTG-APP" but not "PRTG-APP1"
    Example2: ^(PRTG-.*|TestApp123)$ matches "PRTG-*" and "TestApp123"
    #https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER ProxyAddress
    Provide a proxy server address if this required to make connections to M365
    Example: http://proxy.example.com:3128

    .PARAMETER ProxyUser
    Provide a proxy authentication user if ProxyAddress is used

    .PARAMETER ProxyPassword
    Provide a proxy authentication password if ProxyAddress is used

    .EXAMPLE
    Sample call from PRTG EXE/Script Advanced

    "PRTG-M365-AppSecrets.ps1" -ApplicationID 'Test-APPID' -TenantID 'contoso.onmicrosoft.com' -AccessSecret 'Test-AppSecret'

    Microsoft 365 Permission:
        1. Open Azure AD
        2. Register new APP
        3. Overview >> Get Application ID
        4. Set API Permissions >> MS Graph >> Application >> Application.Read.All
        5. Certificates & secrets >> new Secret

    Based on the Script by Jannos-443
    https://github.com/Jannos-443/PRTG-M365
#>
param(
    [string] $TenantID = '',
    [string] $ApplicationID = '',
    [string] $ApplicationSecret = '',
    [string] $IncludeSecretName = '',
    [string] $ExcludeSecretName = '',
    [string] $IncludeAppName = '',
    [string] $ExcludeAppName = '',
    [string] $ProxyAddress = '',
    [string] $ProxyUser = '',
    [string] $ProxyPassword = '',
    [switch] $debug
)

# Convert the Client Secret to a Secure String
$SecureClientSecret = ConvertTo-SecureString -String $ApplicationSecret -AsPlainText -Force

# Create a PSCredential Object Using the Client ID and Secure Client Secret
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecureClientSecret

Import-Module Microsoft.Graph.authentication
Import-Module Microsoft.Graph.Applications

# Remove ProxyAddress var if it only contains an empty string or else the Invoke-RestMethod will fail if no proxy address has been provided
if ($ProxyAddress -eq "")
{
    Remove-Variable ProxyAddress -ErrorAction SilentlyContinue
}

if (($ProxyAddress -ne "") -and ($ProxyUser -ne "") -and ($ProxyPassword -ne ""))
{
    try
    {
        $SecProxyPassword = ConvertTo-SecureString $ProxyPassword -AsPlainText -Force
        $ProxyCreds = New-Object System.Management.Automation.PSCredential ($ProxyUser, $SecProxyPassword)
    }

    catch
    {
        Write-Output "<prtg>"
        Write-Output " <error>1</error>"
        Write-Output " <text>Error Parsing Proxy Credentials ($($_.Exception.Message))</text>"
        Write-Output "</prtg>"
        Exit
    }
}

else
{
    Remove-Variable ProxyCreds -ErrorAction SilentlyContinue
}

if ($null -ne $ProxyCreds)
{
    [system.net.webrequest]::defaultwebproxy = new-object system.net.webproxy($ProxyAddress)
    [system.net.webrequest]::defaultwebproxy.credentials = $ProxyCreds
    [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
}

#Catch all unhandled Errors
$ErrorActionPreference = "Stop"
trap
{
    $Output = "line:$($_.InvocationInfo.ScriptLineNumber.ToString()) char:$($_.InvocationInfo.OffsetInLine.ToString()) --- message: $($_.Exception.Message.ToString()) --- line: $($_.InvocationInfo.Line.ToString()) "
    $Output = $Output.Replace("<", "")
    $Output = $Output.Replace(">", "")
    $Output = $Output.Replace("#", "")
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>$Output</text>"
    Write-Output "</prtg>"
    Exit
}

#region set TLS to 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#endregion

if (($TenantID -eq "") -or ($Null -eq $TenantID))
{
    Throw "TenantID Variable is empty"
}

if (($ApplicationID -eq "") -or ($Null -eq $ApplicationID))
{
    Throw "ApplicationID Variable is empty"
}

if (($ApplicationSecret -eq "") -or ($Null -eq $ApplicationSecret))
{
    Throw "AccessSecret Variable is empty"
}

$xmlOutput = '<?xml version="1.0" encoding="UTF-8" ?>
<prtg>'

Connect-MgGraph -TenantId $TenantID -ClientSecretCredential $ClientSecretCredential -NoWelcome

$Applications = Get-MgApplication

$NextExpiration = 2000

$CredentialList = New-Object System.Collections.ArrayList

# Added handling of app secrets that will return either a displayname or a customKeyIdentifier. If one is set the other one is null. As the customKeyIdentifier is a base64 string it will be encoded as UTF8.
foreach ($Result in $Applications)
    {
        foreach ($passwordCredential in $Result.passwordCredentials)
        {
            [datetime]$ExpireTime = $passwordCredential.endDateTime

            if ($null -ne $passwordCredential.displayName)
            {
                $SecretDisplayName = $passwordCredential.displayName
            }

            else
            {
                $SecretDisplayName = "empty"
            }
        
        $object = [PSCustomObject]@{
            AppDisplayname    = $Result.displayName
            SecretDisplayname = $SecretDisplayName
            Enddatetime       = $ExpireTime
            DaysLeft          = ($ExpireTime - (Get-Date)).days
        }

        $null = $CredentialList.Add($object)
    }

    foreach ($keyCredential in $Result.keyCredentials)
    {
        [datetime]$ExpireTime = $keyCredential.endDateTime
    
        $object = [PSCustomObject]@{
            AppDisplayname    = $Result.displayName
            SecretDisplayname = $keyCredential.displayName
            Enddatetime       = $ExpireTime
            DaysLeft          = ($ExpireTime - (Get-Date)).days
        }
    
        $null = $CredentialList.Add($object)
    }
}

#Also monitor SAML Signing certs
$ServicePrinicpals = Get-MgServicePrincipal

foreach ($Result in $ServicePrinicpals)
{
    if ($Result.signInAudience -eq "AzureADMyOrg")
    {
        foreach ($passwordCredential in $Result.passwordCredentials)
        {
            [datetime]$ExpireTime = $passwordCredential.endDateTime
            $object = [PSCustomObject]@{
                AppDisplayname    = $Result.displayName
                SecretDisplayname = $passwordCredential.displayName
                Enddatetime       = $ExpireTime
                DaysLeft          = ($ExpireTime - (Get-Date)).days
            }
        
        $null = $CredentialList.Add($object)

        }
    }
}

#Region Filter
#APP
if ($ExcludeAppName -ne "")
{
    $CredentialList = $CredentialList | Where-Object { $_.AppDisplayname -notmatch $ExcludeAppName }
}

if ($IncludeAppName -ne "")
{
    $CredentialList = $CredentialList | Where-Object { $_.AppDisplayname -match $IncludeAppName }
}
#SECRET
if ($ExcludeSecretName -ne "")
{
    $CredentialList = $CredentialList | Where-Object { $_.SecretDisplayname -notmatch $ExcludeSecretName }
}

if ($IncludeSecretName -ne "")
{
    $CredentialList = $CredentialList | Where-Object { $_.SecretDisplayname -match $IncludeSecretName }
}

# Ignore secrets with the value "CWAP_AuthSecret". This is created by default with Azure AD app proxy and working as designed. It rotates keys and needs the last 3 passwords even if expired. https://learn.microsoft.com/en-us/entra/identity/app-proxy/application-proxy-faq
$CredentialList = $CredentialList | Where-Object { $_.SecretDisplayname -ne "CWAP_AuthSecret" }

# Ignore secrets with empty value ""
$CredentialList = $CredentialList | Where-Object { $_.SecretDisplayname -ne $null }

#End Region Filter

$ListCount = ($CredentialList | Measure-Object).Count

if ($ListCount -eq 0)
{
    Write-Output "<prtg>"
    Write-Output " <error>1</error>"
    Write-Output " <text>No Secrets or Certs found! Check Permissions</text>"
    Write-Output "</prtg>"
    Exit
}

$CredentialList = $CredentialList | Sort-Object Enddatetime

$Top5 = $CredentialList | Select-Object -First 5
$OutputText = "Next to expire: "
foreach ($Top in $Top5)
{
    $OutputText += "App: `'$($Top.AppDisplayname)`'  Secret: `'$($Top.SecretDisplayname)`' expires in $($Top.DaysLeft)d  | "
}

#Next Expiration
$NextExpiration = ($CredentialList | Select-Object -First 1).DaysLeft

$xmlOutput += "<result>
<channel>Next Cert Expiration</channel>
<value>$($NextExpiration)</value>
<unit>Custom</unit>
<CustomUnit>Days</CustomUnit>
<LimitMode>1</LimitMode>
<LimitMinWarning>30</LimitMinWarning>
<LimitMinError>10</LimitMinError>
</result>"

$Less90Days = ($CredentialList | Where-Object { $_.DaysLeft -le 90 } | Measure-Object).count
$Less180Days = ($CredentialList | Where-Object { $_.DaysLeft -le 180 } | Measure-Object).count

$xmlOutput += "<result>
<channel>less than 90 days left</channel>
<value>$($Less90Days)</value>
<unit>Count</unit>
</result>
<result>
<channel>less than 180 days left</channel>
<value>$($Less180Days)</value>
<unit>Count</unit>
</result>"

$OutputText = $OutputText.Replace("<", "")
$OutputText = $OutputText.Replace(">", "")
$OutputText = $OutputText.Replace("#", "")
$OutputText = $OutputText.Replace("`"", "")

if ($OutputText.Length -gt 1900)
{
    $OutputText = $OutputText.Substring(0, 1900)
}

$xmlOutput += "<text>$($OutputText)</text>"

$xmlOutput += "</prtg>"

Write-Output $xmlOutput
