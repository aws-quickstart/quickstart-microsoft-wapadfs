param(
    [string]
    $DomainDNSName = "example.com",

    [string]
    $DCName = "DC1",

    [string]
    $DomainNetBIOSName = "example",

    [string]
    $Username,

    [string]
    $Password
)

try {
    Start-Transcript -Path C:\cfn\log\Install-WAP.ps1.txt -Append

    $ErrorActionPreference = "Stop"

    $Pass = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList "$DomainNetBIOSName\$Username", $Pass

    Import-PfxCertificate –FilePath "\\$DCName\CertEnroll\adfs.pfx" -CertStoreLocation cert:\localMachine\my -Password $Pass
    $CertificateThumbprint = (dir Cert:\LocalMachine\My)[0].thumbprint

    Install-WindowsFeature Web-Application-Proxy -IncludeManagementTools

    while (-not (Resolve-DnsName -Name "sts.$DomainDNSName" -ErrorAction SilentlyContinue)) { Write-Verbose "Unable to resolve sts.$DomainDNSName. Waiting for 5 seconds before retrying."; Start-Sleep 5 }

    Install-WebApplicationProxy –CertificateThumbprint $CertificateThumbprint -FederationServiceName "sts.$DomainDNSName" -FederationServiceTrustCredential $Credential

    Write-Verbose "Sending CFN Signal @ $(Get-Date)"
    Write-AWSQuickStartStatus -Verbose
}
catch {
    Write-Verbose "$($_.exception.message)@ $(Get-Date)"
    $_ | Write-AWSQuickStartException
}