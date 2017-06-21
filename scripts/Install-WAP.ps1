param(
    [string]
    $DomainDNSName = "example.com",

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

    $WAPScriptBlock = {
        $ErrorActionPreference = "Stop"

        Import-PfxCertificate –FilePath "\\ADFS1\cert\adfs.pfx" -CertStoreLocation cert:\localMachine\my -Password $Using:Pass
        $CertificateThumbprint = (dir Cert:\LocalMachine\My)[0].thumbprint

        Install-WindowsFeature Web-Application-Proxy -IncludeManagementTools

        while (-not (Resolve-DnsName -Name "sts.$Using:DomainDNSName" -ErrorAction SilentlyContinue)) { Write-Host "Unable to resolve sts.$Using:DomainDNSName. Waiting for 5 seconds before retrying."; Start-Sleep 5 }

        $configured = $false
        $tries = 0
        do {
            try {
                Install-WebApplicationProxy –CertificateThumbprint $CertificateThumbprint -FederationServiceName "sts.$Using:DomainDNSName" -FederationServiceTrustCredential $Using:Credential
                $configured = $true
                break
            }
            catch {
                $tries++
                Write-Host "Configuration failed for Web Application Proxy. Exception:"
                Write-Host $_
                Start-Sleep -Seconds 60
            }
        } while ($tries -lt 5)
        if (-not $configured) {
            throw "WAP configuration failed even after multiple retries"
        }
    }
    Invoke-Command -Authentication Credssp -Scriptblock $WAPScriptBlock -ComputerName $env:COMPUTERNAME -Credential $Credential
}
catch {
    Write-Verbose "$($_.exception.message)@ $(Get-Date)"
    $_ | Write-AWSQuickStartException
}