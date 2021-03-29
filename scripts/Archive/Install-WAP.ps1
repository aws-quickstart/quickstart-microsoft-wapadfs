param(
    [Parameter(Mandatory = $true)][string]$DomainDNSName,
    [Parameter(Mandatory = $true)][string]$DomainNetBIOSName,
    [Parameter(Mandatory = $true)][string]$Username,
    [Parameter(Mandatory = $true)][string]$Password
)

Start-Transcript -Path 'C:\cfn\log\Install-WAP.ps1.txt' -Append

Write-Output 'Creating Credential Object for Administrator'
$Pass = ConvertTo-SecureString $Password -AsPlainText -Force
$Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList ("$DomainNetBIOSName\$Username", $Pass)

$WAPScriptBlock = {

    Write-Output 'Importing certificate'
    Try {
        Import-PfxCertificate –FilePath "\\ADFS1.$Using:DomainDNSName\cert\adfs.pfx" -CertStoreLocation cert:\localMachine\my -Password $Using:Pass -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to import certificate $_"
        $_ | Write-AWSQuickStartException
        Exit 1
    }

    Write-Output 'Getting certificate information'
    Try {
        $ADFScertificate = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq "CN=*.$Using:DomainDNSName" } -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get certificate information $_"
        $_ | Write-AWSQuickStartException
        Exit 1
    }

    $CertificateThumbprint = $ADFScertificate | Select-Object -ExpandProperty 'Thumbprint'

    Write-Output 'Installing Web App binaries'
    Try {
        Install-WindowsFeature -Name 'Web-Application-Proxy' -IncludeManagementTools -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to install Web App binaries $_"
        $_ | Write-AWSQuickStartException
        Exit 1
    }

    Write-Output 'Checking if STS DNS record is present'
    $Counter = 0
    Do {
        $StsRecordPresent = Resolve-DnsName -Name "sts.$Using:DomainDNSName" -DnsOnly -ErrorAction SilentlyContinue
        If (-not $StsRecordPresent) {
            $Counter ++
            Write-Output "Unable to resolve sts.$Using:DomainDNSName. Waiting for 10 seconds before retrying."
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($StsRecordPresent -or $Counter -eq 12)
    
    If ($Counter -ge 12) {
        Write-Output 'sts record never appeared'
        $_ | Write-AWSQuickStartException
        Exit 1
    }

    Write-Output 'Installing WAP'
    Try {
        Install-WebApplicationProxy –CertificateThumbprint $CertificateThumbprint -FederationServiceName "sts.$Using:DomainDNSName" -FederationServiceTrustCredential $Using:Credential
    } Catch [System.Exception] {
        Write-Output "Failed to install WAP $_"
        $_ | Write-AWSQuickStartException
        Exit 1
    }
}

Invoke-Command -Authentication 'Credssp' -Scriptblock $WAPScriptBlock -ComputerName $env:COMPUTERNAME -Credential $Credential