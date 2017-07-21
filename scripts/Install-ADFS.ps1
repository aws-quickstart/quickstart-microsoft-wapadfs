param(
    [string]
    $DomainDNSName = "example.com",

    [string]
    $DomainNetBIOSName = "example",

    [string]
    $Username,

    [string]
    $Password,

    [switch]
    $FirstServer
)

try {
    Start-Transcript -Path C:\cfn\log\Install-ADFS.ps1.txt -Append

    $ErrorActionPreference = "Stop"

    $Pass = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList "$DomainNetBIOSName\$Username", $Pass

    if($FirstServer) {
        $FirstServerScriptBlock = {
            $ErrorActionPreference = "Stop"

            function New-CertificateRequest {
                param (
                    [Parameter(Mandatory=$true, HelpMessage = "Please enter the subject beginning with CN=")]
                    [ValidatePattern("CN=")]
                    [string]$subject,
                    [Parameter(Mandatory=$false, HelpMessage = "Please enter the SAN domains as a comma separated list")]
                    [array]$SANs,
                    [Parameter(Mandatory=$false, HelpMessage = "Please enter the Online Certificate Authority")]
                    [string]$OnlineCA,
                    [Parameter(Mandatory=$false, HelpMessage = "Please enter the Online Certificate Authority")]
                    [string]$CATemplate = "WebServer"
                )

                ### Preparation
                $subjectDomain = $subject.split(',')[0].split('=')[1]
                if ($subjectDomain -match "\*.") {
                    $subjectDomain = $subjectDomain -replace "\*", "star"
                }
                $CertificateINI = "$subjectDomain.ini"
                $CertificateREQ = "$subjectDomain.req"
                $CertificateRSP = "$subjectDomain.rsp"
                $CertificateCER = "$subjectDomain.cer"

                ### INI file generation
                new-item -type file $CertificateINI -force
                add-content $CertificateINI '[Version]'
                add-content $CertificateINI 'Signature="$Windows NT$"'
                add-content $CertificateINI ''
                add-content $CertificateINI '[NewRequest]'
                $temp = 'Subject="' + $subject + '"'
                add-content $CertificateINI $temp
                add-content $CertificateINI 'Exportable=TRUE'
                add-content $CertificateINI 'KeyLength=2048'
                add-content $CertificateINI 'KeySpec=1'
                add-content $CertificateINI 'KeyUsage=0xA0'
                add-content $CertificateINI 'MachineKeySet=True'
                add-content $CertificateINI 'ProviderName="Microsoft RSA SChannel Cryptographic Provider"'
                add-content $CertificateINI 'ProviderType=12'
                add-content $CertificateINI 'SMIME=FALSE'
                if ($OnlineCA) {
                    add-content $CertificateINI 'RequestType=PKCS10'
                } else {
                    add-content $CertificateINI 'RequestType=Cert'
                }
                add-content $CertificateINI '[Strings]'
                add-content $CertificateINI 'szOID_ENHANCED_KEY_USAGE = "2.5.29.37"'
                add-content $CertificateINI 'szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"'
                add-content $CertificateINI 'szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"'
                if ($SANs) {
                    add-content $CertificateINI 'szOID_SUBJECT_ALT_NAME2 = "2.5.29.17"'
                    add-content $CertificateINI '[Extensions]'
                    add-content $CertificateINI '2.5.29.17 = "{text}"'

                    foreach ($SAN in $SANs) {
                        $temp = '_continue_ = "dns=' + $SAN + '&"'
                        add-content $CertificateINI $temp
                    }
                }

                ### Certificate request generation
                if (test-path $CertificateREQ) {del $CertificateREQ}
                certreq -new $CertificateINI $CertificateREQ

                ### Online certificate request and import
                if ($OnlineCA) {
                    if (test-path $CertificateCER) {del $CertificateCER}
                    if (test-path $CertificateRSP) {del $CertificateRSP}
                    certreq -submit -attrib "CertificateTemplate:$CATemplate" -config $OnlineCA $CertificateREQ $CertificateCER
                    certreq -accept $CertificateCER
                }
            }

            function Get-CAs {
                [CmdletBinding()]
                param()
                # Dump forest CAs from certutil
                $certutilDump = & certutil.exe -dump -silent
                # Initialize array and entry
                $CAs = @()
                $entry = $null
                # Iterate through dump
                foreach ($line in $certutilDump) {
                    if ($line -match '^Entry \d+:') {
                        # Save off previous CA entry and create new object
                        if ($entry) { $CAs += $entry }
                        Write-Host $line
                        $entry = New-Object -TypeName PSObject
                    }
                    if ($line -match "  (?<variable>[\w\s]+):\s+``(?<value>.*)'") {
                        # Populate CA entry
                        $entry | Add-Member -MemberType NoteProperty -Name $matches.variable -Value $matches.value -Force
                    }
                }
                # Save final CA entry
                if ($entry) { $CAs += $entry }
                # Return array of CAs
                return $CAs
            }

            function Get-ADDCs {
                [CmdletBinding()]
                param()
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
                return @($domain.FindAllDiscoverableDomainControllers())
            }

            function Sync-ADDomain {
                [CmdletBinding()]
                param()
                $DCs = Get-ADDCs
                foreach ($DC in $DCs) {
                    foreach ($partition in $DC.Partitions) {
                        Write-Host "Forcing replication on $DC from all servers for partition $partition"
                        try {
                            $DC.SyncReplicaFromAllServers($partition, 'CrossSite')
                        }
                        catch {
                            Write-Host $_
                            $foreach.Reset()
                            continue
                        }
                    }
                }
            }

            $CertificateAuthorities = Get-CAs
            $CertificateADFSsubject = "*.$Using:DomainDNSName"
            $CertificateADFSsubjectCN = "CN=$CertificateADFSsubject"

            $newCertReqParams = @{
                subject = $CertificateADFSsubjectCN
            }
            if ($CertificateAuthorities[0].Config) {
                $newCertReqParams.Add("OnlineCA",$CertificateAuthorities[0].Config)
            }
            New-CertificateRequest @newCertReqParams
            $ADFScertificate = (dir Cert:\LocalMachine\My)[0]
            Export-PfxCertificate -Cert $ADFScertificate -FilePath "C:\cert\adfs.pfx" -Password $Using:Pass

            & setspn -s host/sts.$Using:DomainDNSName $Using:DomainNetBIOSName\$Using:Username

            Install-WindowsFeature ADFS-Federation -IncludeManagementTools
            $CertificateThumbprint = (dir Cert:\LocalMachine\My)[0].thumbprint
            Install-AdfsFarm -CertificateThumbprint $CertificateThumbprint -FederationServiceDisplayName ADFS -FederationServiceName "sts.$Using:DomainDNSName" -ServiceAccountCredential $Using:Credential -OverwriteConfiguration

            Install-WindowsFeature RSAT-DNS-Server
            $netip = Get-NetIPConfiguration
            $ipconfig = Get-NetIPAddress | ?{$_.IpAddress -eq $netip.IPv4Address.IpAddress}
            $dnsServers = @((Resolve-DnsName $Using:DomainDNSName -Type NS).NameHost)
            foreach ($dnsServer in $dnsServers) {
                $recordCreated = $false
                do {
                    try {
                        Add-DnsServerResourceRecordA -Name sts -ZoneName $Using:DomainDNSName -IPv4Address $ipconfig.IPAddress -Computername $dnsServer
                        Write-Host "DNS record created on DNS server $dnsServer"
                        $recordCreated = $true
                    }
                    catch {
                        Write-Host "Unable to create DNS record on DNS server $dnsServer. Retrying in 5 seconds."
                        Start-Sleep -Seconds 5
                    }
                } while (-not $recordCreated)
            }

            Sync-ADDomain -ErrorAction Continue
        }
        Invoke-Command -Authentication Credssp -Scriptblock $FirstServerScriptBlock -ComputerName $env:COMPUTERNAME -Credential $Credential
    }
    else {
        $ServerScriptBlock = {
            $ErrorActionPreference = "Stop"

            Import-PfxCertificate –FilePath "\\ADFS1\cert\adfs.pfx" -CertStoreLocation cert:\localMachine\my -Password $Using:Pass
            $CertificateThumbprint = (dir Cert:\LocalMachine\My)[0].thumbprint

            & setspn -s host/sts.$Using:DomainDNSName $Using:DomainNetBIOSName\$Using:Username

            while (-not (Resolve-DnsName -Name "adfs1.$Using:DomainDNSName" -ErrorAction SilentlyContinue)) { Write-Host "Unable to resolve adfs1.$Using:DomainDNSName. Waiting for 5 seconds before retrying."; Start-Sleep 5 }

            Install-WindowsFeature ADFS-Federation -IncludeManagementTools
            Add-AdfsFarmNode -CertificateThumbprint $CertificateThumbprint -ServiceAccountCredential $Using:Credential -PrimaryComputerName "adfs1.$Using:DomainDNSName" -PrimaryComputerPort 80 -OverwriteConfiguration
        }
        Invoke-Command -Authentication Credssp -Scriptblock $ServerScriptBlock -ComputerName $env:COMPUTERNAME -Credential $Credential
    }
}
catch {
    Write-Verbose "$($_.exception.message)@ $(Get-Date)"
    $_ | Write-AWSQuickStartException
}