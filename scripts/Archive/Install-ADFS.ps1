param(
    [Parameter(Mandatory = $true)][string]$DomainDNSName,
    [Parameter(Mandatory = $true)][string]$DomainNetBIOSName,
    [Parameter(Mandatory = $true)][string]$Username,
    [Parameter(Mandatory = $true)][string]$Password,
    [Parameter(Mandatory = $false)][switch]$FirstServer
)

Start-Transcript -Path 'C:\cfn\log\Install-ADFS.ps1.txt' -Append

Write-Output 'Creating Credential Object for Administrator'
$Pass = ConvertTo-SecureString $Password -AsPlainText -Force
$Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList ("$DomainNetBIOSName\$Username", $Pass)

Write-Output 'Installing AD FS Binaries'
Try {
    Install-WindowsFeature -Name 'ADFS-Federation' -IncludeManagementTools -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to install AD FS Binaries $_"
    $_ | Write-AWSQuickStartException
    Exit 1
}

If ($FirstServer) {
    $FirstServerScriptBlock = {
        Function New-CertificateRequest {
            param (
                [Parameter(Mandatory=$true, HelpMessage = "Please enter the subject beginning with CN=")]
                [ValidatePattern("CN=")]
                [string]$subject,
                [Parameter(Mandatory=$false, HelpMessage = "Please enter the SAN domains as a comma separated list")]
                [array]$SANs,
                [Parameter(Mandatory=$false, HelpMessage = "Please enter the Online Certificate Authority")]
                [string]$OnlineCA,
                [Parameter(Mandatory=$false, HelpMessage = "Please enter the Certificate Template")]
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
            new-item -type 'file' $CertificateINI -force
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
            & certreq.exe -new $CertificateINI $CertificateREQ > $null
        
            ### Online certificate request and import
            if ($OnlineCA) {
                if (test-path $CertificateCER) {del $CertificateCER}
                if (test-path $CertificateRSP) {del $CertificateRSP}
                & certreq.exe -submit -attrib "CertificateTemplate:$CATemplate" -config $OnlineCA $CertificateREQ $CertificateCER > $null
                & certreq.exe -accept $CertificateCER > $null
            }
        }
        
        Function Sync-ADDomain {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
            $DCs = $domain.FindAllDiscoverableDomainControllers()
            foreach ($DC in $DCs) {
                foreach ($partition in $DC.Partitions) {
                    Write-Host "Forcing replication on $DC from all servers for partition $partition"
                    try {
                        $DC.SyncReplicaFromAllServers($partition, 'CrossSite')
                    } catch [System.Exception] {
                        Write-Host $_
                        $foreach.Reset()
                        continue
                    }
                }
            }
        }

        Write-Output 'Installing AD RSAT Tools'
        Try {
            Install-WindowsFeature -Name 'RSAT-AD-Tools', 'RSAT-DNS-Server' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to install AD RSAT Tools $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        Write-Output 'Importing AD PS Module'
        Try {
            Import-Module -Name 'ActiveDirectory' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to importing AD PS Module $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        Write-Output 'Importing AD Domain Info'
        Try {
            $Domain = Get-ADDomain -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get AD domain $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        $BaseDn = $Domain.DistinguishedName
        $FQDN = $Domain.DNSRoot

        Write-Output 'Getting CA Information'
        Try{
            $CA = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -LDAPFilter '(objectclass=pKIEnrollmentService)' -Properties 'dNSHostName' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get CA Information $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        If ($CA -eq $Null) {
            Write-Output "CA not present, please add and configure an Enterpise CA and try again $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        $CadNSHostName = $CA | Select-Object -ExpandProperty 'dNSHostName'
        $CaName = $CA | Select-Object -ExpandProperty 'Name'
        $CertificateAuthorities = "$CadNSHostName\$CaName"

        $CertificateADFSsubject = "*.$Using:DomainDNSName"
        $CertificateADFSsubjectCN = "CN=$CertificateADFSsubject"

        $newCertReqParams = @{
            subject = $CertificateADFSsubjectCN
        }

        $newCertReqParams.Add("OnlineCA",$CertificateAuthorities)

        Write-Output 'Requesting a new certificate'
        New-CertificateRequest @newCertReqParams

        Write-Output 'Getting certificate information'
        Try {
            $ADFScertificate = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq "CN=*.$Using:DomainDNSName" } -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get certificate information $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        If ($ADFScertificate -eq $Null) {
            Write-Output "Certificate not present, try again $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        Write-Output 'Exporting certificate'
        Try {
            Export-PfxCertificate -Cert $ADFScertificate -FilePath "C:\cert\adfs.pfx" -Password $Using:Pass -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to export certificate $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        Write-Output "Setting SPN on $Using:Username"
        & setspn.exe -s "host/sts.$Using:DomainDNSName" "$Using:Username" > $null

        $CertificateThumbprint = $ADFScertificate | Select-Object -ExpandProperty 'Thumbprint'

        Write-Output 'Installing ADFS farm'
        Try {
            Install-AdfsFarm -CertificateThumbprint $CertificateThumbprint -FederationServiceDisplayName 'ADFS' -FederationServiceName "sts.$Using:DomainDNSName" -ServiceAccountCredential $Using:Credential -OverwriteConfiguration
        } Catch [System.Exception] {
            Write-Output "Failed to install ADFS farm $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        Write-Output 'Getting IP address'
        Try{
            $netip = Get-NetIPConfiguration -ErrorAction Stop | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IpAddress'
        } Catch [System.Exception] {
            Write-Output "Failed to get IP address $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        Write-Output 'Getting DNS servers'
        Try {
            $dnsServers = Resolve-DnsName $Using:DomainDNSName -Type 'NS' -ErrorAction Stop | Select-Object -ExpandProperty 'Namehost'
        } Catch [System.Exception] {
            Write-Output "Failed to get DNS servers $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        Write-Output 'Creating STS DNS record'
        foreach ($dnsServer in $dnsServers) {
            $Counter = 0
            do {
                $ARecordPresent = Resolve-DnsName -Name "$sts.$FQDN" -DnsOnly -Server $dnsServer -ErrorAction SilentlyContinue
                If (-not $ARecordPresent) {
                    $Counter ++
                    Write-Output 'STS record missing, creating it.'
                    Add-DnsServerResourceRecordA -Name 'sts' -ZoneName $Using:DomainDNSName -IPv4Address $netip -Computername $dnsServer -ErrorAction SilentlyContinue
                    If ($Counter -gt '1') {
                        Start-Sleep -Seconds 10
                    }
                }
            } Until ($ARecordPresent -or $Counter -eq 12)
            
            If ($Counter -ge 12) {
                Write-Output 'STS record never created'
                $_ | Write-AWSQuickStartException
                Exit 1
            }
        }

        Sync-ADDomain -ErrorAction Continue
    }
    Invoke-Command -Authentication 'Credssp' -Scriptblock $FirstServerScriptBlock -ComputerName $env:COMPUTERNAME -Credential $Credential
} else {
    $ServerScriptBlock = {
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

        Write-Output "Setting SPN on $Using:Username"
        & setspn.exe -s "host/sts.$Using:DomainDNSName" "$Using:Username" > $null

        Write-Output 'Checking if ADFS1 DNS record is present'
        $Counter = 0
        Do {
            $ADFS1RecordPresent = Resolve-DnsName -Name "adfs1.$Using:DomainDNSName" -DnsOnly -ErrorAction SilentlyContinue
            If (-not $ADFS1RecordPresent) {
                $Counter ++
                Write-Output "Unable to resolve adfs1.$Using:DomainDNSName. Waiting for 10 seconds before retrying."
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($ADFS1RecordPresent -or $Counter -eq 12)
        
        If ($Counter -ge 12) {
            Write-Output 'ADFS1 record never created'
            $_ | Write-AWSQuickStartException
            Exit 1
        }

        Write-Output 'Adding server to ADFS farm'
        Try {
            Add-AdfsFarmNode -CertificateThumbprint $CertificateThumbprint -ServiceAccountCredential $Using:Credential -PrimaryComputerName "adfs1.$Using:DomainDNSName" -PrimaryComputerPort '80' -OverwriteConfiguration -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to add server to ADFS farm $_"
            $_ | Write-AWSQuickStartException
            Exit 1
        }
    }

    Invoke-Command -Authentication 'Credssp' -Scriptblock $ServerScriptBlock -ComputerName $env:COMPUTERNAME -Credential $Credential
}