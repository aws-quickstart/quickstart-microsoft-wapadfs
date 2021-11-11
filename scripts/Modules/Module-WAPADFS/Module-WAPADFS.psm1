Function Invoke-PreConfig {
    #==================================================
    # Main
    #==================================================
    Write-Output 'Temporarily disabling Windows Firewall'
    Try {
        Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled False -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to disable Windows Firewall $_"
        Exit 1
    }
    
    Write-Output 'Creating file directory for DSC public certificate'
    Try {
        $Null = New-Item -Path 'C:\AWSQuickstart\publickeys' -ItemType 'Directory' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create file directory for DSC public certificate $_"
        Exit 1
    }
    
    Write-Output 'Creating certificate to encrypt credentials in MOF file'
    Try {
        $cert = New-SelfSignedCertificate -Type 'DocumentEncryptionCertLegacyCsp' -DnsName 'AWSQSDscEncryptCert' -HashAlgorithm 'SHA256' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create certificate to encrypt credentials in MOF file $_"
        Exit 1
    }
    
    Write-Output 'Exporting the self signed public key certificate'
    Try {
        $Null = $cert | Export-Certificate -FilePath 'C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy self signed certificate to publickeys directory $_"
        Exit 1
    }    
}

Function Invoke-LcmConfig {
    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting the DSC certificate thumbprint to secure the MOF file'
    Try {
        $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
    } Catch [System.Exception] {
        Write-Output "Failed to get DSC certificate thumbprint $_"
        Exit 1
    } 
    
    [DSCLocalConfigurationManager()]
    Configuration LCMConfig
    {
        Node 'localhost' {
            Settings {
                RefreshMode                    = 'Push'
                ConfigurationModeFrequencyMins = 15
                ActionAfterReboot              = 'StopConfiguration'                      
                RebootNodeIfNeeded             = $false
                ConfigurationMode              = 'ApplyAndAutoCorrect'
                CertificateId                  = $DscCertThumbprint  
            }
        }
    }
    
    Write-Output 'Generating MOF file for DSC LCM'
    LCMConfig -OutputPath 'C:\AWSQuickstart\LCMConfig'
        
    Write-Output 'Setting the DSC LCM configuration from the MOF generated in previous command'
    Try {
        Set-DscLocalConfigurationManager -Path 'C:\AWSQuickstart\LCMConfig' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set DSC LCM configuration $_"
        Exit 1
    } 
}

Function Get-EniConfig {
    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting network configuration'
    Try {
        $NetIpConfig = Get-NetIPConfiguration -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get network configuration $_"
        Exit 1
    }

    Write-Output 'Grabbing the current gateway address in order to static IP correctly'
    $GatewayAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4DefaultGateway' | Select-Object -ExpandProperty 'NextHop'

    Write-Output 'Formatting IP address in format needed for IPAdress DSC resource'
    $IpAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IpAddress'
    $Prefix = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'PrefixLength'
    $IpAddr = 'IP/CIDR' -replace 'IP', $IpAddress -replace 'CIDR', $Prefix

    Write-Output 'Getting MAC address'
    Try {
        $MacAddress = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'MacAddress'
    } Catch [System.Exception] {
        Write-Output "Failed to get MAC address $_"
        Exit 1
    }

    $Output = [PSCustomObject][Ordered]@{
        'GatewayAddress' = $GatewayAddress
        'IpAddress'      = $IpAddr
        'MacAddress'     = $MacAddress
    }
    Return $Output
}

Function Get-SecretInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][String]$DomainNetBIOSName,
        [Parameter(Mandatory = $True)][String]$SecretArn
    )

    #==================================================
    # Main
    #==================================================

    Write-Output "Getting $SecretArn Secret"
    Try {
        $SecretContent = Get-SECSecretValue -SecretId $SecretArn -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString' | ConvertFrom-Json -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get $SecretArn Secret $_"
        Exit 1
    }
       
    Write-Output 'Creating PSCredential object from Secret'
    $Username = $SecretContent.username
    $UserPassword = ConvertTo-SecureString ($SecretContent.password) -AsPlainText -Force
    $Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$DomainNetBIOSName\$Username", $UserPassword)

    $Output = [PSCustomObject][Ordered]@{
        'Credentials'  = $Credentials
        'Username'     = $Username
        'UserPassword' = $UserPassword
    }

    Return $Output
}

Function Invoke-DscStatusCheck {

    #==================================================
    # Main
    #==================================================

    $LCMState = Get-DscLocalConfigurationManager -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'LCMState'
    If ($LCMState -eq 'PendingConfiguration' -Or $LCMState -eq 'PendingReboot') {
        Exit 3010
    } Else {
        Write-Output 'DSC configuration completed'
    }
}

Function Set-DscConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][string]$DomainController1IP,
        [Parameter(Mandatory = $true)][string]$DomainController2IP,
        [Parameter(Mandatory = $true)][string]$DomainDNSName,
        [Parameter(Mandatory = $true)][string]$GatewayAddress,
        [Parameter(Mandatory = $true)][string]$InstanceNetBIOSName,
        [Parameter(Mandatory = $true)][string]$IpAddress,
        [Parameter(Mandatory = $true)][string]$MacAddress
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting the DSC encryption certificate thumbprint to secure the MOF file'
    Try {
        $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
    } Catch [System.Exception] {
        Write-Output "Failed to get DSC encryption certificate thumbprint $_"
        Exit 1
    }
    
    Write-Output 'Creating configuration data block that has the certificate information for DSC configuration processing'
    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName             = '*'
                CertificateFile      = 'C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer'
                Thumbprint           = $DscCertThumbprint
                PSDscAllowDomainUser = $true
            },
            @{
                NodeName = 'localhost'
            }
        )
    }
    
    Configuration ConfigInstance {
        param
        (
            [PSCredential] $Credentials
        )
        
        Import-DscResource -ModuleName 'PSDesiredStateConfiguration', 'NetworkingDsc', 'ComputerManagementDsc'
    
        Node LocalHost {
            NetAdapterName RenameNetAdapterPrimary {
                NewName    = 'Primary'
                MacAddress = $MacAddress
            }
            NetIPInterface DisableDhcp {
                Dhcp           = 'Disabled'
                InterfaceAlias = 'Primary'
                AddressFamily  = 'IPv4'
                DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
            }
            IPAddress SetIP {
                IPAddress      = $IpAddress
                InterfaceAlias = 'Primary'
                AddressFamily  = 'IPv4'
                DependsOn      = '[NetIPInterface]DisableDhcp'
            }
            DefaultGatewayAddress SetDefaultGateway {
                Address        = $GatewayAddress
                InterfaceAlias = 'Primary'
                AddressFamily  = 'IPv4'
                DependsOn      = '[IPAddress]SetIP'
            }
            DnsServerAddress DnsServerAddress {
                Address        = $DomainController1IP, $DomainController2IP
                InterfaceAlias = 'Primary'
                AddressFamily  = 'IPv4'
                DependsOn      = '[DefaultGatewayAddress]SetDefaultGateway'
            }
            DnsConnectionSuffix DnsConnectionSuffix {
                InterfaceAlias                 = 'Primary'
                ConnectionSpecificSuffix       = $DomainDNSName
                RegisterThisConnectionsAddress = $True
                UseSuffixWhenRegistering       = $False
            }
            WindowsFeature RSAT-DNS-Tools {
                Ensure = 'Present'
                Name   = 'RSAT-DNS-Server'
            }
            WindowsFeature RSAT-AD-Tools {
                Ensure = 'Present'
                Name   = 'RSAT-AD-Tools'
            }
            WindowsFeature RSAT-ADDS {
                Ensure = 'Present'
                Name   = 'RSAT-ADDS'
            }
            WindowsFeature RSAT-ADCS {
                Ensure = 'Present'
                Name   = 'RSAT-ADCS'
            }
            WindowsFeature RSAT-ADCS-Mgmt {
                Ensure = 'Present'
                Name   = 'RSAT-ADCS-Mgmt'
            }
            Computer JoinDomain {
                Name       = $InstanceNetBIOSName
                DomainName = $DomainDNSName
                Credential = $Credentials
                DependsOn  = '[WindowsFeature]RSAT-ADDS'
            }
        }
    }
    
    Write-Output 'Generating MOF file'
    ConfigInstance -OutputPath 'C:\AWSQuickstart\ConfigInstance' -Credentials $Credentials -ConfigurationData $ConfigurationData
}

Function Set-CredSSP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Enable', 'Disable')][string]$Action
    )

    #==================================================
    # Variables
    #==================================================

    $RootKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows'
    $CredDelKey = 'CredentialsDelegation'
    $FreshCredKey = 'AllowFreshCredentials'
    $FreshCredKeyNTLM = 'AllowFreshCredentialsWhenNTLMOnly'

    #==================================================
    # Main
    #==================================================

    Switch ($Action) {
        'Enable' {
            Write-Output 'Enabling CredSSP'
            Try {
                $Null = Enable-WSManCredSSP -Role 'Client' -DelegateComputer '*' -Force -ErrorAction Stop
                $Null = Enable-WSManCredSSP -Role 'Server' -Force -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to enable CredSSP $_"
                $Null = Disable-WSManCredSSP -Role 'Client' -ErrorAction SilentlyContinue
                $Null = Disable-WSManCredSSP -Role 'Server' -ErrorAction SilentlyContinue
                Exit 1
            }
       
            Write-Output 'Setting CredSSP registry entries'
            $CredDelKeyPresent = Test-Path -Path (Join-Path -Path $RootKey -ChildPath $CredDelKey) -ErrorAction SilentlyContinue
            If (-not $CredDelKeyPresent) {
                Try {
                    $CredDelPath = New-Item -Path $RootKey -Name $CredDelKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'

                    $FreshCredKeyPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKey) -ErrorAction SilentlyContinue
                    If (-not $FreshCredKeyPresent) {
                        $FreshCredKeyPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                    }

                    $FreshCredKeyNTLMPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKeyNTLM) -ErrorAction SilentlyContinue
                    If (-not $FreshCredKeyNTLMPresent) {
                        $FreshCredKeyNTLMPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKeyNTLM -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                    }

                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentials' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFresh' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentialsWhenNTLMOnly' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$FreshCredKeyPath" -Name '1' -Value 'WSMAN/*' -PropertyType 'String' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$FreshCredKeyNTLMPath" -Name '1' -Value 'WSMAN/*' -PropertyType 'String' -Force -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-Output "Failed to create CredSSP registry entries $_"
                    Remove-Item -Path (Join-Path -Path $RootKey -ChildPath $CredDelKey) -Force -Recurse
                    Exit 1
                }
            }
        }
        'Disable' {
            Write-Output 'Disabling CredSSP'
            Try {
                Disable-WSManCredSSP -Role 'Client' -ErrorAction Continue
                Disable-WSManCredSSP -Role 'Server' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to disable CredSSP $_"
                Exit 1
            }

            Write-Output 'Removing CredSSP registry entries'
            Try {
                Remove-Item -Path (Join-Path -Path $RootKey -ChildPath $CredDelKey) -Force -Recurse
            } Catch [System.Exception] {
                Write-Output "Failed to remove CredSSP registry entries $_"
                Exit 1
            }
        }
        Default { 
            Write-Output 'InvalidArgument: Invalid value is passed for parameter Action' 
            Exit 1
        }
    }
}

Function New-TemplateOID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$ConfigNC
    )

    #==================================================
    # Variables
    #==================================================

    $Hex = '0123456789ABCDEF'

    #==================================================
    # Main
    #==================================================

    Do {
        [string]$RandomHex = $null
        For ($i = 1; $i -le 32; $i++) {
            $RandomHex += $Hex.Substring((Get-Random -Minimum 0 -Maximum 16), 1)
        }

        $OID_Part_1 = Get-Random -Minimum 1000000 -Maximum 99999999
        $OID_Part_2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $OID_Part_3 = $RandomHex
        $OID_Forest = Get-ADObject -Server $Server -Identity "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" -Properties msPKI-Cert-Template-OID | Select-Object -ExpandProperty msPKI-Cert-Template-OID -ErrorAction SilentlyContinue
        $msPKICertTemplateOID = "$OID_Forest.$OID_Part_1.$OID_Part_2"
        $Name = "$OID_Part_2.$OID_Part_3"
        $Search = Get-ADObject -Server $Server -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" -Filter { cn -eq $Name -and msPKI-Cert-Template-OID -eq $msPKICertTemplateOID } -ErrorAction SilentlyContinue
        If ($Search) { 
            $Unique = 'False'
        } Else { 
            $Unique = 'True'
        }
    } Until ($Unique = 'True')
    Return @{
        TemplateOID  = $msPKICertTemplateOID
        TemplateName = $Name
    }
}

Function New-AdfsCertTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BaseDn,
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Server
    )

    #==================================================
    # Main
    #==================================================

    $OID = New-TemplateOID -Server $Server -ConfigNC "CN=Configuration,$BaseDn"

    $TemplateOIDPath = "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn"
    $OidOtherAttributes = @{
        'DisplayName'             = 'ADFS-QS'
        'flags'                   = [System.Int32]'1'
        'msPKI-Cert-Template-OID' = $OID.TemplateOID
    }

    $OtherAttributes = @{
        'flags'                                = [System.Int32]'131649'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Name-Flag'          = [System.Int32]'1'
        'msPKI-Enrollment-Flag'                = [System.Int32]'8'
        'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
        'msPKI-Private-Key-Flag'               = [System.Int32]'101056768'
        'msPKI-Template-Minor-Revision'        = [System.Int32]'2'
        'msPKI-Template-Schema-Version'        = [System.Int32]'4'
        'msPKI-RA-Signature'                   = [System.Int32]'0'
        'pKIMaxIssuingDepth'                   = [System.Int32]'0'
        'ObjectClass'                          = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
        'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft RSA SChannel Cryptographic Provider', '2,Microsoft DH SChannel Cryptographic Provider')
        'pKIDefaultKeySpec'                    = [System.Int32]'1'
        'pKIExpirationPeriod'                  = [System.Byte[]]@('0', '128', '114', '14', '93', '194', '253', '255')
        'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1')
        'pKIKeyUsage'                          = [System.Byte[]]@('160', '0')
        'pKIOverlapPeriod'                     = [System.Byte[]]@('0', '128', '166', '10', '255', '222', '255', '255')
        'revision'                             = [System.Int32]'100'
        'msPKI-Cert-Template-OID'              = $OID.TemplateOID
    }

    Try {
        New-ADObject -Path $TemplateOIDPath -OtherAttributes $OidOtherAttributes -Name $OID.TemplateName -Type 'msPKI-Enterprise-Oid' -Server $Server -Credential $Credential -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create new ADFS-QS certificate template OID $_"
        Exit 1
    }

    $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn"

    Try {
        New-ADObject -Path $TemplatePath -OtherAttributes $OtherAttributes -Name 'ADFS-QS' -DisplayName 'ADFS-QS' -Type 'pKICertificateTemplate' -Server $Server -Credential $Credential -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create new ADFS-QS certificate template $_"
        Exit 1
    }
}

Function Add-AdfsCertTemplateAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$IdentityReference,
        [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights]$ActiveDirectoryRights,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.AccessControlType]$AccessControlType,
        [Parameter(Mandatory = $false)][Guid]$ObjectGuid,        
        [Parameter(Mandatory = $false)][System.DirectoryServices.ActiveDirectorySecurityInheritance]$ActiveDirectorySecurityInheritance,
        [Parameter(Mandatory = $false)][Guid]$InheritedObjectGuid
    )

    #==================================================
    # Main
    #==================================================

    Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
        Import-Module -Name 'ActiveDirectory' -Force

        [Security.Principal.SecurityIdentifier]$IdentityReference = $Using:IdentityReference | Select-Object -ExpandProperty 'Value'

        $ArgumentList = $IdentityReference, $Using:ActiveDirectoryRights, $Using:AccessControlType, $Using:ObjectGuid, $Using:ActiveDirectorySecurityInheritance, $Using:InheritedObjectGuid
        $ArgumentList = $ArgumentList.Where( { $_ -ne $Null })

        Try {
            $Rule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ArgumentList -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create ACL object $_"
            Exit 1
        }

        Try {
            $ObjectAcl = Get-Acl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get ACL for $Using:Path $_"
            Exit 1
        }

        $ObjectAcl.AddAccessRule($Rule) 

        Try {
            Set-Acl -AclObject $ObjectAcl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set ACL for $Using:Path $_"
            Exit 1
        }
    }
}

Function Set-AdfsCertTemplateAclInheritance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Path
    )

    #==================================================
    # Main
    #==================================================

    Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
        Import-Module -Name 'ActiveDirectory' -Force

        Try {
            $ObjectAcl = Get-Acl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get ACL for $Using:Path $_"
            Exit 1
        }

        $ObjectAcl.SetAccessRuleProtection($true, $false)

        Try {
            Set-Acl -AclObject $ObjectAcl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set ACL inheritance for $Using:Path $_"
            Exit 1
        }
    }
}

Function Remove-AdfsCertTemplateAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$IdentityReference,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.AccessControlType]$AccessControlType
    )

    #==================================================
    # Main
    #==================================================

    Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
        Import-Module -Name 'ActiveDirectory' -Force

        Try {
            $ObjectAcl = Get-Acl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get ACL for $Using:Path $_"
            Exit 1
        }

        [Security.Principal.SecurityIdentifier]$IdentityReference = $Using:IdentityReference | Select-Object -ExpandProperty 'Value'

        $ObjectAcl.RemoveAccess($IdentityReference, $Using:AccessControlType)

        Try {
            Set-Acl -AclObject $ObjectAcl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set ACL for $Using:Path $_"
            Exit 1
        }
    }
}

Function New-CertificateRequest {
    param (
        [Parameter(Mandatory = $true)][string]$DNSRoot,
        [Parameter(Mandatory = $true)][string]$OnlineCA,
        [Parameter(Mandatory = $true)][ValidatePattern("CN=")][string]$Subject,
        [Parameter(Mandatory = $true)][string]$TemplateName
    )

    #==================================================
    # Variables
    #==================================================

    $CertificateINI = "ADFS.ini"
    $CertificateREQ = "ADFS.req"
    $CertificateRSP = "ADFS.rsp"
    $CertificateCER = "ADFS.cer"

    $San1 = ('_continue_ = "dns=sts.FQDN&"').Replace("FQDN", $DNSRoot)
    $San2 = ('_continue_ = "dns=certauth.sts.FQDN&"').Replace("FQDN", $DNSRoot)
    $Ini = @(
        '[Version]',
        'Signature = "$Windows NT$"',
        '[NewRequest]',
        "Subject = $Subject",
        'Exportable = TRUE',
        'KeyLength = 2048',
        'KeySpec = 1',
        'KeyUsage = 0xa0',
        'MachineKeySet = True',
        'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"',
        'ProviderType = 12',
        'Silent = True',
        'SMIME = False',
        'RequestType = PKCS10'
        '[Strings]'
        'szOID_SUBJECT_ALT_NAME2 = "2.5.29.17"'
        '[Extensions]'
        '2.5.29.17 = "{text}"'
        $San1
        $San2
    )

    #==================================================
    # Main
    #==================================================

    $Ini | Out-File -FilePath $CertificateINI -Encoding 'ascii'

    If (Test-Path $CertificateREQ) { Remove-Item $CertificateREQ }
    & certreq.exe -new $CertificateINI $CertificateREQ > $null

    If (Test-Path $CertificateCER) { Remove-Item $CertificateCER }
    If (Test-Path $CertificateRSP) { Remove-Item $CertificateRSP }
    & certreq.exe -submit -attrib "CertificateTemplate:$TemplateName" -config $OnlineCA $CertificateREQ $CertificateCER > $null
    & certreq.exe -accept $CertificateCER > $null

    Start-Sleep -Seconds 15

    $IssuedCert = Get-ChildItem -Path 'cert:\LocalMachine\My' | Where-Object { $_.Subject -eq $Subject }
    If ($Null -eq $IssuedCert) {
        Write-Output 'Certifcate was not issued, please check CA for failure reason'
        Exit 1
    } Else {
        Write-Output 'Cerificate succesfully issued'
    }
}

Function Invoke-AdfsServiceAccount {
    param (
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$CompName,
        [Parameter(Mandatory = $true)][string]$DC,
        [Parameter(Mandatory = $true)][string]$DirectoryType,
        [Parameter(Mandatory = $true)][string]$gMSAName,
        [Parameter(Mandatory = $true)][string]$GroupName
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Importing AD PS module'
    Try {
        Import-Module -Name 'ActiveDirectory' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to importing AD PS Module $_"
        Exit 1
    }

    If ($DirectoryType -eq 'SelfManaged') {
        $KdsPresent = Invoke-Command -ComputerName $DC -Credential $Credential -ScriptBlock { Get-KdsRootKey -ErrorAction SilentlyContinue }
        If (-not $KdsPresent) {
            Try {
                Write-Output 'Generate a new root key for the KdsSvc within Active Directory'
                Invoke-Command -ComputerName $DC -Credential $Credential -ScriptBlock { Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10)) -ErrorAction Stop }
            } Catch [System.Exception] {
                Write-Output "Error encountered when attempting to generate a new root key $_"
                Exit 1
            }
        } Elseif ($KdsPresent.EffectiveTime -ge (Get-Date)) {
            Write-Output 'KDS Key not effective yet try again once it is effective'
            Exit 1
        }
    }

    Write-Output 'Getting AD domain info'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get AD domain $_"
        Exit 1
    }

    $DNSRoot = $Domain.DNSRoot

    $GroupPresent = Get-ADGroup -Identity $GroupName -Credential $Credential -Server $DC -ErrorAction SilentlyContinue
    If (-not $GroupPresent) {
        Write-Output 'Creating group for gMSA retreival'
        Try {
            New-ADGroup -Name $GroupName -SamAccountName $GroupName -GroupCategory 'Security' -GroupScope 'DomainLocal' -DisplayName $GroupName -Description "Members of the group can use $gMSAName for services" -Credential $Credential -Server $DC -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get create group $GroupName $_"
            Exit 1
        }
        Write-Output 'Sleeping to ensure replication of group replication has completed'
        Start-Sleep -Seconds 60 
    }

    Write-Output "Adding $CompName to group $GroupName"
    Try {
        $ComputerAcct = Get-ADComputer -Identity $CompName -Server $DC -ErrorAction Stop | Select-Object -ExpandProperty 'DistinguishedName'
        Add-ADGroupMember -Identity $GroupName -Members $ComputerAcct -Credential $Credential -Server $DC -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to add $CompName to group $GroupName $_"
        Exit 1
    }

    Write-Output 'Sleeping to ensure replication of group of AD changes have completed'
    Start-Sleep -Seconds 60 

    & Klist.exe -li 0x3e7 purge >$Null
   
    $gMSAPresent = Get-ADServiceAccount -Identity $gMSAName -Credential $Credential -Server $DC -ErrorAction SilentlyContinue
    If (-not $gMSAPresent) {
        Write-Output 'Creating new gMSA'
        Try {
            New-ADServiceAccount -Name $gMSAName -DNSHostName "$gMSAName.$DNSRoot" -Enabled $True -ManagedPasswordIntervalInDays 30 -PrincipalsAllowedToRetrieveManagedPassword $GroupName -Credential $Credential -Server $DC -ErrorAction Stop 
        } Catch [System.Exception] {
            Write-Output "Failed to get create new gMSA $gMSAName $_"
            Exit 1
        }
    } Else {
        Try {
            Set-ADServiceAccount -Identity $gMSAName -PrincipalsAllowedToRetrieveManagedPassword $GroupName -Credential $Credential -Server $DC -ErrorAction Stop 
        } Catch [System.Exception] {
            Write-Output "Failed to set PrincipalsAllowedToRetrieveManagedPassword on gMSA $gMSAName $_"
            Exit 1
        }
    }
    
    $Counter = 0
    Do {
        Write-Output 'Attempting to install gMSA'
        $Installed = $True
        Try {
            Install-ADServiceAccount -Identity $gMSAName -Force -ErrorAction Stop 
        } Catch [System.Exception] {
            $Counter ++
            Start-Sleep -Seconds 10
            $Installed = $False
        }
    } Until ($Installed -eq $True -or $Counter -eq 24)

    If ($Counter -ge 24) {
        Write-Output 'gMSA never installed'
        Exit 1
    }
}

Function Install-FirstADFS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$DirectoryType,
        [Parameter(Mandatory = $true)][SecureString]$Password,
        [Parameter(Mandatory = $true)][string]$Username
    )

    #==================================================
    # Variables
    #==================================================

    $CompName = $env:COMPUTERNAME
    $gMSAGroupName = 'gMSA-ADFS-Principals-Allowed-To-Retrieve-Managed-Password'
    $gMSAName = 'gMSA-ADFS-QS'
    $Template = 'ADFS-QS'

    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting IP address'
    Try {
        $IP = Get-NetIPConfiguration -ErrorAction Stop | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IpAddress'
    } Catch [System.Exception] {
        Write-Output "Failed to get IP address $_"
        Exit 1
    }

    Write-Output 'Installing ADFS binaries'
    Try {
        $Null = Install-WindowsFeature -Name 'ADFS-Federation' -IncludeManagementTools -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to install ADFS binaries $_"
        Exit 1
    }

    Write-Output 'Importing AD PS module'
    Try {
        Import-Module -Name 'ActiveDirectory' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to importing AD PS module $_"
        Exit 1
    }

    Write-Output 'Getting AD domain information'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get AD domain information $_"
        Exit 1
    }

    $BaseDn = $Domain.DistinguishedName
    $DNSRoot = $Domain.DNSRoot
    $NetBiosName = $Domain.NetBIOSName

    Write-Output 'Getting a Domain Controller to perform actions against'
    Try {
        $DC = Get-ADDomainController -Discover -ForceDiscover -NextClosestSite -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
    } Catch [System.Exception] {
        Write-Output "Failed to get a Domain Controller $_"
        Exit 1
    }

    Write-Output "Adding $CompName to group $gMSAGroupName"
    Invoke-AdfsServiceAccount -Credential $Credential -CompName $CompName -DC $DC -DirectoryType $DirectoryType -gMSAName $gMSAName -GroupName $gMSAGroupName

    Write-Output 'Creating cert directory'
    $PathPresent = Test-Path -Path 'C:\cert' -ErrorAction SilentlyContinue
    If (-not $PathPresent) {
        Try {
            $Null = New-Item -Path 'C:\cert' -Type 'Directory' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create cert directory $_"
            Exit 1
        }
    } 

    Write-Output 'Sharing cert directory'
    $SharePresent = Get-SmbShare -Name 'cert' -ErrorAction SilentlyContinue
    If (-not $SharePresent) {
        Try {
            $Null = New-SmbShare -Name 'cert' -Path 'C:\cert' -FullAccess 'SYSTEM', "$NetBiosName\$Username", "$NetBiosName\Domain Admins" -ReadAccess "$NetBiosName\Domain Computers" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create cert SMB share $_"
            Exit 1
        }
    }

    Write-Output 'Getting CA information'
    Try {
        $CA = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -LDAPFilter '(objectclass=pKIEnrollmentService)' -Properties 'dNSHostName' -Server $DC -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get CA information $_"
        Exit 1
    }

    If ($Null -eq $CA) {
        Write-Output "CA not present, please add and configure an Enterpise CA and try again $_"
        Exit 1
    }

    $CadNSHostName = $CA | Select-Object -ExpandProperty 'dNSHostName'
    $CaName = $CA | Select-Object -ExpandProperty 'Name'

    Write-Output 'Enabling CredSSP'
    Set-CredSSP -Action 'Enable'

    Write-Output 'Creating STS DNS record'
    $Counter = 0
    Do {
        $ARecordPresent = Resolve-DnsName -Name "sts.$DNSRoot" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
        If (-not $ARecordPresent) {
            $Counter ++
            Write-Output 'STS record missing, attempting to create it.'
            Invoke-Command -Authentication 'Credssp' -ComputerName $CompName -Credential $Credential -ScriptBlock { Add-DnsServerResourceRecordA -Name 'sts' -ZoneName $Using:DNSRoot -IPv4Address $Using:IP -ComputerName $Using:DC -ErrorAction SilentlyContinue }
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($ARecordPresent -or $Counter -eq 12)

    If ($Counter -ge 12) {
        Write-Output 'STS record never created'
        Exit 1
    }

    Write-Output 'Creating ADFS certificate template'
    New-AdfsCertTemplate -BaseDn $BaseDn -Credential $Credential -Server $DC

    $SidsToAdd = @(
        (Get-ADComputer -Identity $CompName | Select-Object -ExpandProperty 'SID'),
        (Get-ADUser -Identity $Username | Select-Object -ExpandProperty 'SID')
    )

    $SidsToRemove = @(
        [Security.Principal.SecurityIdentifier]'S-1-5-18',
        (Get-ADGroup -Identity 'Domain Admins' | Select-Object -ExpandProperty 'SID')
    )

    Write-Output 'Cleaning up ACLs on ADFS certificate template'
    $ExtendedRightGuid = [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    Foreach ($SidToAdd in $SidsToAdd) {
        Add-AdfsCertTemplateAcl -Credential $Credential -Path "CN=ADFS-QS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -IdentityReference $SidToAdd -ActiveDirectoryRights 'GenericRead,GenericWrite,WriteDacl,WriteOwner,Delete' -AccessControlType 'Allow' -ActiveDirectorySecurityInheritance 'None'
        Add-AdfsCertTemplateAcl -Credential $Credential -Path "CN=ADFS-QS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -IdentityReference $SidToAdd -ActiveDirectoryRights 'ExtendedRight' -AccessControlType 'Allow' -ObjectGuid $ExtendedRightGuid -ActiveDirectorySecurityInheritance 'None'    
    }

    Set-AdfsCertTemplateAclInheritance -Credential $Credential -Path "CN=ADFS-QS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn"

    Foreach ($SidToRemove in $SidsToRemove) {
        Remove-AdfsCertTemplateAcl -Credential $Credential -Path "CN=ADFS-QS,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -IdentityReference $SidToRemove -AccessControlType 'Allow'
    }

    Write-Output "Publishing $Template template to allow enrollment"
    $Counter = 0
    Do {
        $TempPresent = $Null
        Try {
            $TempPresent = Invoke-Command -Authentication 'Credssp' -ComputerName $CompName -Credential $Credential -ScriptBlock { 
                Get-ADObject "CN=$Using:CaName,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$Using:BaseDn" -Partition "CN=Configuration,$Using:BaseDn" -Properties 'certificateTemplates' | Select-Object -ExpandProperty 'certificateTemplates' | Where-Object { $_ -contains $Using:Template }
            }
        } Catch [System.Exception] {
            Write-Output "$Template Template missing"
            $TempPresent = $Null
        }
        If (-not $TempPresent) {
            $Counter ++
            Write-Output "$Template Template missing adding it."
            Try {
                Invoke-Command -Authentication 'Credssp' -ComputerName $CompName -Credential $Credential -ScriptBlock {
                    Set-ADObject "CN=$Using:CaName,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$Using:BaseDn" -Partition "CN=Configuration,$Using:BaseDn" -Add @{ 'certificateTemplates' = $Using:Template } 
                }
            } Catch [System.Exception] {
                Write-Output "Failed to add publish $Template template $_"
            }
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($TempPresent -or $Counter -eq 12)

    Write-Output 'Sleeping to ensure replication of ADFS certifcate template and ACL changes'
    Start-Sleep -Seconds 60

    Write-Output 'Requesting a new certificate'
    Invoke-Command -Authentication 'Credssp' -ComputerName $CompName -Credential $Credential -ScriptBlock { 
        Import-Module -Name 'C:\AWSQuickstart\Module-WAPADFS\Module-WAPADFS.psm1' -Force 
        New-CertificateRequest -DNSRoot $Using:DNSRoot -OnlineCA "$Using:CadNSHostName\$Using:CaName" -Subject "CN=*.$Using:DNSRoot" -TemplateName $Using:Template 
    }

    Write-Output "Setting SPN on $gMSAName"
    Invoke-Command -Authentication 'Credssp' -ComputerName $CompName -Credential $Credential -ScriptBlock { & setspn.exe -s "host/sts.$Using:DNSRoot" "$Using:gMSAName" > $null }

    Write-Output 'Getting certificate information'
    Try {
        $ADFScertificate = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq "CN=*.$DNSRoot" } -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get certificate information $_"
        Exit 1
    }

    If ($Null -eq $ADFScertificate) {
        Write-Output "Certificate not present, try again $_"
        Exit 1
    }

    Write-Output 'Exporting certificate'
    Try {
        $Null = Export-PfxCertificate -Cert $ADFScertificate -FilePath "C:\cert\adfs.pfx" -Password $Password -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to export certificate $_"
        Exit 1
    }

    $CertificateThumbprint = $ADFScertificate | Select-Object -ExpandProperty 'Thumbprint'

    Switch ($DirectoryType) {
        'SelfManaged' {
            Write-Output 'Installing ADFS farm'
            Try {
                $Null = Install-AdfsFarm -CertificateThumbprint $CertificateThumbprint -Credential $Credential -DecryptionCertificateThumbprint $CertificateThumbprint -FederationServiceName "sts.$DNSRoot" -FederationServiceDisplayName 'ADFS' -GroupServiceAccountIdentifier "$NetBiosName\$gMSAName$" -SigningCertificateThumbprint $CertificateThumbprint -OverwriteConfiguration -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to install ADFS farm $_"
                Exit 1
            }
        }
        'AWSManaged' {
            Write-Output 'Creating ADFS containers'
            $ContainerPre = Get-ADObject -Identity "CN=ADFS,OU=$NetBiosName,$BaseDn" -Credential $Credential -Server $DC -ErrorAction SilentlyContinue
            If (-not $ContainerPre) {
                Try {
                    New-ADObject -Name 'ADFS' -Type 'Container' -Path "OU=$NetBiosName,$BaseDn" -Credential $Credential -Server $DC -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-Output "Failed to create ADFS container $_"
                    Exit 1
                }
            }
            Try {
                $Guid = New-Guid -ErrorAction Stop | Select-Object -ExpandProperty 'Guid'
                New-ADObject -Name $Guid -Type 'Container' -Path "CN=ADFS,OU=$NetBiosName,$BaseDn" -Credential $Credential -Server $DC -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to create GUID container $_"
                Exit 1
            }

            Write-Output 'Sleeping to ensure replication of ADFS container'
            Start-Sleep -Seconds 60
           
            $AdminConfig = @{ 'DKMContainerDn' = "CN=$Guid,CN=ADFS,OU=$NetBiosName,$BaseDn" }
            
            Write-Output 'Installing ADFS farm'
            Try {
                $Null = Install-AdfsFarm -CertificateThumbprint $CertificateThumbprint -Credential $Credential -DecryptionCertificateThumbprint $CertificateThumbprint -FederationServiceName "sts.$DNSRoot" -FederationServiceDisplayName 'ADFS' -GroupServiceAccountIdentifier "$NetBiosName\$gMSAName$" -SigningCertificateThumbprint $CertificateThumbprint -OverwriteConfiguration -AdminConfiguration $AdminConfig -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to install ADFS farm $_"
                Exit 1
            }
        }
    }

    Write-Output 'Disabling CredSSP'
    Set-CredSSP -Action 'Disable'
}

Function Install-AdditionalADFS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$DirectoryType,
        [Parameter(Mandatory = $true)][string]$FirstAdfsServerBIOSName,
        [Parameter(Mandatory = $true)][SecureString]$Password
    )

    #==================================================
    # Variables
    #==================================================

    $CompName = $env:COMPUTERNAME
    $gMSAGroupName = 'gMSA-ADFS-Principals-Allowed-To-Retrieve-Managed-Password'
    $gMSAName = 'gMSA-ADFS-QS'

    #==================================================
    # Main
    #==================================================

    Write-Output 'Importing AD PS Module'
    Try {
        Import-Module -Name 'ActiveDirectory' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to importing AD PS Module $_"
        Exit 1
    }

    Write-Output 'Getting AD domain information'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get AD domain information $_"
        Exit 1
    }

    Write-Output 'Getting a Domain Controller to perform actions against'
    Try {
        $DC = Get-ADDomainController -Discover -ForceDiscover -NextClosestSite -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
    } Catch [System.Exception] {
        Write-Output "Failed to get a Domain Controller $_"
        Exit 1
    }

    $DNSRoot = $Domain.DNSRoot
    $NetBiosName = $Domain.NetBIOSName

    Write-Output "Adding $CompName to group $gMSAGroupName"
    Invoke-AdfsServiceAccount -Credential $Credential -CompName $CompName -DC $DC -DirectoryType $DirectoryType -gMSAName $gMSAName -GroupName $gMSAGroupName

    Write-Output 'Installing ADFS binaries'
    Try {
        $Null = Install-WindowsFeature -Name 'ADFS-Federation' -IncludeManagementTools -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to install ADFS binaries $_"
        Exit 1
    }

    Write-Output 'Importing certificate'
    Try {
        $Null = Import-PfxCertificate -FilePath "\\$FirstAdfsServerBIOSName.$DNSRoot\cert\adfs.pfx" -CertStoreLocation cert:\localMachine\my -Password $Password -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to import certificate $_"
        Exit 1
    }

    Write-Output 'Getting certificate information'
    Try {
        $ADFScertificate = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq "CN=*.$DNSRoot" } -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get certificate information $_"
        Exit 1
    }

    $CertificateThumbprint = $ADFScertificate | Select-Object -ExpandProperty 'Thumbprint'

    Write-Output "Checking If $FirstAdfsServerBIOSName DNS record is present"
    $Counter = 0
    Do {
        $ADFS1RecordPresent = Resolve-DnsName -Name "$FirstAdfsServerBIOSName.$DNSRoot" -DnsOnly -ErrorAction SilentlyContinue
        If (-not $ADFS1RecordPresent) {
            $Counter ++
            Write-Output "Unable to resolve $FirstAdfsServerBIOSName.$DNSRoot. Waiting for 10 seconds before retrying."
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($ADFS1RecordPresent -or $Counter -eq 12)
    
    If ($Counter -ge 12) {
        Write-Output 'ADFS1 record never created'
        Exit 1
    }

    Write-Output 'Adding server to ADFS farm'
    Try {
        $Null = Add-AdfsFarmNode -CertificateThumbprint $CertificateThumbprint -GroupServiceAccountIdentifier "$NetBiosName\$gMSAName$" -PrimaryComputerName "$FirstAdfsServerBIOSName.$DNSRoot" -PrimaryComputerPort '80' -OverwriteConfiguration -Credential $Credential -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to add server to ADFS farm $_"
        Exit 1
    }
}

Function Install-WAP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$FirstAdfsServerBIOSName,
        [Parameter(Mandatory = $true)][SecureString]$Password
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Importing AD PS Module'
    Try {
        Import-Module -Name 'ActiveDirectory' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to importing AD PS Module $_"
        Exit 1
    }

    Write-Output 'Getting AD domain information'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get AD domain information $_"
        Exit 1
    }

    $DNSRoot = $Domain.DNSRoot

    Write-Output 'Importing certificate'
    Try {
        $Null = Import-PfxCertificate -FilePath "\\$FirstAdfsServerBIOSName.$DNSRoot\cert\adfs.pfx" -CertStoreLocation 'cert:\localMachine\my' -Password $Password -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to import certificate $_"
        Exit 1
    }

    Write-Output 'Getting certificate information'
    Try {
        $CertificateThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq "CN=*.$DNSRoot" } -ErrorAction Stop | Select-Object -ExpandProperty 'Thumbprint'
    } Catch [System.Exception] {
        Write-Output "Failed to get certificate information $_"
        Exit 1
    }

    Write-Output 'Installing Web App binaries'
    Try {
        $Null = Install-WindowsFeature -Name 'Web-Application-Proxy' -IncludeManagementTools -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to install Web App binaries $_"
        Exit 1
    }

    Write-Output 'Checking If STS DNS record is present'
    $Counter = 0
    Do {
        $StsRecordPresent = Resolve-DnsName -Name "sts.$DNSRoot" -DnsOnly -ErrorAction SilentlyContinue
        If (-not $StsRecordPresent) {
            $Counter ++
            Write-Output "Unable to resolve sts.$DNSRoot. Waiting for 10 seconds before retrying."
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($StsRecordPresent -or $Counter -eq 12)

    If ($Counter -ge 12) {
        Write-Output 'STS record never appeared'
        Exit 1
    }

    Write-Output 'Installing WAP'
    Try {
        $Null = Install-WebApplicationProxy -CertificateThumbprint $CertificateThumbprint -FederationServiceName "sts.$DNSRoot" -FederationServiceTrustCredential $Credential -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to install WAP $_"
        Exit 1
    }
}

Function Start-CleanUp {
    #==================================================
    # Main
    #==================================================

    Write-Output 'Re-enabling Windows Firewall'
    Try {
        Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled 'True' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to re-enable Windows Firewall $_"
    }  

    Write-Output 'Removing DSC configuration'
    Try {    
        Remove-DscConfigurationDocument -Stage 'Current' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to remove DSC configuration $_"
    }
    
    Write-Output 'Removing QuickStart build files'
    Try {
        Remove-Item -Path 'C:\AWSQuickstart' -Recurse -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed remove QuickStart build files $_"
    }
    
    Write-Output 'Removing self signed certificate'
    Try {
        $SelfSignedThumb = Get-ChildItem -Path 'cert:\LocalMachine\My\' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
        Remove-Item -Path "cert:\LocalMachine\My\$SelfSignedThumb" -DeleteKey
    } Catch [System.Exception] {
        Write-Output "Failed remove self signed certificate $_"
    }
}