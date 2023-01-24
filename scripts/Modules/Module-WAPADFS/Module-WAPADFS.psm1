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

Function Set-AuditDscConfiguration {

    #==================================================
    # Main
    #==================================================

    Configuration ConfigInstance {
        Import-DscResource -ModuleName 'AuditPolicyDsc'
        Node LocalHost {
            AuditPolicySubcategory CredentialValidationSuccess {
                Name      = 'Credential Validation'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory CredentialValidationFailure {
                Name      = 'Credential Validation'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory KerberosAuthenticationServiceSuccess {
                Name      = 'Kerberos Authentication Service'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KerberosAuthenticationServiceFailure {
                Name      = 'Kerberos Authentication Service'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KerberosServiceTicketOperationsSuccess {
                Name      = 'Kerberos Service Ticket Operations'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KerberosServiceTicketOperationsFailure {
                Name      = 'Kerberos Service Ticket Operations'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherAccountLogonEventsSuccess {
                Name      = 'Other Account Logon Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherAccountLogonEventsFailure {
                Name      = 'Other Account Logon Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGroupManagementSuccess {
                Name      = 'Application Group Management'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGroupManagementFailure {
                Name      = 'Application Group Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ComputerAccountManagementSuccess {
                Name      = 'Computer Account Management'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ComputerAccountManagementFailure {
                Name      = 'Computer Account Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DistributionGroupManagementSuccess {
                Name      = 'Distribution Group Management'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DistributionGroupManagementFailure {
                Name      = 'Distribution Group Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherAccountManagementEventsSuccess {
                Name      = 'Other Account Management Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherAccountManagementEventsFailure {
                Name      = 'Other Account Management Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SecurityGroupManagementSuccess {
                Name      = 'Security Group Management'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecurityGroupManagementFailure {
                Name      = 'Security Group Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory UserAccountManagementSuccess {
                Name      = 'User Account Management'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory UserAccountManagementFailure {
                Name      = 'User Account Management'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DPAPIActivitySuccess {
                Name      = 'DPAPI Activity'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DPAPIActivityFailure {
                Name      = 'DPAPI Activity'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory PNPActivitySuccess {
                Name      = 'Plug and Play Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory PNPActivityFailure {
                Name      = 'Plug and Play Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ProcessCreationSuccess {
                Name      = 'Process Creation'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory ProcessCreationFailure {
                Name      = 'Process Creation'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ProcessTerminationSuccess {
                Name      = 'Process Termination'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory ProcessTerminationFailure {
                Name      = 'Process Termination'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory RPCEventsSuccess {
                Name      = 'RPC Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory RPCEventsFailure {
                Name      = 'RPC Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory TokenRightAdjustedSuccess {
                Name      = 'Token Right Adjusted Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory TokenRightAdjustedFailure {
                Name      = 'Token Right Adjusted Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DetailedDirectoryServiceReplicationSuccess {
                Name      = 'Detailed Directory Service Replication'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DetailedDirectoryServiceReplicationFailure {
                Name      = 'Detailed Directory Service Replication'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceAccessSuccess {
                Name      = 'Directory Service Access'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceAccessFailure {
                Name      = 'Directory Service Access'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceChangesSuccess {
                Name      = 'Directory Service Changes'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceChangesFailure {
                Name      = 'Directory Service Changes'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceReplicationSuccess {
                Name      = 'Directory Service Replication'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceReplicationFailure {
                Name      = 'Directory Service Replication'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AccountLockoutSuccess {
                Name      = 'Account Lockout'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AccountLockoutFailure {
                Name      = 'Account Lockout'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory UserDeviceClaimsSuccess {
                Name      = 'User / Device Claims'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory UserDeviceClaimsFailure {
                Name      = 'User / Device Claims'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory GroupMembershipSuccess {
                Name      = 'Group Membership'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory GroupMembershipFailure {
                Name      = 'Group Membership'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory IPsecExtendedModeSuccess {
                Name      = 'IPsec Extended Mode'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecExtendedModeFailure {
                Name      = 'IPsec Extended Mode'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecMainModeSuccess {
                Name      = 'IPsec Main Mode'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecMainModeFailure {
                Name      = 'IPsec Main Mode'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecQuickModeSuccess {
                Name      = 'IPsec Quick Mode'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecQuickModeFailure {
                Name      = 'IPsec Quick Mode'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory LogoffSuccess {
                Name      = 'Logoff'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory Logoffailure {
                Name      = 'Logoff'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory LogonSuccess {
                Name      = 'Logon'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory LogonFailure {
                Name      = 'Logon'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory NetworkPolicyServerSuccess {
                Name      = 'Network Policy Server'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory NetworkPolicyServerFailure {
                Name      = 'Network Policy Server'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherLogonLogoffEventsSuccess {
                Name      = 'Other Logon/Logoff Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherLogonLogoffEventsFailure {
                Name      = 'Other Logon/Logoff Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SpecialLogonSuccess {
                Name      = 'Special Logon'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SpecialLogonFailure {
                Name      = 'Special Logon'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGeneratedSuccess {
                Name      = 'Application Generated'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGeneratedFailure {
                Name      = 'Application Generated'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory CertificationServicesSuccess {
                Name      = 'Certification Services'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory CertificationServicesFailure {
                Name      = 'Certification Services'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DetailedFileShareSuccess {
                Name      = 'Detailed File Share'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DetailedFileShareFailure {
                Name      = 'Detailed File Share'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileShareSuccess {
                Name      = 'File Share'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileShareFailure {
                Name      = 'File Share'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileSystemSuccess {
                Name      = 'File System'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileSystemFailure {
                Name      = 'File System'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FilteringPlatformConnectionSuccess {
                Name      = 'Filtering Platform Connection'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FilteringPlatformConnectionFailure {
                Name      = 'Filtering Platform Connection'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FilteringPlatformPacketDropSuccess {
                Name      = 'Filtering Platform Packet Drop'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory FilteringPlatformPacketDropFailure {
                Name      = 'Filtering Platform Packet Drop'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory HandleManipulationSuccess {
                Name      = 'Handle Manipulation'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory HandleManipulationFailure {
                Name      = 'Handle Manipulation'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KernelObjectSuccess {
                Name      = 'Kernel Object'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KernelObjectFailure {
                Name      = 'Kernel Object'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherObjectAccessEventsSuccess {
                Name      = 'Other Object Access Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherObjectAccessEventsFailure {
                Name      = 'Other Object Access Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RegistrySuccess {
                Name      = 'Registry'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RegistryFailure {
                Name      = 'Registry'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RemovableStorageSuccess {
                Name      = 'Removable Storage'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RemovableStorageFailure {
                Name      = 'Removable Storage'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory CentralAccessPolicyStagingSuccess {
                Name      = 'Central Policy Staging'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory CentralAccessPolicyStagingFailure {
                Name      = 'Central Policy Staging'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuditPolicyChangeSuccess {
                Name      = 'Audit Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuditPolicyChangeFailure {
                Name      = 'Audit Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AuthenticationPolicyChangeSuccess {
                Name      = 'Authentication Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuthenticationPolicyChangeFailure {
                Name      = 'Authentication Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AuthorizationPolicyChangeSuccess {
                Name      = 'Authorization Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuthorizationPolicyChangeFailure {
                Name      = 'Authorization Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory MPSSVCRule-LevelPolicyChangeSuccess {
                Name      = 'MPSSVC Rule-Level Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory MPSSVCRule-LevelPolicyChangeFailure {
                Name      = 'MPSSVC Rule-Level Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherPolicyChangeEventsSuccess {
                Name      = 'Other Policy Change Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherPolicyChangeEventsFailure {
                Name      = 'Other Policy Change Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory NonSensitivePrivilegeUseSuccess {
                Name      = 'Non Sensitive Privilege Use'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory NonSensitivePrivilegeUseFailure {
                Name      = 'Non Sensitive Privilege Use'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherPrivilegeUseEventsSuccess {
                Name      = 'Other Privilege Use Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherPrivilegeUseEventsFailure {
                Name      = 'Other Privilege Use Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SensitivePrivilegeUseSuccess {
                Name      = 'Sensitive Privilege Use'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SensitivePrivilegeUseFailure {
                Name      = 'Sensitive Privilege Use'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecDriverSuccess {
                Name      = 'IPsec Driver'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecDriverFailure {
                Name      = 'IPsec Driver'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherSystemEventsSuccess {
                Name      = 'Other System Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherSystemEventsFailure {
                Name      = 'Other System Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecurityStateChangeSuccess {
                Name      = 'Security State Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecurityStateChangeFailure {
                Name      = 'Security State Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SecuritySystemExtensionSuccess {
                Name      = 'Security System Extension'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecuritySystemExtensionFailure {
                Name      = 'Security System Extension'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SystemIntegritySuccess {
                Name      = 'System Integrity'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SystemIntegrityFailure {
                Name      = 'System Integrity'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
        }
    }
    Write-Output 'Generating MOF file'
    ConfigInstance -OutputPath 'C:\AWSQuickstart\AuditConfigInstance' -ConfigurationData $ConfigurationData
}

Function Set-LogsAndMetricsCollection {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('ADFS', 'WAP')][string]$Role,
        [Parameter(Mandatory = $true)][string]$Stackname
    )

    If ($ServerRole -eq 'ADFS') {
        $ADFSCategories = @(
            @{
                'Category' = 'AD FS'
                'Counters' = @(
                    @{
                        'Counter' = 'Token Request'
                        'Unit'    = 'Count'
                    },
                    @{
                        'Counter' = 'Token Request/sec'
                        'Unit'    = 'Count/Second'
                    },
                    @{
                        'Counter' = 'Federation Metadata Requests'
                        'Unit'    = 'Count'
                    },
                    @{
                        'Counter' = 'Federation Metadata Requests/sec'
                        'Unit'    = 'Count/Second'
                    },
                    @{
                        'Counter' = 'Artifact Resolution Requests'
                        'Unit'    = 'Count'
                    },
                    @{
                        'Counter' = 'Artifact Resolution Requests/sec'
                        'Unit'    = 'Count/Second'
                    }
                )
            }
        )

        $ADFSDcSources = @(
            @{
                'Id'         = 'ADFSAdminLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'AD FS/Admin'
            }
        )

        $ADFSDcSinks = @(
            @{
                'Id'             = 'ADFSAdminLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'ADFSAdminLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            }
        )

        $ADFSDcPipes = @(
            @{
                'Id'        = 'ADFSAdminLogToCloudWatch'
                'SourceRef' = 'ADFSAdminLog'
                'SinkRef'   = 'ADFSAdminLog-CloudWatchLogsSink'
            }
        )
    }

    If ($ServerRole -eq 'WAP') {
        $WAPCategories = @(
            @{
                'Category' = 'AD FS Proxy'
                'Counters' = @(
                    @{
                        'Counter' = 'Requests'
                        'Unit'    = 'Count'
                    },
                    @{
                        'Counter' = 'Requests/sec'
                        'Unit'    = 'Count/Second'
                    },
                    @{
                        'Counter' = 'Outstanding Requests'
                        'Unit'    = 'Count'
                    }
                )
            }
        )

        $WAPSources = @(
            @{
                'Id'         = 'ADFSAdminLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'AD FS/Admin'
            },
            @{
                'Id'         = 'WAPAdminLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'Microsoft-Windows-WebApplicationProxy/Admin'
            }
        )

        $WAPSinks = @(
            @{
                'Id'             = 'ADFSAdminLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'ADFSAdminLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            },
            @{
                'Id'             = 'WAPAdminLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'WAPAdminLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            }
        )

        $WAPPipes = @(
            @{
                'Id'        = 'ADFSAdminLogToCloudWatch'
                'SourceRef' = 'ADFSAdminLog'
                'SinkRef'   = 'ADFSAdminLog-CloudWatchLogsSink'
            },
            @{
                'Id'        = 'WAPAdminLogToCloudWatch'
                'SourceRef' = 'WAPAdminLog'
                'SinkRef'   = 'WAPAdminLog-CloudWatchLogsSink'
            }
        )
    }

    $KenesisAgentSettings = @{
        'Sources'    = @(
            @{
                'Id'         = 'PerformanceCounter'
                'SourceType' = 'WindowsPerformanceCounterSource'
                'Categories' = @(
                    @{
                        'Category'  = 'ENA Packets Shaping'
                        'Instances' = 'ENA #1'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Aggregate inbound BW allowance exceeded'
                                'Unit'    = 'Count'
                            },
                            @{
                                'Counter' = 'Aggregate outbound BW allowance exceeded'
                                'Unit'    = 'Count'
                            },
                            @{
                                'Counter' = 'Connection tracking allowance exceeded'
                                'Unit'    = 'Count'
                            },
                            @{
                                'Counter' = 'Link local packet rate allowance exceeded'
                                'Unit'    = 'Count'
                            },
                            @{
                                'Counter' = 'PPS allowance exceeded'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category'  = 'LogicalDisk'
                        'Instances' = 'D:'
                        'Counters'  = @(
                            @{
                                'Counter' = '% Free Space'
                                'Unit'    = 'Percent'
                            },
                            @{
                                'Counter' = 'Avg. Disk Queue Length'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category'  = 'LogicalDisk'
                        'Instances' = 'C:'
                        'Counters'  = @(
                            @{
                                'Counter' = '% Free Space'
                                'Unit'    = 'Percent'
                            },
                            @{
                                'Counter' = 'Avg. Disk Queue Length'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category' = 'Memory'
                        'Counters' = @(
                            @{
                                'Counter' = '% Committed Bytes in Use'
                                'Unit'    = 'Percent'
                            },
                            @{
                                'Counter' = 'Available MBytes'
                                'Unit'    = 'Megabytes'
                            },
                            @{
                                'Counter' = 'Long-Term Average Standby Cache Lifetime (s)'
                                'Unit'    = 'Seconds'
                            }
                        )
                    },
                    @{
                        'Category'  = 'Network Interface'
                        'Instances' = 'Amazon Elastic Network Adapter'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Bytes Received/sec'
                                'Unit'    = 'Count/Second'
                            },
                            @{
                                'Counter' = 'Bytes Sent/sec'
                                'Unit'    = 'Count/Second'
                            },
                            @{
                                'Counter' = 'Current Bandwidth'
                                'Unit'    = 'Bits/Second'
                            }
                        )
                    },
                    @{
                        'Category'  = 'PhysicalDisk'
                        'Instances' = '0 C:'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Avg. Disk Queue Length'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category'  = 'PhysicalDisk'
                        'Instances' = '1 D:'
                        'Counters'  = @(
                            @{
                                'Counter' = 'Avg. Disk Queue Length'
                                'Unit'    = 'Count'
                            }
                        )
                    },
                    @{
                        'Category'  = 'Processor'
                        'Instances' = '*'
                        'Counters'  = @(
                            @{
                                'Counter' = '% Processor Time'
                                'Unit'    = 'Percent'
                            }
                        )
                    }
                    $ADFSCategories
                    $WAPCategories
                )
            },
            @{
                'Id'         = 'ApplicationLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'Application'
            },
            @{
                'Id'         = 'SecurityLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'Security'
            },
            @{
                'Id'         = 'SystemLog'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'System'
            },
            @{
                'Id'         = 'AD FS/Admin'
                'SourceType' = 'WindowsEventLogSource'
                'LogName'    = 'Microsoft-Windows-DNSServer/Audit'
            }
            $ADFSSources
            $WAPSources
        )
        'Sinks'      = @(
            @{
                'Namespace' = "EC2-Domain-Member-Metrics-$Stackname"
                'Region'    = 'ReplaceMe'
                'Id'        = 'CloudWatchSink'
                'Interval'  = '60'
                'SinkType'  = 'CloudWatch'
            },
            @{
                'Id'             = 'ApplicationLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'ApplicationLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            },
            @{
                'Id'             = 'SecurityLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'SecurityLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            },
            @{
                'Id'             = 'SystemLog-CloudWatchLogsSink'
                'SinkType'       = 'CloudWatchLogs'
                'BufferInterval' = '60'
                'LogGroup'       = "{ComputerName}-$Stackname-Log-Group"
                'LogStream'      = 'SystemLog-Stream'
                'Region'         = 'ReplaceMe'
                'Format'         = 'json'
            }
            $ADFSSinks
            $WAPSinks
        )
        'Pipes'      = @(
            @{
                'Id'        = 'PerformanceCounterToCloudWatch'
                'SourceRef' = 'PerformanceCounter'
                'SinkRef'   = 'CloudWatchSink'
            },
            @{
                'Id'        = 'ApplicationLogToCloudWatch'
                'SourceRef' = 'ApplicationLog'
                'SinkRef'   = 'ApplicationLog-CloudWatchLogsSink'
            },
            @{
                'Id'        = 'SecurityLogToCloudWatch'
                'SourceRef' = 'SecurityLog'
                'SinkRef'   = 'SecurityLog-CloudWatchLogsSink'
            },
            @{
                'Id'        = 'SystemLogToCloudWatch'
                'SourceRef' = 'SystemLog'
                'SinkRef'   = 'SystemLog-CloudWatchLogsSink'
            }
            $ADFSPipes
            $WAPPipes
        )
        'SelfUpdate' = 0
    }

    Try {
        $Version = (Invoke-WebRequest 'https://s3-us-west-2.amazonaws.com/kinesis-agent-windows/downloads/packages.json' -Headers @{"Accept" = "application/json" } -UseBasicParsing | Select-Object -ExpandProperty 'Content' | ConvertFrom-Json | Select-Object -ExpandProperty 'Packages').Version[0]
    } Catch [System.Exception] {
        Write-Output "Failed to get latest KTAP version $_"
        Exit 1
    }

    (New-Object -TypeName 'System.Net.WebClient').DownloadFile("https://s3-us-west-2.amazonaws.com/kinesis-agent-windows/downloads/AWSKinesisTap.$Version.msi", 'C:\AWSQuickstart\AWSKinesisTap.msi')

    Write-Output 'Installing KinesisTap'
    $Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/I C:\AWSQuickstart\AWSKinesisTap.msi /quiet /l C:\AWSQuickstart\ktap-install-log.txt' -NoNewWindow -PassThru -Wait -ErrorAction Stop
    
    If ($Process.ExitCode -ne 0) {
        Write-Output "Error installing KinesisTap -exit code $($Process.ExitCode)"
        Exit 1
    }

    Write-Output 'Getting region'
    Try {
        [string]$Token = Invoke-RestMethod -Headers @{'X-aws-ec2-metadata-token-ttl-seconds' = '3600' } -Method 'PUT' -Uri 'http://169.254.169.254/latest/api/token' -UseBasicParsing -ErrorAction Stop
        $Region = (Invoke-RestMethod -Headers @{'X-aws-ec2-metadata-token' = $Token } -Method 'GET' -Uri 'http://169.254.169.254/latest/dynamic/instance-identity/document' -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty 'Region').ToUpper()
    } Catch [System.Exception] {
        Write-Output "Failed to get region $_"
        Exit 1
    }

    $KenesisAgentSettings.Sinks | Where-Object { $_.Region -eq 'ReplaceMe' } | ForEach-Object { $_.Region = $Region }
    
    Write-Output 'Exporting appsettings.json content'
    Try {
        $KenesisAgentSettings | ConvertTo-Json -Depth 10 -ErrorAction Stop | Out-File 'C:\Program Files\Amazon\AWSKinesisTap\appsettings.json' -Encoding 'ascii' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Unable to export appsettings.json $_"
        Exit 1
    }

    Write-Output 'Restarting AWSKinesisTap service'
    Try {
        Restart-Service 'AWSKinesisTap' -Force
    } Catch [System.Exception] {
        Write-Output "Unable to restart AWSKinesisTap $_"
        Exit 1
    }
}