#------------------------------------------------------------------------------ 
# Firewall
#------------------------------------------------------------------------------ 
function firewall {
    Write-Host "======= Firewall services uitschakelen ======="

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

}

#------------------------------------------------------------------------------ 
#  IP-configuratie
#------------------------------------------------------------------------------ 
function IPconfiguratie {
    Write-Host "======= Ip adress aanpassen ======="

    $interface = "Ethernet 2"
    $address = "192.168.25.10"
    $prefix =  "24"

    $existingIP = Get-NetIPAddress -InterfaceAlias $interface -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $address }

    if (-not $existingIP) {
        New-NetIPAddress `
            -InterfaceAlias $interface `
            -IPAddress $address `
            -PrefixLength $prefix
    }else {
        Write-Host "Ip adress is al $address"
    }


    # dns caching uitschakelen op nat adapter
    Get-NetAdapter "Ethernet" | Set-DNSClient -RegisterThisConnectionsAddress $False
}

#------------------------------------------------------------------------------ 
# Active Directory
#------------------------------------------------------------------------------
function ActiveDirectory{
    # Variabelen
    $voornaam = "Joran"
    $LDAPPath = "WS2-25-$voornaam"
    $domein = "hogent"
    $domeinNaam = "$LDAPPath.$domein"

    $LegacyName = "WS225JORAN"
    $FFLevel = "Win2025"
    $DFLevel = "Win2025"
    $safemode = ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force

    Write-Host "======= AD service installeren ======="
    if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
        Write-Host "AD Services installeren..."
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

        
            Write-Host "======= Forest Configureren ======="
            Install-ADDSForest `
                -DomainName $domeinNaam `
                -SafeModeAdministratorPassword $safemode `
                -DomainNetbiosName $LegacyName `
                -ForestMode $FFLevel `
                -DomainMode $DFLevel `
                -InstallDNS:$true `
                -Force `
                
            Write-Host "Rebooting Server... ,Gelieve het script opnieuw te runnen binnen 5 minuten!!!" 
            exit 0
    }else{
        Write-Host "AD service en forest al geinstalleerd, skippen..."
    }




    # OU configureren
    if (Get-ADDomain -ErrorAction SilentlyContinue) { #checken of forest er al is
        
        Write-Host "======= OU configureren ======="
            $OUs = @("Admins", "employees", "IT")

            foreach ($ou in $OUs) {
                $exists = Get-ADOrganizationalUnit -LDAPFilter "(ou=$ou)" -ErrorAction SilentlyContinue
                if (-not $exists) {
                    Write-Host "OU $ou created."
                    New-ADOrganizationalUnit -Name $ou -Path "DC=$LDAPPath,DC=$domein"
                } else {
                    Write-Host "OU $ou already exists, skipping..."
                }
            }    

        Write-Host "======= admin gebruikers aanmaken ======="
        $adminUsers = @(
            @{ Name = "Admin1"; SamAccountName = "Admin1"; OU = "Admins" },
            @{ Name = "Admin2"; SamAccountName = "Admin2"; OU = "Admins" }
        )

        foreach ($user in $adminUsers) {
            $exists = Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'" -ErrorAction SilentlyContinue
            if (-not $exists) {
                Write-Host "Domain Admin creeren: $($user.Name)"
                $pw = ConvertTo-SecureString "P@ssword123" -AsPlainText -Force
                New-ADUser -Name $user.Name `
                        -SamAccountName $user.SamAccountName `
                        -AccountPassword $pw `
                        -Enabled $true `
                        -Path "OU=$($user.OU),DC=$LDAPPath,DC=$domein"
                Add-ADGroupMember -Identity "Domain Admins" -Members $user.SamAccountName
            } else {
                Write-Host "User $($user.Name) bestaat al, skippen..."
            }
        }


        Write-Host "=== Normale gebruikers aanmaken ==="
        $normalUsers = @(
            @{ Name = "User1"; SamAccountName = "User1"; OU = "employees" },
            @{ Name = "User2"; SamAccountName = "User2"; OU = "IT" }
        )

        foreach ($user in $normalUsers) {
            $exists = Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'" -ErrorAction SilentlyContinue
            if (-not $exists) {
                Write-Host "Domain User creeren: $($user.Name)"
                $pw = ConvertTo-SecureString "P@ssword123" -AsPlainText -Force
                New-ADUser -Name $user.Name `
                        -SamAccountName $user.SamAccountName `
                        -AccountPassword $pw `
                        -Enabled $true `
                        -Path "OU=$($user.OU),DC=$LDAPPath,DC=$domein"
            } else {
                Write-Host "User $($user.Name) bestaat al, skippen..."
            }
        }
    }else{
        Write-Host "forest niet geinstallleerd of server moet opnieuw opgestard worden, OU skippen..."
    }

}

#------------------------------------------------------------------------------ 
# Primaire DNS
#------------------------------------------------------------------------------ 
function DNS {

    # AD domein instellen
    $LDAPPath = "WS2-25-Joran"
    $domein = "hogent"
    $domeinNaam = "$LDAPPath.$domein"

    $zone = $domeinNaam                  # Forward zone = AD-domein
    $network = "192.168.25.0/24"        # Netwerk voor reverse lookup
    $reverseZoneName = "25.168.192.in-addr.arpa"
    $secondaryDNS = "192.168.25.20"      # Secundaire DNS

    Write-Host "======= DNS Configuratie ======="

    # DNS rol installeren
    Install-WindowsFeature DNS -IncludeManagementTools | Out-Null

    # Forward lookup zone
    if (-not (Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue)) {
        Add-DnsServerPrimaryZone -Name $zone -ZoneFile "$zone.DNS"
        Write-Host "Forward zone: $zone gecreerd."
    } else {
        Write-Host "Forward zone: $zone bestaat al, skippen..."
    }

    # Zone transfers configureren
    Set-DnsServerPrimaryZone -Name $zone -SecureSecondaries TransferToSecureServers -SecondaryServers $secondaryDNS
    Write-Host "Zone transfers geconfigureerd als secundaire DNS: $secondaryDNS."

    # Reverse lookup zone
    if (-not (Get-DnsServerZone -Name $reverseZoneName -ErrorAction SilentlyContinue)) {
        Add-DnsServerPrimaryZone -NetworkID $network -ReplicationScope "Forest"
        Write-Host "Reverse zone: $reverseZoneName gecreerd."
    } else {
        Write-Host "Reverse zone: $reverseZoneName bestaat al, skippen..."
    }

    # PTR-record voor DC (pas naam aan naar je servernaam)
    $ptrHost = "WS2-25-Joran.$domein"  # Domeincontroller hostname
    if (-not (Get-DnsServerResourceRecord -ZoneName $reverseZoneName -Name "10" -RRType PTR -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordPtr -Name "10" -ZoneName $reverseZoneName -PtrDomainName $ptrHost
        Write-Host "PTR record voor: $ptrHost gecreerd."
    } else {
        Write-Host "PTR record bestaat al, skippen..."
    }
}
#------------------------------------------------------------------------------ 
# DHCP
#------------------------------------------------------------------------------ 
function DHCP {
    # Variabelen
    $voornaam = "Joran"
    $LDAPPath = "WS2-25-$voornaam"
    $domein = "hogent"
    $domeinNaam = "$LDAPPath.$domein"

    $DNSName = "server1.$domeinNaam"
    $scopeName = "ScopeHOGENT"
    $startRange = "192.168.25.50"
    $endRange = "192.168.25.150"
    $subnet = "255.255.255.0"
    $state = "Active"

    $exclusionStart = "192.168.25.101"
    $exclusionEnd = "192.168.25.150"
    $scopeID = "192.168.25.0"

    Write-Host "======= DHCP Configuratie ======="

    # DHCP rol installeren
    Install-WindowsFeature DHCP -IncludeManagementTools

    # DHCP service herstarten
    Restart-Service dhcpserver

    # DHCP server autoriseren binnen AD
    $authorized = Get-DhcpServerInDC -ErrorAction SilentlyContinue | Where-Object { $_.DnsName -eq $DNSName }
    if (-not $authorized) {
        Add-DhcpServerInDC -DnsName $DNSName -IPAddress 192.168.25.10
        Write-Host "DHCP server: $DNSName geautoriseerd in AD."
    } else {
        Write-Host "DHCP server: $DNSName is al geautoriseerd, skipping..."
    }

    # Controleer of scope al bestaat
    $existingScope = Get-DhcpServerv4Scope -ScopeId $scopeID -ErrorAction SilentlyContinue
    if (-not $existingScope) {
        Add-DhcpServerv4Scope -Name $scopeName -StartRange $startRange -EndRange $endRange -SubnetMask $subnet -State $state
        Write-Host "DHCP scope: $scopeName aangemaakt."
    } else {
        Write-Host "DHCP scope: $scopeName bestaat al, skipping..."
    }

    # Controleer of exclusion range al bestaat
    $existingExclusions = Get-DhcpServerv4ExclusionRange -ScopeId $scopeID -ErrorAction SilentlyContinue |
                          Where-Object { $_.StartRange -eq $exclusionStart -and $_.EndRange -eq $exclusionEnd }
    if (-not $existingExclusions) {
        Add-DhcpServerv4ExclusionRange -ScopeID $scopeID -StartRange $exclusionStart -EndRange $exclusionEnd
        Write-Host "Exclusion range: $exclusionStart - $exclusionEnd toegevoegd."
    } else {
        Write-Host "Exclusion range: $exclusionStart - $exclusionEnd bestaat al, skipping..."
    }
}


#------------------------------------------------------------------------------ 
# CA
#------------------------------------------------------------------------------ 
function CA {
    $CACommonName = "WSII-CA"

    Write-Host "======= Certificate Authority installeren ======="

    # Install Certificate Services + Web Enrollment
    if (-not (Get-WindowsFeature ADCS-Cert-Authority).Installed) {
        Write-Host "Installeren ADCS-Cert-Authority..."
        Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
    } else {
        Write-Host "ADCS-Cert-Authority al geïnstalleerd, skippen..."
    }

    if (-not (Get-WindowsFeature ADCS-Web-Enrollment).Installed) {
        Write-Host "Installeren ADCS-Web-Enrollment..."
        Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
    } else {
        Write-Host "ADCS-Web-Enrollment al geïnstalleerd, skippen..."
    }

    # Configure Enterprise Root CA if not already configured
    $caStatus = Get-CACertificationAuthority -ErrorAction SilentlyContinue
    if (-not $caStatus) {
        Write-Host "Configureren Enterprise Root CA..."
        try {
            Install-AdcsCertificationAuthority `
                -CAType EnterpriseRootCA `
                -CACommonName $CACommonName `
                -KeyLength 2048 `
                -HashAlgorithmName SHA256 `
                -ValidityPeriod Years `
                -ValidityPeriodUnits 5 `
                -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
                -Force
            Write-Host "Root CA geïnstalleerd."
        }
        catch {
            Write-Host "Fout bij installeren CA: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    } else {
        Write-Host "De Certification Authority is al geconfigureerd, skippen..."
    }

    # Configure Web Enrollment if not already configured
    $webEnrollmentStatus = Get-WebApplication -Site "Default Web Site" -Name "CertSrv" -ErrorAction SilentlyContinue
    if (-not $webEnrollmentStatus) {
        Write-Host "Configureren Web Enrollment..."
        try {
            Install-AdcsWebEnrollment -Force
            Write-Host "Web Enrollment geconfigureerd."
        }
        catch {
            Write-Host "Fout bij configureren Web Enrollment: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Web Enrollment is al geconfigureerd, skippen..."
    }

    # Configure IIS settings for CertSrv - ALLOW ALL DOMAIN USERS
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    

    Write-Host "Configureren IIS instellingen voor CertSrv (toegang voor alle domeingebruikers)..."

    # Enable Windows Authentication
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value true -Location "Default Web Site/CertSrv" -ErrorAction SilentlyContinue
        
    # Disable Anonymous Authentication
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value false -Location "Default Web Site/CertSrv" -ErrorAction SilentlyContinue        
    
    Set-WebConfigurationProperty -Filter "/system.webServer/security/access" -Name sslFlags -Value "None" -Location "Default Web Site/certsrv"

    Add-WebConfigurationProperty -PSPath 'IIS:\' -Filter 'system.webServer/authorization' -Location $loc -Name '.' -Value @{accessType='Allow'; users='*'} -ErrorAction SilentlyContinue | Out-Null


    # Wait for certificate service to be ready
    Write-Host "Wachten op certificaat service..."
    Start-Sleep -Seconds 15

    # # Get and export CA certificate
    # $exportPath = "C:\CAroot.cer"
    # try {
    #     $caCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$CACommonName*" } | Select-Object -First 1
        
    #     if (-not $caCert) {
    #         # Alternative search in CA store
    #         $caCert = Get-ChildItem Cert:\LocalMachine\CA | Where-Object { $_.Subject -like "*$CACommonName*" } | Select-Object -First 1
    #     }

    #     if ($caCert) {
    #         Export-Certificate -Cert $caCert -FilePath $exportPath -Type CERT -Force
    #         Write-Host "======= Root CA certificaat geëxporteerd naar $exportPath ======="
    #     } else {
    #         Write-Host "Waarschuwing: Kon CA certificaat niet vinden om te exporteren!" -ForegroundColor Yellow
    #     }
    # }
    # catch {
    #     Write-Host "Fout bij exporteren certificaat: $($_.Exception.Message)" -ForegroundColor Red
    # }

    # # Create GPO for automatic trust
    # try {
    #     # $domain = (Get-ADDomain).DNSRoot
    #     $domainDN = (Get-ADDomain).DistinguishedName

    #     $gpo = Get-GPO -Name "Auto-Trust-Enterprise-CA" -ErrorAction SilentlyContinue
    #     if (-not $gpo) {
    #         $gpo = New-GPO -Name "Auto-Trust-Enterprise-CA"
    #         Write-Host "GPO $($gpo.DisplayName) aangemaakt."
            
    #         # Set GPO description
    #         Set-GPRegistryValue -Name $gpo.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates" -ValueName "AutoTrustCA" -Type String -Value "Enabled"
    #     } else {
    #         Write-Host "GPO $($gpo.DisplayName) bestaat al, skippen..."
    #     }

    #     # Check if the link already exists
    #     $existingLink = Get-GPInheritance -Target $domainDN | 
    #         Select-Object -ExpandProperty GpoLinks |
    #         Where-Object { $_.DisplayName -eq $gpo.DisplayName }

    #     if (-not $existingLink) {
    #         New-GPLink -Name $gpo.DisplayName -Target $domainDN -LinkEnabled Yes
    #         Write-Host "GPO-link $($gpo.DisplayName) aangemaakt."
    #     } else {
    #         Write-Host "GPO-link $($gpo.DisplayName) bestaat al, skippen..."
    #     }

    #     # Import certificate to Trusted Root Certification Authorities
    #     if (Test-Path $exportPath) {
    #         Import-Certificate -FilePath $exportPath -CertStoreLocation "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue
    #         Write-Host "Certificaat geïmporteerd in Trusted Root Store."
    #     }

    # }
    # catch {
    #     Write-Host "Waarschuwing: GPO configuratie mislukt: $($_.Exception.Message)" -ForegroundColor Yellow
    # }

    # # Force GPO update
    # Write-Host "Forceren GPO update..."
    # gpupdate /force | Out-Null

    # Write-Host "======= CA installatie en GPO configuratie voltooid =======" -ForegroundColor Green
    Write-Host "======= Certificate Authority Web Enrollment draait nu op: http://$env:COMPUTERNAME/CertSrv =======" -ForegroundColor Green
    # Write-Host "======= En ook op: http://$((Get-ADDomain).DNSRoot)/CertSrv =======" -ForegroundColor Green
    # Write-Host "======= TOEGANG: Alle domeingebruikers hebben nu toegang! =======" -ForegroundColor Cyan
}

#------------------------------------------------------------------------------ 
# Helper: Run as Domain Admin
#------------------------------------------------------------------------------ 
function RunAsDomainAdminInline {
    param (
        [string]$FunctionName
    )

    $domainAdmin = "WS225JORAN\Admin1"
    $password = ConvertTo-SecureString "P@ssword123" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($domainAdmin, $password)

    Write-Host "==> Uitvoeren van $FunctionName als $domainAdmin ..."

    # Definieer de functie eerst in de remote sessie, dan roep je ze aan
    $functionDef = (Get-Command $FunctionName).Definition

    Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {
        param($fnName, $fnBody)
        # functie opnieuw definiëren in remote sessie
        Invoke-Expression "function $fnName { $fnBody }"
        & $fnName
    } -ArgumentList $FunctionName, $functionDef
}

#------------------------------------------------------------------------------ 
# run
#------------------------------------------------------------------------------ 
firewall
IPconfiguratie
ActiveDirectory
DNS
# DHCP en CA moet als domain admin draaien
RunAsDomainAdminInline -FunctionName "DHCP"
RunAsDomainAdminInline -FunctionName "CA"
Write-Host "======= Server 1 Volledig Geconfigureerd ======="