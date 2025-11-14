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

    # Stel de host-only interface in om server1 als DNS te gebruiken
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses 192.168.25.10

    # Controleer het opnieuw
    Get-DnsClientServerAddress -InterfaceAlias "Ethernet 2"


    # dns caching uitschakelen op nat adapter
    Get-NetAdapter "Ethernet" | Set-DNSClient -RegisterThisConnectionsAddress $False

}

#------------------------------------------------------------------------------ 
# RSAT tools
#------------------------------------------------------------------------------ 
function RSAT {
    Write-Host "======= RSAT tools installeren ======="

    # Voor Windows 10/11 clients (Features-on-Demand)
    Write-Host "Active directory tools installeren ..."
    Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"

    Write-Host "DNS tools installeren ..."
    Add-WindowsCapability -Online -Name "Rsat.Dns.Tools~~~~0.0.1.0"

    Write-Host "DHCP tools installeren ..."
    Add-WindowsCapability -Online -Name "Rsat.Dhcp.Tools~~~~0.0.1.0"

    Write-Host "AD CS management tools installeren ..."
    Add-WindowsCapability -Online -Name "Rsat.CertificateServices.Tools~~~~0.0.1.0"


}

#------------------------------------------------------------------------------ 
# SSMS
#------------------------------------------------------------------------------ 
function Install-SSMSClient {
    Write-Host "======= SSMS Client installeren ======="
    # Pad waar SSMS geïnstalleerd zal worden
    $ssmsInstallerPath = Join-Path -Path $PSScriptRoot -ChildPath "vs_SSMS.exe"

    # Download SSMS installer als deze nog niet aanwezig is
    if (-not (Test-Path $ssmsInstallerPath)) {
        Write-Host "SSMS installer wordt gedownload..."
        # Invoke-WebRequest -Uri "https://aka.ms/ssms/21/release/vs_SSMS.exe" -OutFile 
        Start-BitsTransfer -Source "https://aka.ms/ssmsfullsetup" -Destination $ssmsInstallerPath
    } else {
        Write-Host "SSMS installer bestaat al, overslaan download."
    }

    # SSMS installeren (stil)   
    Write-Host "SSMS wordt geinstalleerd..."
    Start-Process -FilePath $ssmsInstallerPath -ArgumentList "/install /quiet" -Wait

    Write-Host "SSMS installatie voltooid."
    Write-Host "Je kan nu verbinding maken met SQL Server via SSMS."
}
#------------------------------------------------------------------------------ 
# Domeinlid maken
#------------------------------------------------------------------------------
function Join-Domain {
    param (
        [string]$DomainName = "WS2-25-Joran.hogent",
        [string]$DomainAdmin  = "Admin1",
        [string]$OU = "OU=employees,DC=WS2-25-Joran,DC=hogent"  # Optional: specifieke OU voor client
    )
    $DomainAdminPassword = "P@ssword123"
    # Controleer of machine al lid is van het domein
    $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    if ($currentDomain -eq $DomainName) {
        Write-Host "Machine is al lid van domein: $DomainName, skippen..."
        return
    }

    Write-Host "Machine wordt lid van domein: $DomainName..."

    $securePassword = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ("$DomainName\$DomainAdmin", $securePassword)

    # Lid worden van domein
    Add-Computer -DomainName $DomainName -Credential $Cred -OUPath $OU -Restart
    Write-Host "======= Client is Volledig Geconfigureerd ======="

    Write-Host "Client is succesvol lid van het domein. De machine wordt herstart..."
}
#------------------------------------------------------------------------------ 
# run
#------------------------------------------------------------------------------ 
firewall
IPconfiguratie
RSAT
Install-SSMSClient
Join-Domain
