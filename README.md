# Extreme RAM Optimization Script for Windows
# WARNING: This script aggressively optimizes memory usage.

# Ensure the script is run as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You need to run this script as an administrator!" -ForegroundColor Red
    exit
}

Write-Host "Starting the extreme RAM optimization script..." -ForegroundColor Yellow

# PART 1: Kernel-Level Memory Management and Paging Optimizations
Write-Host "Optimizing kernel-level memory handling and paging..." -ForegroundColor Yellow
$memoryManagementPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"

# Disable Paging Executive: Keep system processes in RAM
New-ItemProperty -Path $memoryManagementPath -Name "DisablePagingExecutive" -Value 1 -Force

# Set LargeSystemCache to 0
New-ItemProperty -Path $memoryManagementPath -Name "LargeSystemCache" -Value 0 -Force

# Maximize RAM usage for I/O
New-ItemProperty -Path $memoryManagementPath -Name "IoPageLockLimit" -Value 0xFFFFFFFF -Force

# Clear pagefile at shutdown to avoid unnecessary paging
New-ItemProperty -Path $memoryManagementPath -Name "ClearPageFileAtShutdown" -Value 1 -Force

# Optimize System Cache Working Set Size
New-ItemProperty -Path $memoryManagementPath -Name "SystemCacheWorkingSetSize" -Value 0xFFFFFFFF -Force

# PART 2: Disable Memory-Intensive Services
Write-Host "Disabling unnecessary services..." -ForegroundColor Yellow
$services = @(
    "SysMain", "WSearch", "DiagTrack", "DoSvc", "Fax", "XblAuthManager",
    "WMPNetworkSvc", "Spooler", "MapsBroker", "BluetoothUserService",
    "RetailDemo", "IKEEXT", "OneSyncSvc", "BcastDVRUserService",
    "MessagingService", "TabletInputService", "NetTcpPortSharing",
    "SmsRouter", "BiSvc"
)

foreach ($service in $services) {
    # Check if the service exists before trying to disable it
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        Set-Service -Name $service -StartupType Disabled
        Stop-Service -Name $service -Force
        Write-Host "Disabled $service service" -ForegroundColor Green
    } else {
        Write-Host "Service $service not found on this system." -ForegroundColor Red
    }
}

# PART 3: More Aggressive Memory Management Optimizations
Write-Host "Tweaking memory management settings..." -ForegroundColor Yellow

# Disable Superfetch/Prefetch
$prefetchPath = "$memoryManagementPath\PrefetchParameters"
New-ItemProperty -Path $prefetchPath -Name "EnablePrefetcher" -Value 0 -Force
New-ItemProperty -Path $prefetchPath -Name "EnableSuperfetch" -Value 0 -Force

# Disable standby memory
New-ItemProperty -Path $memoryManagementPath -Name "StandbyMemoryListPriority" -Value 0 -Force

# Enable memory compression
New-ItemProperty -Path $memoryManagementPath -Name "CompressionEnabled" -Value 1 -Force

# Disable Windows Defender's real-time monitoring (if available)
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    Set-MpPreference -DisableRealtimeMonitoring $true
} else {
    Write-Host "Windows Defender module not available. Skipping real-time monitoring disablement." -ForegroundColor Yellow
}

# PART 4: Visual Effects and UI Stripping
Write-Host "Disabling visual effects and animations..." -ForegroundColor Yellow

# Disable all visual effects
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Force

# Disable window animations and transparency
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value 90,12,03,80,10,00,00,00 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Force

# PART 5: Optimize Virtual Memory (Page File)
Write-Host "Optimizing virtual memory settings..." -ForegroundColor Yellow

# Set page file size (Min: 1GB, Max: 2GB)
New-ItemProperty -Path $memoryManagementPath -Name "PagingFiles" -Value "C:\pagefile.sys 1024 2048" -Force

# PART 6: Disable Background Apps and Telemetry
Write-Host "Disabling background apps and telemetry..." -ForegroundColor Yellow

# Disable background apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2 -Force

# Disable telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force

# Disable Windows Error Reporting
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Force

# PART 7: Final Tweaks
Write-Host "Applying final tweaks..." -ForegroundColor Yellow

# Disable Windows Tips and Spotlight
$tipsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
New-ItemProperty -Path $tipsPath -Name "SoftLandingEnabled" -Value 0 -Force
New-ItemProperty -Path $tipsPath -Name "SubscribedContent-338389Enabled" -Value 0 -Force

# Remove startup delay
$serializePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize"
New-Item -Path $serializePath -Force | Out-Null
New-ItemProperty -Path $serializePath -Name "StartupDelayInMSec" -Value 0 -Force

Write-Host "Extreme RAM optimization complete. Reboot your system for all changes to take effect." -ForegroundColor Green
