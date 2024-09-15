# Ultimate-Ram
Ram Unlimited
# Extreme RAM Optimization Script for Windows
# WARNING: This script will aggressively strip Windows of memory-consuming features and services to maximize available RAM.

# Ensure the script is run as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You need to run this script as an administrator!" -ForegroundColor Red
    exit
}

Write-Host "Starting the ultimate RAM optimization script for Windows..." -ForegroundColor Yellow

# PART 1: Kernel-Level Memory Management and Paging Optimizations

Write-Host "Optimizing kernel-level memory handling and paging..." -ForegroundColor Yellow
# Disable Paging Executive (forces Windows to keep system processes in RAM, not paging them to disk)
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Force

# Set LargeSystemCache to 0 to avoid allocating too much RAM to file system caching
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 0 -Force

# Force Windows to prioritize using physical memory (RAM) over paging to the disk
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IoPageLockLimit" -Value 0xFFFFFFFF -Force  # Maximize RAM usage for I/O

# Force Windows to use all available RAM before paging to disk
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Force  # Clears the pagefile at shutdown to prevent unnecessary paging

# Adjust system cache working set to prevent excessive memory use by cache manager
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SystemCacheWorkingSetSize" -Value 0xFFFFFFFF -Force  # Optimized for performance

# PART 2: Disable Memory-Intensive Services and Processes

Write-Host "Disabling more unnecessary services to free up RAM..." -ForegroundColor Yellow
$services = @(
    "SysMain",  # Superfetch (RAM-hungry service that preloads apps into memory)
    "WSearch",  # Windows Search (uses RAM to index files)
    "DiagTrack",  # Diagnostic Tracking Service (sends telemetry and consumes RAM)
    "DoSvc",  # Delivery Optimization (Windows Update delivery, uses background memory)
    "Fax",  # Fax Service (not needed for most users)
    "XblAuthManager",  # Xbox Live Auth Manager (background Xbox service)
    "WMPNetworkSvc",  # Windows Media Player Network Sharing Service
    "Spooler",  # Print Spooler (disable if no printer is used)
    "MapsBroker",  # Offline Maps service (not used by most)
    "BluetoothUserService",  # Bluetooth service (disable if not used)
    "RetailDemo",  # Retail Demo service (only for demo PCs)
    "IKEEXT",  # IPsec Keying Modules (not needed for home users)
    "OneSyncSvc",  # Sync Host (syncs settings across devices, uses background RAM)
    "BcastDVRUserService",  # Game Broadcasting (RAM-hungry service)
    "MessagingService",  # Messaging service (used for mobile SMS sync, not needed on most PCs)
    "TabletInputService",  # Tablet PC Input Service (disable if no tablet is used)
    "NetTcpPortSharing",  # TCP Port Sharing (disable if not needed)
    "SmsRouter",  # SMS Router Service
    "BiSvc"  # Biometrics Service (disable if no biometric devices are used)
)

foreach ($service in $services) {
    Set-Service -Name $service -StartupType Disabled
    Stop-Service -Name $service -Force
    Write-Host "Disabled $service service to free up RAM" -ForegroundColor Green
}

# PART 3: More Aggressive Memory Management Optimizations

Write-Host "Tweaking memory management settings to maximize RAM efficiency..." -ForegroundColor Yellow
# Disable Superfetch/Prefetch entirely (these services preload apps into RAM, reducing free memory)
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Force
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 0 -Force

# Disable standby list memory for more active RAM usage
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "StandbyMemoryListPriority" -Value 0 -Force

# Enable memory compression (reduces RAM usage by compressing less active data in memory)
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "CompressionEnabled" -Value 1 -Force

# Disable Windows Defender's real-time monitoring to free up memory
Set-MpPreference -DisableRealtimeMonitoring $true

# PART 4: Visual Effects and UI Stripping to Reduce RAM Usage

Write-Host "Disabling visual effects and animations to free up RAM..." -ForegroundColor Yellow
# Set system for best performance (disables all visual effects)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Force

# Disable window animations, shadows, and taskbar animations
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value 90,12,03,80,10,00,00,00 -Force  # Minimal visual effects
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0 -Force  # Instant menu display
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value 0 -Force  # Disable full window dragging

# Disable transparency effects that consume GPU and RAM
New-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Force

# PART 5: Optimize Virtual Memory (Page File) for RAM Efficiency

Write-Host "Optimizing virtual memory settings to reduce paging and maximize RAM usage..." -ForegroundColor Yellow
# Optimize the page file size (limit the amount of RAM being swapped to disk)
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "C:\pagefile.sys 1024 2048" -Force  # Min 1GB, Max 2GB

# Clear the page file at shutdown to prevent excessive use of paging
New-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Force

# PART 6: Background Apps and Telemetry Disablement to Free Up RAM

Write-Host "Disabling background apps to free up RAM..." -ForegroundColor Yellow
# Disable Windows background apps that consume memory in the background
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2 -Force  # Prevent background apps from running

# Disable telemetry (tracking services) that consume RAM
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force  # Disable telemetry

# Disable Windows Error Reporting (fewer services running in the background)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Force

# PART 7: Final RAM-Optimizing Tweaks and Miscellaneous Settings

Write-Host "Applying final tweaks to optimize RAM usage..." -ForegroundColor Yellow
# Disable Windows Tips and feedback to reduce memory consumption
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0 -Force  # Disable Windows Tips
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0 -Force  # Disable Spotlight tips and suggestions

# Remove startup delay to speed up boot time and reduce initial RAM usage
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Value 0 -Force

Write-Host "Extreme RAM optimization complete. Reboot your system for all changes to take effect." -ForegroundColor Green
