
                 NETWORK ENDPOINT VISUAL PINGER


A multi-threaded network endpoint monitoring 
tool written natively in PowerShell. This utility leverages .NET 
Runspace Pools for extreme concurrency and Windows DPAPI to secure local 
preset data.


------------------------------------------------------------------------
I. KEY FEATURES
------------------------------------------------------------------------

* High-Performance Multi-Threading:
  Utilizing native .NET Runspace Pools rather than heavy, slow PSJobs 
  to query dozens of hosts concurrently with minimal system overhead.

* DPAPI Secure Local Storage:
  Presets and configuration files are encrypted on-disk using the 
  Windows Data Protection API (DPAPI). Your network topology and targets 
  remain secure and readable only by your specific Windows user session.

* Autonomous Diagnostics (Auto-Traceroute):
  Tracks state transitions. If a monitored host goes from ONLINE to 
  OFFLINE, the engine automatically fires an asynchronous background 
  traceroute to isolate where the connection broke, without 
  interrupting the live UI.

* Live Interactive Dashboard:
  A clean, color-coded terminal interface showing real-time ping latency, 
  host nicknames, active background diagnostic tasks, and recent failure 
  event logs.

* Safety Governor Engine:
  Prevents unintentional network flooding or CPU exhaustion by capping 
  concurrency threads and restricting minimal ping frequencies unless 
  explicitly bypassed by an administrator.

* Web Report Integration:
  Optionally outputs a clean, self-refreshing HTML dashboard 
  (status.html) for quick monitoring on secondary screens or sharing 
  across local networks.


------------------------------------------------------------------------
II. SYSTEM REQUIREMENTS
------------------------------------------------------------------------

* Operating System: Windows 10 / 11 or Windows Server (2016+)
* PowerShell Version: PowerShell 5.1 or PowerShell Core (7.x+)
* Privileges: Administrative privileges are required to perform raw 
  ICMP send requests and network diagnostics.


------------------------------------------------------------------------
III. INSTALLATION & SETUP
------------------------------------------------------------------------

1. Clone this repository to your local machine:
   
   git clone https://github.com/YOUR_USERNAME/visual-pinger-tool.git
   cd visual-pinger-tool

2. Run PowerShell as an Administrator.

3. Set your execution policy to allow local script runs if you haven't 
   already:
   
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process


------------------------------------------------------------------------
IV. HOW TO RUN THE TOOL
------------------------------------------------------------------------

Launch the tool from your administrator PowerShell terminal:

   .\Visual-Pinger-Tool.ps1

Command-Line Parameters:

* -EncryptedFile <string>
  Specify a custom path/name for your encrypted presets file 
  (defaults to pinger_presets.enc).

* -DebugMode
  Enables highly verbose diagnostic and error outputs to the console 
  for troubleshooting.

Example using custom database file:
   .\Visual-Pinger-Tool.ps1 -EncryptedFile "production_servers.enc"


------------------------------------------------------------------------
V. GUIDED WALKTHROUGH
------------------------------------------------------------------------


       ENTERPRISE MULTI-PRESET VISUAL PINGER        

1. Select a Saved Preset & Start Monitor
2. Create New Preset (Import from text file)
3. Create New Preset (Manually type)
4. Manage Presets (View / Edit / Delete)
5. Configure Global Settings & Safety limits
6. Exit System
=
Select option (1-6): 

1. Creating a Preset:
   You can spin up a preset in two ways:
   * Manual Entry (Option 3): Type in your IP addresses or Hostnames, 
     and optionally assign clean, human-readable Nicknames 
     (e.g., "Gateway Router" or "Primary Domain Controller").
   * Bulk Import (Option 2): Point the script to a plain-text file 
     containing one IP/Hostname per line to batch import large lists 
     of infrastructure targets.

2. Launching the Live Monitor:
   When you launch a monitoring session, you will see a live dashboard 
   displaying:
   * Online/Offline status indicators (Green/Red).
   * Latency response in milliseconds (ms).
   * Active background diagnostic jobs.
   * The last 5 traceroute alerts compiled directly from the 
     monitoring pipeline.

   [PRO-TIP]: You can stop the live monitor safely at any time by 
   pressing CTRL + C. The script will intercept the command, cleanly 
   terminate its worker runspace threads, close out background jobs, 
   and gracefully return you to the main menu.

3. Tuning Performance (Global Settings):
   Navigate to Option 5 to configure default safety parameters:
   * Refresh Interval: How often target pools are pinged (seconds).
   * Max Concurrency: Maximum threads to spawn in the Runspace Pool.
   * Stagger Delay: Millisecond delay between spawning threads to 
     smooth out local network egress.
   * Randomize Jitter: Applies a random +/- 2 second offset to the 
     refresh timer to prevent diagnostic patterns from looking like 
     automated scans.


------------------------------------------------------------------------
VI. ARCHITECTURAL & SECURITY HIGHLIGHTS
------------------------------------------------------------------------

If you are evaluating this tool for enterprise applications or reviewing 
it for a portfolio, here are the core design principles implemented 
under the hood:

1. High Performance: Runspaces vs. PSJobs
   Traditional PowerShell parallel scripts use standard Start-Job 
   commands. This creates an entirely new powershell.exe process 
   context for each target, which consumes roughly 30-50MB of RAM per 
   target and strains the host CPU.

   This script implements:
   [runspacefactory]::CreateRunspacePool()
   
   Threading occurs in-memory within a single process context, enabling 
   massive parallel scans with sub-second execution times and negligible 
   footprint.

2. Secure by Default: Windows DPAPI
   Unlike tools that save configurations in plaintext JSON, this script 
   protects data using DPAPI through the .NET Cryptography Class:

   [System.Security.Cryptography.ProtectedData]::Protect(
       $bytes, $null, 
       [System.Security.Cryptography.DataProtectionScope]::CurrentUser
   )

   The configuration is encrypted using a key tied to the operating 
   system user account. If another user on the machine or an attacker 
   steals the pinger_presets.enc file, they cannot decrypt or read your 
   target endpoints.

3. Event-Driven Asynchronous Logging
   Rather than running intensive traceroutes constantly, the script 
   utilizes state-based transitions. Traceroutes are only triggered 
   the exact loop iteration an endpoint transitions from ONLINE 
   directly to OFFLINE. The resulting route trace is preserved in 
   pinger_debug.log for future forensic network analysis.
