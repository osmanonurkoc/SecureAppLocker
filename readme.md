

# 🔒 SecureAppLocker

A lightweight, system-level application locker for Windows. Built with a modern **WinUI 3** interface and a robust background NT Service, it intercepts and locks specified applications instantly, requiring a master password for access.

Designed with a **"Fail-Secure"** architecture to prioritize your privacy and keep your personal apps strictly personal.

[![Download Latest Release](https://img.shields.io/badge/Download-Latest_Release-2ea44f?style=for-the-badge&logo=github&logoColor=white)](https://github.com/osmanonurkoc/SecureAppLocker/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows_10%20%7C%2011-0078D4.svg)]()
[![Framework](https://img.shields.io/badge/.NET-10.0-512BD4.svg)]()
[![UI](https://img.shields.io/badge/WinUI-3.0-0078D4.svg)]()
![Downloads](https://img.shields.io/github/downloads/osmanonurkoc/SecureAppLocker/total)
![Release](https://img.shields.io/github/v/release/osmanonurkoc/SecureAppLocker)

## 📸 Screenshots

Instead of cluttering the main page, you can view the Manager Dashboard and Password Prompt designs here:
👉 **[Check out the Screenshots](./screenshots/)**

---

## 🛡️ SECURITY NOTES

**IMPORTANT PLEASE READ:**
This software is designed to enforce application locking on shared or personal computers. While it employs strong system-level defenses, it is important to understand its boundaries based on Windows user privileges.

**🛡️ Standard User Protection (Highly Secure):**
For a standard, non-admin Windows account, this locker is virtually unbreakable:
* **Service-Level Execution:** The core watchdog runs as a Windows NT Service under the `SYSTEM` account. A Standard User cannot stop, pause, or kill this service via Task Manager.
* **ACL File Protection:** Configuration files and encrypted password hashes are protected by strict Access Control Lists (ACLs). Standard users cannot read, modify, or delete the lock rules or password files to bypass the system.

**⚠️ Local Administrator Bypasses & Mitigation:**
Because the Windows OS inherently grants ultimate control to Local Administrators, a user with Admin privileges theoretically has the power to bypass this software. Historically, an admin could bypass the locker by taking ownership of configuration folders, altering registry keys, or disabling the NT Service via `services.msc`.

To combat this, the **System Tools Hardening** feature allows you to lock down the operating system. When enabled, SecureAppLocker actively blocks access to the tools an admin would use to dismantle the service, including:
* Command Prompt, PowerShell, and Windows Terminal
* Registry Editor (`regedit.exe`)
* Microsoft Management Console (`mmc.exe` and `services.msc`)
* System Configuration (`msconfig.exe`)

Furthermore, the core background service is designed so that forcefully terminating it (for example, via Task Manager) results in a system BSOD. This effectively neutralizes direct kill attempts. With System Tools Hardening enabled, booting Windows into Safe Mode (which prevents third-party services from starting) is the only remaining bypass route for a local administrator.

*(Note: We have mitigated the standard Control Panel uninstallation bypass by implementing an independent, SHA-1 hashed uninstall password requirement during the setup phase).*

**USE CASES:**
* **✓** Parental controls (Highly effective if the child uses a Standard Windows account)
* **✓** Privacy from roommates, friends, or family sharing the PC
* **✓** Personal productivity (blocking distracting apps)

**NOT SUITABLE FOR:**
* **✗** Corporate/business endpoint security
* **✗** Protecting highly sensitive/financial data from malicious IT experts
* **✗** Full disk/file encryption (it only locks the app executable, not the raw files on the disk)

---

## ✨ Key Features

* **🎛️ Master Protection Switch & Logging:** Need to quickly disable the system for a gaming session or a heavy workflow? Use the global toggle switch on the Manager dashboard to instantly arm or disarm all application locks without losing your configured apps. You can also toggle the logging switch on or off from the security settings depending on your preference.
* **🛡️ System Tools Hardening:** Instantly protect critical operating system binaries to prevent local administrators from easily bypassing the locker.
* **🔒 Strict Parent-Child Process Validation:** The background service uses NTDLL to trace the execution tree of any launched process. If a protected application is spawned by a parent process that is currently unlocked or explicitly trusted, the password prompt is bypassed. This ensures legitimate wrapper scripts and background environments function uninterrupted, while unauthorized invocations remain blocked.
* **🔍 Audit Logging & Trusted Exceptions UI:** Gain precise control over when locked applications can be invoked by other programs. When an unauthorized background call is intercepted (e.g., a browser extension calling `cmd.exe`), the service silently blocks the process and logs the event instead of throwing a password prompt. You can review these logs in the "Audit Logs" tab and choose to "Trust Parent" or "Trust Command" to selectively whitelist specific executions.
* **✳️ Wildcard (\*) Support:** The Trusted Exceptions system fully supports wildcard characters. Instead of constantly updating exception lists for dynamically changing installer paths (e.g., `VSCodeUserSetup-x64-1.132.0.tmp`), you can define a rule using an asterisk like `VSCodeUserSetup-*.tmp`. The engine securely converts this into a regex pattern to grant seamless access to future updates while keeping your ghost process lists clean.
* **🖱️ Context Menu "Trusted Run":** A "Run via SecureAppLocker" option is integrated directly into the Windows right-click context menu. This allows you to launch any executable with a temporary, one-time "Parent Immunity" after verifying your master password, supporting both standard and elevated administrator privileges. Once the application closes, the temporary clearance vanishes.
* **⚡ Smart Metadata Detection:** Does not just rely on easily spoofable `.exe` file names. It extracts and verifies the `OriginalFilename` and `ProductName` directly from the executable's metadata to prevent simple rename bypasses.
* **⏱️ Granular Timeout Controls:** Temporarily unlock specific apps for a custom duration (e.g., 5, 15, or 60 minutes), or use "Global Unlock" to freely use all protected apps for a defined time window.
* **🔄 State Management & SafePID Resets:** Internal process caching is strictly maintained. SafePIDs and active application immunities are immediately purged and reset whenever the configuration is updated or the Windows session is locked, ensuring no permissions linger.
* **⚙️ Adjustable Micro-Polling:** Control the background service's process scanning interval directly from the UI. Find your perfect balance between CPU performance and millisecond-level instant locking.
* **🔒 Zero-Trust Session Lock (Auto-Reset):** Integrates tightly with Windows Terminal Services (WTS). The moment you lock your Windows session (Win+L), all active unlocked app caches are instantly wiped. Your apps are immediately secure when you step away.
* **🧱 Fail-Secure Architecture:** If the user forcefully closes the password prompt (UI), the background service enters *Lockdown Mode*. Protected apps will be instantly killed without a prompt, locking out the user completely until the UI is manually restarted.
* **🔌 Session-Independent IPC:** Uses robust Named Pipes to communicate securely between the SYSTEM-level background service (Session 0) and the user-level UI (Session 1).
* **🔑 Offline Recovery & Uninstaller Protection:** Generates a locally encrypted DPAPI recovery key so you can reset your Master Password without needing an internet connection. Furthermore, the installer demands a custom uninstall password to stop unauthorized removals.
* **🎨 Modern WinUI 3 Design:** A sleek management dashboard featuring Mica backdrop, smooth animations, and automatic system theme detection.

## 🚀 Getting Started

### System Requirements
* **OS:** Windows 10 (Version 1809 or later) or Windows 11.
* **Privileges:** Local Administrator rights are required to install and run the background service.

### Initial Setup & Installation
1. **Download:** Grab the latest installer from the **Releases** page.
2. **Install & Secure:** Run the setup. **Crucial:** During installation, you will be required to set an *Uninstall Password*. Keep this safe! This step also installs the UI components and registers the `SecureAppLocker` background service with Windows.
3. **First Launch:** Open **SecureAppLocker Manager** from your Start menu. **Important Note:** The default Master Password is **`1234`**. You will need this to authenticate and access the manager interface for the very first time. 
4. **Change Master Password:** Once inside, it is highly recommended to change the default password immediately via the settings. Make sure to safely save the generated Recovery Key.
5. **Add Protected Apps:** The Master Protection Switch is toggled **ON** by default upon launch. Simply use the "Browse" button to securely select target executables. The manager will automatically read the application's internal metadata for accurate tracking.

## 🧠 How It Works (Under the Hood)

Windows has strict boundaries between background services and the user's desktop interface (Session 0 Isolation). SecureAppLocker elegantly solves this by splitting the workload:
1. **The Watchdog (NT Service):** Runs silently as `SYSTEM`. Its only job is to aggressively monitor processes. When a locked app is launched, it kills it instantly and sends a signal through a Named Pipe.
2. **The UI Companion:** Runs in the user's session. It listens for the service's signals and displays the modern WinUI 3 password prompt. If authenticated, it tells the service to whitelist the app temporarily.

### ⚠️ Known Behaviors & Best Practices

*   **Startup Synchronization Delay:** Because the core watchdog runs at the system level (`SYSTEM`), it initializes and begins protecting your computer before you even log into Windows. However, the Password Prompt UI (`SecureAppLocker.UI`) is a user-level application triggered via the Windows Registry upon login. This creates a brief timing gap. If you attempt to launch a protected application immediately after logging into Windows, the service will instantly lock and kill the app, but the password prompt UI may not appear right away because it is still booting up in the background. If this happens, simply wait a few seconds for your startup programs to load, and try launching the application again.
*   **Initial Launch Arguments & Elevation Loss:** The default double-click Password Prompt UI currently does not support capturing launch arguments or "Run as Administrator" elevation states. If a locked application is launched with specific parameters or elevated privileges, the background service will intercept and kill the initial attempt to display the password prompt. Once authenticated, the UI will successfully launch the application, but it will open as a standard user process without any of the original arguments. To use an application with its intended arguments or admin privileges, use the **"Run via SecureAppLocker"** right-click context menu option instead.
*   **Handling Bulk Package Managers (Winget, Scoop):** When using command-line package managers to perform bulk application upgrades, the operating system often breaks the process tree by delegating the actual installation tasks to background OS services or COM objects. Because of this architectural broken chain, parent-child immunity cannot reliably propagate to the extracted setup files. If you have **System Tools Hardening** enabled, these bulk updates will likely be intercepted and blocked. To ensure a smooth experience, we recommend temporarily disabling the Master Protection Switch (or activating the 5-minute Global Unlock mode) from the Manager UI before initiating bulk upgrade operations with Winget, Scoop, or similar tools.

## 🤖 Development & Vibe Coding

**Full Transparency:** This project was brought to life with the support of **"vibe coding"** (roughly 50% AI assistance).

However, do not let that fool you. This is not raw, unchecked output. Every single line of code was meticulously reviewed, manually refactored, and heavily battle-tested. The application underwent long-duration stress tests, edge-case evaluations, and complex IPC/Session 0 deadlock scenarios to ensure maximum stability, zero memory leaks, and a perfectly reliable "fail-secure" environment.

## 🤝 Contributing & Bug Reports

Contributions, feature requests, and bug reports are highly welcome!
* **Found a bug?** The Windows process architecture can be tricky across different setups. Please open an **Issue** with steps to reproduce, and specify your Windows version.
* **Want to contribute?** Feel free to fork the repository, create a feature branch, and submit a **Pull Request**.

## 📄 License

This project is licensed under the [MIT License](LICENSE).

----------

*Created by [@osmanonurkoc](https://osmanonurkoc.com)*
