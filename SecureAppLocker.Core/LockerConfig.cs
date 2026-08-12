using System;
using System.Collections.Generic;

namespace SecureAppLocker.Core
{
    public class AppLockRule
    {
        public string Name { get; set; } = string.Empty;
        public bool IsEnabled { get; set; } = true;
        public string OriginalFileName { get; set; } = string.Empty;
        public string ProductName { get; set; } = string.Empty;
    }

    public class AuditLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string AppKey { get; set; } = string.Empty;
        public string ParentProcess { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
    }

    public class TrustedCommandRule
    {
        public string ParentProcess { get; set; } = string.Empty;
        public string CommandSnippet { get; set; } = string.Empty;
    }

    public class LockerConfig
    {
        public List<AppLockRule> ProtectedApps { get; set; } = new List<AppLockRule>();
        public List<string> TrustedParents { get; set; } = new List<string>();
        
        public List<TrustedCommandRule> TrustedCommands { get; set; } = new List<TrustedCommandRule>();
        
        public string UnlockMode { get; set; } = "AppSpecific";
        public int TimeoutMinutes { get; set; } = 5;
        public int PollingIntervalMs { get; set; } = 300;
        public string MasterPasswordHash { get; set; } = string.Empty;
        public string EncryptedRecoveryCode { get; set; } = string.Empty;
        public bool IsActive { get; set; } = true;
        public bool EnableLogging { get; set; } = true;
    }
}
