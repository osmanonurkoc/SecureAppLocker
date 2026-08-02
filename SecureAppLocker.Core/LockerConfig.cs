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

    public class LockerConfig
    {
        public List<AppLockRule> ProtectedApps { get; set; } = new List<AppLockRule>();
        public string UnlockMode { get; set; } = "AppSpecific";
        public int TimeoutMinutes { get; set; } = 5;
        public int PollingIntervalMs { get; set; } = 300;
        public string MasterPasswordHash { get; set; } = string.Empty;
        public string EncryptedRecoveryCode { get; set; } = string.Empty;
        public bool IsActive { get; set; } = true;
    }
}
