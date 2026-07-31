using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace SecureAppLocker.Core
{
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Action { get; set; } = string.Empty;
        public string AppName { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
    }

    public static class LogManager
    {
        public static string GetLogFilePath()
        {
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string appFolder = Path.Combine(programData, "SecureAppLocker");
            return Path.Combine(appFolder, "audit.log");
        }

        public static void WriteLog(string action, string appName, string details)
        {
            try
            {
                string logPath = GetLogFilePath();
                var entry = new LogEntry
                {
                    Timestamp = DateTime.Now,
                    Action = action,
                    AppName = appName,
                    Details = details
                };

                string jsonLine = JsonSerializer.Serialize(entry, ConfigManager.JsonOptions);
                
                // Use a lock-free or file-share-aware append
                using (var fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                using (var writer = new StreamWriter(fs))
                {
                    writer.WriteLine(jsonLine);
                }

                EnforceLogSecurity(logPath);
            }
            catch { /* Fail silently to not crash the service */ }
        }

        private static void EnforceLogSecurity(string path)
        {
            try
            {
                var fInfo = new FileInfo(path);
                var fSecurity = fInfo.GetAccessControl();
                
                // Protect from inheritance
                fSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

                // SYSTEM and Admins can do everything
                fSecurity.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
                fSecurity.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));
                
                // Users can only READ (they can't delete the evidence)
                fSecurity.AddAccessRule(new FileSystemAccessRule(usersSid, FileSystemRights.Read, AccessControlType.Allow));
                
                fInfo.SetAccessControl(fSecurity);
            }
            catch { }
        }
    }
}