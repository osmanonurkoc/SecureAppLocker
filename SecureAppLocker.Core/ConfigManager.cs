using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecureAppLocker.Core
{
    public static class ConfigManager
    {
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SecureAppLocker_DPAPI_Entropy_2026");

        public static readonly System.Text.Json.JsonSerializerOptions JsonOptions = new System.Text.Json.JsonSerializerOptions
        {
            TypeInfoResolver = new System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver(),
            WriteIndented = false
        };

        public static string GetConfigFilePath()
        {
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string appFolder = Path.Combine(programData, "SecureAppLocker");
            
            if (!Directory.Exists(appFolder))
            {
                Directory.CreateDirectory(appFolder);
            }
            
            return Path.Combine(appFolder, "config.dat");
        }

        public static void EnforceSecurityACLs()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                bool isSystemOrAdmin = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator) || 
                                       principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.SystemOperator) ||
                                       identity.IsSystem;

                if (!isSystemOrAdmin)
                {
                    // If not running elevated or as SYSTEM, we cannot manipulate ACLs. Return gracefully.
                    return;
                }

                string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string appFolder = Path.Combine(programData, "SecureAppLocker");
                string configFile = Path.Combine(appFolder, "config.dat");

                if (!Directory.Exists(appFolder))
                    Directory.CreateDirectory(appFolder);

                // Directory Security using .NET 8 extensions
                var dInfo = new DirectoryInfo(appFolder);
                var dSecurity = dInfo.GetAccessControl();
                dSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

                dSecurity.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                dSecurity.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                dSecurity.AddAccessRule(new FileSystemAccessRule(usersSid, FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                
                dInfo.SetAccessControl(dSecurity);

                // File Security
                if (File.Exists(configFile))
                {
                    var fInfo = new FileInfo(configFile);
                    var fSecurity = fInfo.GetAccessControl();
                    fSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                    fSecurity.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
                    fSecurity.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));
                    fSecurity.AddAccessRule(new FileSystemAccessRule(usersSid, FileSystemRights.Read, AccessControlType.Allow));
                    fInfo.SetAccessControl(fSecurity);
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Gracefully degrade if somehow permissions are strictly blocked despite elevation
            }
        }

        public static LockerConfig LoadConfig()
        {
            string configPath = GetConfigFilePath();

            if (!File.Exists(configPath))
            {
                return CreateDefaultConfig(configPath);
            }

            try
            {
                string json = File.ReadAllText(configPath);
                var config = JsonSerializer.Deserialize<LockerConfig>(json, JsonOptions);
                if (config == null || string.IsNullOrEmpty(config.MasterPasswordHash))
                {
                    return CreateDefaultConfig(configPath);
                }
                return config;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading config: {ex.Message}");
                return CreateDefaultConfig(configPath);
            }
        }

        public static void SaveConfigLocal(LockerConfig config)
        {
            string path = GetConfigFilePath();
            string json = System.Text.Json.JsonSerializer.Serialize(config, JsonOptions);

            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            // CRITICAL: Strip Read-Only or Hidden attributes if they exist to prevent UnauthorizedAccessException
            if (File.Exists(path))
            {
                var attributes = File.GetAttributes(path);
                if ((attributes & (FileAttributes.ReadOnly | FileAttributes.Hidden)) != 0)
                {
                    File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly & ~FileAttributes.Hidden);
                }
            }

            // Safely write the contents
            File.WriteAllText(path, json);
        }

        public static async Task<bool> SaveConfigViaIPCAsync(LockerConfig config)
        {
            // DO NOT use a try-catch block here. Let the exceptions bubble up to the UI!
            
            // CRITICAL: Ensure the pipe name is EXACTLY "SecureAppLocker_ConfigPipe"
            using var pipeClient = new NamedPipeClientStream(
                ".", 
                "SecureAppLocker_ConfigPipe", 
                PipeDirection.InOut, 
                PipeOptions.Asynchronous);
            
            // If it fails to connect within 2 seconds, it will throw a TimeoutException
            await pipeClient.ConnectAsync(2000); 

            using var reader = new StreamReader(pipeClient);
            using var writer = new StreamWriter(pipeClient) { AutoFlush = true };

            string jsonPayload = System.Text.Json.JsonSerializer.Serialize(config, JsonOptions);
            await writer.WriteLineAsync($"UPDATE_CONFIG|{jsonPayload}");
            
            string? response = await reader.ReadLineAsync();
            
            if (response == "SUCCESS")
            {
                return true;
            }
            
            throw new Exception($"Server rejected the config. Response: {response}");
        }

        private static LockerConfig CreateDefaultConfig(string configPath)
        {
            var defaultConfig = new LockerConfig();
            // Intentionally empty. User must add apps.

            var hashData = CryptoHelper.HashPassword("1234");
            defaultConfig.MasterPasswordHash = hashData.Hash;
            defaultConfig.MasterPasswordSalt = hashData.Salt;

            try
            {
                SaveConfigLocal(defaultConfig);
            }
            catch
            {
                // UI process may fail to write due to ACL. Ignored, service will heal it.
            }
            return defaultConfig;
        }
    }
}
