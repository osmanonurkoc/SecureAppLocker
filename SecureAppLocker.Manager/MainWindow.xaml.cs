using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Text;
using Microsoft.UI.Windowing;
using Windows.Graphics;
using WinRT.Interop;
using SecureAppLocker.Core;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace SecureAppLocker.Manager
{
    public sealed partial class MainWindow : Window
    {
        private LockerConfig _config = new LockerConfig();
        public ObservableCollection<AppLockRule> AppsList { get; set; } = new ObservableCollection<AppLockRule>();
        public ObservableCollection<AppLockRule> SystemAppsList { get; set; } = new ObservableCollection<AppLockRule>();
        public ObservableCollection<AuditLogEntry> AuditLogs { get; set; } = new ObservableCollection<AuditLogEntry>();
        public ObservableCollection<string> TrustedParentsList { get; set; } = new ObservableCollection<string>();
        public ObservableCollection<TrustedCommandRule> TrustedCommandsList { get; set; } = new ObservableCollection<TrustedCommandRule>();

        private readonly AppLockRule[] _systemTools = new AppLockRule[]
        {
            // Command Line & Terminals
            new AppLockRule { Name = "cmd.exe", OriginalFileName = "Cmd.Exe", IsEnabled = true },
            new AppLockRule { Name = "powershell.exe", OriginalFileName = "PowerShell.EXE", IsEnabled = true },
            new AppLockRule { Name = "pwsh.exe", OriginalFileName = "pwsh.dll", IsEnabled = true }, // PowerShell Core
            new AppLockRule { Name = "WindowsTerminal.exe", OriginalFileName = "WindowsTerminal.exe", IsEnabled = true },
            new AppLockRule { Name = "wt.exe", OriginalFileName = "wt.exe", IsEnabled = true }, // Windows Terminal Alias
            
            // Scripting Engines
            new AppLockRule { Name = "wscript.exe", OriginalFileName = "wscript.exe", IsEnabled = true },
            new AppLockRule { Name = "cscript.exe", OriginalFileName = "cscript.exe", IsEnabled = true },
            
            // System Management & Registry
            new AppLockRule { Name = "mmc.exe", OriginalFileName = "mmc.exe", IsEnabled = true },
            new AppLockRule { Name = "net.exe", OriginalFileName = "net.exe", IsEnabled = true },
            new AppLockRule { Name = "wmic.exe", OriginalFileName = "wmic.exe", IsEnabled = true }, // Legacy Support
            new AppLockRule { Name = "msconfig.exe", OriginalFileName = "msconfig.exe", IsEnabled = true },
            new AppLockRule { Name = "regedit.exe", OriginalFileName = "regedit.exe", IsEnabled = true }
        };

        private const string PasswordRegex = @"^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?/_""]+$";

        public MainWindow()
        {
            this.InitializeComponent();

            // Taskbar Icon Injection
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            Microsoft.UI.WindowId windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
            Microsoft.UI.Windowing.AppWindow appWindow = Microsoft.UI.Windowing.AppWindow.GetFromWindowId(windowId);
            appWindow.SetIcon("Assets\\logo.ico");

            this.SystemBackdrop = new Microsoft.UI.Xaml.Media.MicaBackdrop();
            AppsListView.ItemsSource = AppsList;
            
            CustomizeWindowStructure();

            this.Closed += (s, e) => { Environment.Exit(0); };

            LoadConfiguration();

            if (this.Content is FrameworkElement rootElement)
            {
                rootElement.Loaded += MainWindow_Loaded;
            }
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            if (this.Content is FrameworkElement rootElement)
            {
                rootElement.Loaded -= MainWindow_Loaded;
            }

            while (true)
            {
                var passwordBox = new PasswordBox { PlaceholderText = "Enter Master Password" };
                var errorTextBlock = new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Red), Visibility = Visibility.Collapsed, Margin = new Thickness(0, 8, 0, 0) };
                var stackPanel = new StackPanel { Children = { passwordBox, errorTextBlock } };

                var dialog = new ContentDialog
                {
                    Title = "Authentication Required",
                    Content = stackPanel,
                    PrimaryButtonText = "Login",
                    SecondaryButtonText = "Recover",
                    CloseButtonText = "Cancel",
                    DefaultButton = ContentDialogButton.Primary,
                    XamlRoot = this.Content.XamlRoot
                };

                bool isAuthenticated = false;
                dialog.Closing += (s, args) =>
                {
                    if (args.Result == ContentDialogResult.Primary && !isAuthenticated)
                    {
                        if (VerifyDPAPIPassword(passwordBox.Password, _config.MasterPasswordHash))
                        {
                            isAuthenticated = true;
                        }
                        else
                        {
                            args.Cancel = true;
                            passwordBox.Password = string.Empty;
                            errorTextBlock.Text = "Invalid master password. Please try again.";
                            errorTextBlock.Visibility = Visibility.Visible;
                        }
                    }
                };

                var result = await dialog.ShowAsync();
                
                if (result == ContentDialogResult.Primary && isAuthenticated)
                {
                    MainRootGrid.Visibility = Visibility.Visible;
                    return;
                }
                else if (result == ContentDialogResult.Secondary)
                {
                    bool recovered = await ShowRecoveryDialogAsync();
                    if (recovered)
                    {
                        MainRootGrid.Visibility = Visibility.Visible;
                        return;
                    }
                }
                else
                {
                    Application.Current.Exit();
                    return;
                }
            }
        }

        private async Task<bool> ShowRecoveryDialogAsync()
        {
            var recoveryCodeBox = new TextBox { PlaceholderText = "Enter Recovery Key (SAL-XXXX...)", Margin = new Thickness(0, 0, 0, 8) };
            var newPasswordBox = new PasswordBox { PlaceholderText = "Enter New Master Password", Margin = new Thickness(0, 0, 0, 8) };
            var confirmPasswordBox = new PasswordBox { PlaceholderText = "Confirm New Master Password" };
            var errorTextBlock = new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Red), Visibility = Visibility.Collapsed, Margin = new Thickness(0, 8, 0, 0) };
            var stackPanel = new StackPanel { Children = { recoveryCodeBox, newPasswordBox, confirmPasswordBox, errorTextBlock } };

            var dialog = new ContentDialog
            {
                Title = "Offline Master Password Recovery",
                Content = stackPanel,
                PrimaryButtonText = "Reset Password",
                CloseButtonText = "Back to Login",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = this.Content.XamlRoot
            };

            bool isRecovered = false;
            dialog.Closing += async (s, args) =>
            {
                if (args.Result == ContentDialogResult.Primary && !isRecovered)
                {
                    var deferral = args.GetDeferral();
                    args.Cancel = true;

                    if (string.IsNullOrEmpty(_config.EncryptedRecoveryCode))
                    {
                        errorTextBlock.Text = "No recovery key was ever generated.";
                        errorTextBlock.Visibility = Visibility.Visible;
                        deferral.Complete();
                        return;
                    }

                    if (!VerifyDPAPIPassword(recoveryCodeBox.Text.Trim(), _config.EncryptedRecoveryCode))
                    {
                        errorTextBlock.Text = "Invalid recovery key. Please check and try again.";
                        errorTextBlock.Visibility = Visibility.Visible;
                        deferral.Complete();
                        return;
                    }

                    if (string.IsNullOrEmpty(newPasswordBox.Password) || newPasswordBox.Password != confirmPasswordBox.Password)
                    {
                        errorTextBlock.Text = "New passwords do not match or are empty.";
                        errorTextBlock.Visibility = Visibility.Visible;
                        deferral.Complete();
                        return;
                    }

                    var tempConfig = ConfigManager.LoadConfig();
                    tempConfig.TimeoutMinutes = _config.TimeoutMinutes;
                    tempConfig.PollingIntervalMs = _config.PollingIntervalMs;
                    tempConfig.UnlockMode = _config.UnlockMode;
                    tempConfig.IsActive = _config.IsActive;
                    tempConfig.EnableLogging = _config.EnableLogging;
                    tempConfig.ProtectedApps = _config.ProtectedApps.ToList();
                    tempConfig.TrustedParents = _config.TrustedParents.ToList();
                    tempConfig.TrustedCommands = _config.TrustedCommands.ToList();

                    tempConfig.MasterPasswordHash = HashDPAPIPassword(newPasswordBox.Password);

                    bool success = await ConfigManager.SaveConfigViaIPCAsync(tempConfig);
                    if (success)
                    {
                        _config = tempConfig;
                        isRecovered = true;
                        dialog.Hide();
                    }
                    else
                    {
                        errorTextBlock.Text = "Failed to save configuration via IPC.";
                        errorTextBlock.Visibility = Visibility.Visible;
                    }
                    deferral.Complete();
                }
            };

            await dialog.ShowAsync();
            if (isRecovered)
            {
                ShowSuccess("Master Password reset successfully via Recovery Key.");
            }
            return isRecovered;
        }

        private void CustomizeWindowStructure()
        {
            IntPtr hWnd = WindowNative.GetWindowHandle(this);
            WindowId wndId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hWnd);
            AppWindow appWindow = AppWindow.GetFromWindowId(wndId);

            int width = 450;
            int height = 750;

            var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(wndId, Microsoft.UI.Windowing.DisplayAreaFallback.Primary);
            if (displayArea != null)
            {
                int x = (displayArea.WorkArea.Width - width) / 2;
                int y = (displayArea.WorkArea.Height - height) / 2;
                appWindow.MoveAndResize(new RectInt32(x, y, width, height));
            }
            else
            {
                appWindow.Resize(new SizeInt32 { Width = width, Height = height });
            }

            if (AppWindowTitleBar.IsCustomizationSupported())
            {
                var titleBar = appWindow.TitleBar;
                titleBar.ExtendsContentIntoTitleBar = true;
                titleBar.ButtonBackgroundColor = Microsoft.UI.Colors.Transparent;
            }
        }

        private void LoadConfiguration()
        {
            _config = ConfigManager.LoadConfig();

            if (DeactivateSwitch != null) DeactivateSwitch.IsOn = _config.IsActive;
            if (EnableLoggingSwitch != null) EnableLoggingSwitch.IsOn = _config.EnableLogging;

            AppsList.Clear();
            SystemAppsList.Clear();

            foreach (var app in _config.ProtectedApps)
            {
                if (_systemTools.Any(st => st.Name.Equals(app.Name, StringComparison.OrdinalIgnoreCase)))
                    SystemAppsList.Add(app);
                else
                    AppsList.Add(app);
            }

            TrustedParentsList.Clear();
            foreach (var p in _config.TrustedParents) TrustedParentsList.Add(p);

            TrustedCommandsList.Clear();
            foreach (var c in _config.TrustedCommands) TrustedCommandsList.Add(c);

            if (HardeningSwitch != null)
            {
                bool allLocked = _systemTools.All(tool =>
                _config.ProtectedApps.Any(app => app.Name.Equals(tool.Name, StringComparison.OrdinalIgnoreCase)));

                HardeningSwitch.Toggled -= HardeningSwitch_Toggled;
                HardeningSwitch.IsOn = allLocked;

                if (SystemToolsContainer != null)
                    SystemToolsContainer.Visibility = allLocked ? Visibility.Visible : Visibility.Collapsed;

                HardeningSwitch.Toggled += HardeningSwitch_Toggled;
            }

            if (_config.UnlockMode == "Global")
                UnlockModeRadioButtons.SelectedIndex = 1;
            else
                UnlockModeRadioButtons.SelectedIndex = 0;

            TimeoutNumberBox.Value = _config.TimeoutMinutes >= 0 ? _config.TimeoutMinutes : 5;
            PollingIntervalBox.Value = _config.PollingIntervalMs > 0 ? _config.PollingIntervalMs : 300;

            bool isDefaultPassword = VerifyDPAPIPassword("1234", _config.MasterPasswordHash);
            if (isDefaultPassword)
            {
                OldPasswordBox.Visibility = Visibility.Collapsed;
                ShowInfo("First time setup: Please set a new Master Password.");
            }
            else
            {
                OldPasswordBox.Visibility = Visibility.Visible;
            }
        }

        private bool IsMatchWithWildcard(string pattern, string target)
        {
            if (string.IsNullOrWhiteSpace(pattern) || string.IsNullOrWhiteSpace(target)) return false;
            
            if (pattern.EndsWith("*") && pattern.StartsWith("*") && pattern.Length > 2)
                return target.Contains(pattern.Trim('*'), StringComparison.OrdinalIgnoreCase);
            
            if (pattern.EndsWith("*"))
                return target.StartsWith(pattern.TrimEnd('*'), StringComparison.OrdinalIgnoreCase);
            
            if (pattern.StartsWith("*"))
                return target.EndsWith(pattern.TrimStart('*'), StringComparison.OrdinalIgnoreCase);
            
            return target.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        }

        private void LoadAuditLogs()
        {
            AuditLogs.Clear();
            try
            {
                string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string auditFile = System.IO.Path.Combine(programData, "SecureAppLocker", "AuditLog.json");
                if (System.IO.File.Exists(auditFile))
                {
                    string json = System.IO.File.ReadAllText(auditFile);
                    var logs = System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.List<AuditLogEntry>>(json, ConfigManager.JsonOptions);
                    if (logs != null)
                    {
                        var filteredLogs = logs.Where(l => 
                            !_config.TrustedParents.Any(tp => IsMatchWithWildcard(tp, l.ParentProcess)) &&
                            !_config.TrustedCommands.Any(tc => 
                                (string.IsNullOrWhiteSpace(tc.ParentProcess) || IsMatchWithWildcard(tc.ParentProcess, l.ParentProcess)) &&
                                (!string.IsNullOrWhiteSpace(tc.CommandSnippet) && l.CommandLine.Contains(tc.CommandSnippet, StringComparison.OrdinalIgnoreCase)))
                        ).ToList();

                        var uniqueLogs = filteredLogs
                            .GroupBy(l => new { l.AppKey, l.ParentProcess, l.CommandLine })
                            .Select(g => g.OrderByDescending(x => x.Timestamp).First())
                            .OrderByDescending(l => l.Timestamp)
                            .ToList();

                        foreach (var log in uniqueLogs)
                        {
                            AuditLogs.Add(log);
                        }
                        
                        var listToSave = AuditLogs.ToList();
                        System.IO.File.WriteAllText(auditFile, System.Text.Json.JsonSerializer.Serialize(listToSave, ConfigManager.JsonOptions));
                    }
                }
            }
            catch { }
        }

        private void SaveAuditLogs()
        {
            try
            {
                string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string auditFile = System.IO.Path.Combine(programData, "SecureAppLocker", "AuditLog.json");
                var listToSave = AuditLogs.ToList();
                System.IO.File.WriteAllText(auditFile, System.Text.Json.JsonSerializer.Serialize(listToSave, ConfigManager.JsonOptions));
            }
            catch { }
        }

        private async void TrustParent_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string parentProcess)
            {
                if (!string.IsNullOrWhiteSpace(parentProcess) && !_config.TrustedParents.Contains(parentProcess, StringComparer.OrdinalIgnoreCase))
                {
                    _config.TrustedParents.Add(parentProcess);
                    TrustedParentsList.Add(parentProcess);

                    var toRemove = AuditLogs.Where(l => IsMatchWithWildcard(parentProcess, l.ParentProcess)).ToList();
                    foreach (var item in toRemove)
                    {
                        AuditLogs.Remove(item);
                    }
                    SaveAuditLogs();

                    await SaveConfigAndNotifyAsync($"'{parentProcess}' added to trusted parents.");
                }
                else if (_config.TrustedParents.Contains(parentProcess, StringComparer.OrdinalIgnoreCase))
                {
                    ShowInfo($"'{parentProcess}' is already trusted.");
                }
            }
        }

        private async void UntrustParent_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string parentProcess)
            {
                var item = _config.TrustedParents.FirstOrDefault(x => x.Equals(parentProcess, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    _config.TrustedParents.Remove(item);
                }
                
                var uiItem = TrustedParentsList.FirstOrDefault(x => x.Equals(parentProcess, StringComparison.OrdinalIgnoreCase));
                if (uiItem != null)
                {
                    TrustedParentsList.Remove(uiItem);
                }

                await SaveConfigAndNotifyAsync($"'{parentProcess}' removed from trusted parents.");
            }
        }

        private async void TrustCommand_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is AuditLogEntry logEntry)
            {
                var textBox = new TextBox 
                { 
                    Text = logEntry.CommandLine, 
                    TextWrapping = TextWrapping.Wrap, 
                    AcceptsReturn = true, 
                    Height = 100 
                };
                
                var parentTextBox = new TextBox
                {
                    Text = logEntry.ParentProcess,
                    Margin = new Thickness(0, 0, 0, 8)
                };

                var stackPanel = new StackPanel { Spacing = 8 };
                stackPanel.Children.Add(new TextBlock { Text = "Parent Process (Supports * wildcard):", FontWeight = FontWeights.SemiBold });
                stackPanel.Children.Add(parentTextBox);
                
                stackPanel.Children.Add(new TextBlock { Text = "Command Snippet:", FontWeight = FontWeights.SemiBold });
                stackPanel.Children.Add(new TextBlock 
                { 
                    Text = "Dynamic parameters like random session IDs or pipe names change on every launch. Please trim the command snippet below to a static, unique keyword (e.g. 'xdm-app-host.exe') so it can match future executions.", 
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray),
                    FontSize = 12
                });
                stackPanel.Children.Add(textBox);

                var dialog = new ContentDialog
                {
                    Title = "Trust Command Snippet",
                    Content = stackPanel,
                    PrimaryButtonText = "Trust Snippet",
                    CloseButtonText = "Cancel",
                    DefaultButton = ContentDialogButton.Primary,
                    XamlRoot = this.Content.XamlRoot
                };

                var result = await dialog.ShowAsync();
                if (result == ContentDialogResult.Primary)
                {
                    string snippet = textBox.Text.Trim();
                    string parent = parentTextBox.Text.Trim();
                    
                    if (!string.IsNullOrWhiteSpace(snippet))
                    {
                        var rule = new TrustedCommandRule { ParentProcess = parent, CommandSnippet = snippet };
                        
                        if (!_config.TrustedCommands.Any(r => r.ParentProcess == rule.ParentProcess && r.CommandSnippet == rule.CommandSnippet))
                        {
                            _config.TrustedCommands.Add(rule);
                            TrustedCommandsList.Add(rule);
                            
                            var toRemove = AuditLogs.Where(l => IsMatchWithWildcard(rule.ParentProcess, l.ParentProcess) && l.CommandLine.Contains(rule.CommandSnippet, StringComparison.OrdinalIgnoreCase)).ToList();
                            foreach (var item in toRemove)
                            {
                                AuditLogs.Remove(item);
                            }
                            SaveAuditLogs();

                            await SaveConfigAndNotifyAsync("Command rule added to trusted list.");
                        }
                        else
                        {
                            ShowInfo("This command rule is already trusted.");
                        }
                    }
                }
            }
        }

        private async void EditCommand_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is TrustedCommandRule rule)
            {
                var textBox = new TextBox 
                { 
                    Text = rule.CommandSnippet, 
                    TextWrapping = TextWrapping.Wrap, 
                    AcceptsReturn = true, 
                    Height = 100 
                };
                
                var parentTextBox = new TextBox
                {
                    Text = rule.ParentProcess,
                    Margin = new Thickness(0, 0, 0, 8)
                };

                var stackPanel = new StackPanel { Spacing = 8 };
                stackPanel.Children.Add(new TextBlock { Text = "Parent Process (Supports * wildcard):", FontWeight = FontWeights.SemiBold });
                stackPanel.Children.Add(parentTextBox);
                
                stackPanel.Children.Add(new TextBlock { Text = "Command Snippet:", FontWeight = FontWeights.SemiBold });
                stackPanel.Children.Add(new TextBlock 
                { 
                    Text = "Edit the command snippet. Keep only the static, unique keywords to match future executions.", 
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray),
                    FontSize = 12
                });
                stackPanel.Children.Add(textBox);

                var dialog = new ContentDialog
                {
                    Title = "Edit Trusted Rule",
                    Content = stackPanel,
                    PrimaryButtonText = "Save Changes",
                    CloseButtonText = "Cancel",
                    DefaultButton = ContentDialogButton.Primary,
                    XamlRoot = this.Content.XamlRoot
                };

                var result = await dialog.ShowAsync();
                if (result == ContentDialogResult.Primary)
                {
                    string newSnippet = textBox.Text.Trim();
                    string newParent = parentTextBox.Text.Trim();
                    
                    if (!string.IsNullOrWhiteSpace(newSnippet))
                    {
                        var configItem = _config.TrustedCommands.FirstOrDefault(x => x.ParentProcess == rule.ParentProcess && x.CommandSnippet == rule.CommandSnippet);
                        if (configItem != null)
                        {
                            configItem.ParentProcess = newParent;
                            configItem.CommandSnippet = newSnippet;
                        }

                        var uiItem = TrustedCommandsList.FirstOrDefault(x => x.ParentProcess == rule.ParentProcess && x.CommandSnippet == rule.CommandSnippet);
                        if (uiItem != null)
                        {
                            int index = TrustedCommandsList.IndexOf(uiItem);
                            TrustedCommandsList[index] = new TrustedCommandRule { ParentProcess = newParent, CommandSnippet = newSnippet };
                        }

                        await SaveConfigAndNotifyAsync("Command rule updated successfully.");
                        LoadAuditLogs();
                    }
                }
            }
        }

        private async void UntrustCommand_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is TrustedCommandRule rule)
            {
                var item = _config.TrustedCommands.FirstOrDefault(x => x.ParentProcess == rule.ParentProcess && x.CommandSnippet == rule.CommandSnippet);
                if (item != null)
                {
                    _config.TrustedCommands.Remove(item);
                }
                
                var uiItem = TrustedCommandsList.FirstOrDefault(x => x.ParentProcess == rule.ParentProcess && x.CommandSnippet == rule.CommandSnippet);
                if (uiItem != null)
                {
                    TrustedCommandsList.Remove(uiItem);
                }

                await SaveConfigAndNotifyAsync("Command rule removed from trusted list.");
            }
        }
        
        private void RefreshAuditLogs_Click(object sender, RoutedEventArgs e)
        {
            LoadAuditLogs();
            ShowInfo("Audit logs refreshed.");
        }

        private void SegmentedToggle_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Microsoft.UI.Xaml.Controls.Primitives.ToggleButton clickedToggle)
            {
                NavApps.IsChecked = clickedToggle == NavApps;
                NavSecurity.IsChecked = clickedToggle == NavSecurity;
                NavPassword.IsChecked = clickedToggle == NavPassword;
                
                var navAudit = MainRootGrid.FindName("NavAudit") as ToggleButton;
                if (navAudit != null) navAudit.IsChecked = clickedToggle == navAudit;

                AppsPage.Visibility = Visibility.Collapsed;
                SecurityPage.Visibility = Visibility.Collapsed;
                PasswordPage.Visibility = Visibility.Collapsed;
                
                var auditPage = MainRootGrid.FindName("AuditPage") as StackPanel;
                if (auditPage != null) auditPage.Visibility = Visibility.Collapsed;
                
                StatusInfoBar.IsOpen = false;

                switch (clickedToggle.Tag?.ToString())
                {
                    case "Apps": AppsPage.Visibility = Visibility.Visible; break;
                    case "Security": SecurityPage.Visibility = Visibility.Visible; break;
                    case "Password": PasswordPage.Visibility = Visibility.Visible; break;
                    case "Audit": 
                        LoadAuditLogs();
                        if (auditPage != null) auditPage.Visibility = Visibility.Visible;
                        break;
                }
            }
        }

        // Win32 Native File Dialog implementation to bypass WinUI 3 Elevation/Admin limits
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class OpenFileName
        {
            public int lStructSize = Marshal.SizeOf(typeof(OpenFileName));
            public IntPtr hwndOwner = IntPtr.Zero;
            public IntPtr hInstance = IntPtr.Zero;
            public string? lpstrFilter = null;
            public string? lpstrCustomFilter = null;
            public int nMaxCustFilter = 0;
            public int nFilterIndex = 0;
            public string? lpstrFile = null;
            public int nMaxFile = 0;
            public string? lpstrFileTitle = null;
            public int nMaxFileTitle = 0;
            public string? lpstrInitialDir = null;
            public string? lpstrTitle = null;
            public int Flags = 0;
            public short nFileOffset = 0;
            public short nFileExtension = 0;
            public string? lpstrDefExt = null;
            public IntPtr lCustData = IntPtr.Zero;
            public IntPtr lpfnHook = IntPtr.Zero;
            public string? lpTemplateName = null;
            public IntPtr pvReserved = IntPtr.Zero;
            public int dwReserved = 0;
            public int flagsEx = 0;
        }

        [DllImport("comdlg32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool GetOpenFileName([In, Out] OpenFileName ofn);

        private void BrowseApp_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
                
                var ofn = new OpenFileName();
                ofn.hwndOwner = hwnd;
                
                // Native filters use \0 as separators and must end with \0\0
                ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
                
                // Pre-allocate buffer for the selected file path (2048 to prevent buffer overflow)
                ofn.lpstrFile = new string(new char[2048]);
                ofn.nMaxFile = ofn.lpstrFile.Length;
                ofn.lpstrTitle = "Select Application to Lock";
                
                // OFN_EXPLORER (0x00080000) | OFN_FILEMUSTEXIST (0x00001000)
                ofn.Flags = 0x00081000; 

                if (GetOpenFileName(ofn))
                {
                    // Clean the returned string by stripping out the null terminators
                    string filePath = ofn.lpstrFile;
                    int nullIndex = filePath.IndexOf('\0');
                    if (nullIndex >= 0) 
                    {
                        filePath = filePath.Substring(0, nullIndex);
                    }

                    string fileName = System.IO.Path.GetFileName(filePath);

                    // File selected, extract metadata (OriginalFilename, ProductName)
                    var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
                    
                    string originalName = versionInfo.OriginalFilename ?? string.Empty;
                    string productName = versionInfo.ProductName ?? string.Empty;

                    if (productName.Contains("Windows", StringComparison.OrdinalIgnoreCase) && 
                        productName.Contains("Operating System", StringComparison.OrdinalIgnoreCase))
                    {
                        productName = string.Empty;
                    }
                    
                    // Fallback: If the developer left metadata empty, use the raw file name directly.
                    if (string.IsNullOrWhiteSpace(originalName) && string.IsNullOrWhiteSpace(productName))
                    {
                        originalName = fileName;
                    }

                    bool isDuplicate = AppsList.Any(x => 
                                           x.Name.Equals(fileName, StringComparison.OrdinalIgnoreCase) || 
                                           (!string.IsNullOrEmpty(originalName) && !string.IsNullOrEmpty(x.OriginalFileName) && x.OriginalFileName.Equals(originalName, StringComparison.OrdinalIgnoreCase))) 
                                       || 
                                       SystemAppsList.Any(x => 
                                           x.Name.Equals(fileName, StringComparison.OrdinalIgnoreCase) || 
                                           (!string.IsNullOrEmpty(originalName) && !string.IsNullOrEmpty(x.OriginalFileName) && x.OriginalFileName.Equals(originalName, StringComparison.OrdinalIgnoreCase)));

                    if (!isDuplicate)
                    {
                        AppsList.Add(new AppLockRule 
                        { 
                            Name = fileName, 
                            OriginalFileName = originalName, 
                            ProductName = productName, 
                            IsEnabled = true 
                        });
                    }
                    else
                    {
                        ShowInfo($"{fileName} is already in the protection list.");
                    }
                }
            }
            catch (Exception ex)
            {
                ShowError($"Failed to open file picker or read metadata: {ex.Message}");
            }
        }

        private void RemoveApp_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is AppLockRule appRule)
            {
                AppsList.Remove(appRule);
            }
        }

        private async void SaveApps_Click(object sender, RoutedEventArgs e)
        {
            _config.ProtectedApps = AppsList.Concat(SystemAppsList)
                                            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                                            .Select(g => g.First())
                                            .ToList();
            await SaveConfigAndNotifyAsync();
        }

        private async void HardeningSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            if (_config == null || HardeningSwitch == null || SystemToolsContainer == null) return;

            bool isEnabled = HardeningSwitch.IsOn;
            SystemAppsList.Clear();

            if (isEnabled)
            {
                var duplicates = AppsList.Where(a => _systemTools.Any(st => st.Name.Equals(a.Name, StringComparison.OrdinalIgnoreCase))).ToList();
                foreach (var dup in duplicates)
                {
                    AppsList.Remove(dup);
                }

                foreach (var tool in _systemTools)
                {
                    SystemAppsList.Add(new AppLockRule
                    {
                        Name = tool.Name,
                        OriginalFileName = tool.OriginalFileName,
                        IsEnabled = true
                    });
                }
            }

            SystemToolsContainer.Visibility = isEnabled ? Visibility.Visible : Visibility.Collapsed;

            _config.ProtectedApps = AppsList.Concat(SystemAppsList)
                                            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                                            .Select(g => g.First())
                                            .ToList();

            await SaveConfigAndNotifyAsync(isEnabled ? "System Hardening Enabled: OS tools are locked." : "System Hardening Disabled.");
        }

        private async void SaveSettings_Click(object sender, RoutedEventArgs e)
        {
            StatusInfoBar.IsOpen = false;

            var selectedRadio = UnlockModeRadioButtons.SelectedItem as RadioButton;
            if (selectedRadio != null && selectedRadio.Tag != null)
                _config.UnlockMode = selectedRadio.Tag.ToString() ?? "AppSpecific";

            _config.TimeoutMinutes = (int)TimeoutNumberBox.Value;
            _config.PollingIntervalMs = (int)PollingIntervalBox.Value;
            _config.EnableLogging = EnableLoggingSwitch.IsOn;
            await SaveConfigAndNotifyAsync("Security Settings saved successfully.");
        }

        private async void UpdatePassword_Click(object sender, RoutedEventArgs e)
        {
            StatusInfoBar.IsOpen = false;

            string oldPass = OldPasswordBox.Password;
            string newPass = NewPasswordBox.Password;
            string confirmPass = ConfirmPasswordBox.Password;

            if (string.IsNullOrEmpty(newPass))
            {
                ShowError("New password cannot be empty.");
                return;
            }

            if (newPass != confirmPass)
            {
                ShowError("New passwords do not match.");
                return;
            }

            if (!Regex.IsMatch(newPass, PasswordRegex))
            {
                ShowError("Password contains invalid characters. Use only English letters, numbers, and standard punctuation.");
                return;
            }

            bool isDefaultPassword = VerifyDPAPIPassword("1234", _config.MasterPasswordHash);
            if (!isDefaultPassword && !VerifyDPAPIPassword(oldPass, _config.MasterPasswordHash))
            {
                ShowError("Incorrect current password.");
                return;
            }

            var tempConfig = ConfigManager.LoadConfig();
            tempConfig.TimeoutMinutes = _config.TimeoutMinutes;
            tempConfig.PollingIntervalMs = _config.PollingIntervalMs;
            tempConfig.UnlockMode = _config.UnlockMode;
            tempConfig.IsActive = _config.IsActive;
            tempConfig.EnableLogging = _config.EnableLogging;
            tempConfig.ProtectedApps = _config.ProtectedApps.ToList();
            tempConfig.TrustedParents = _config.TrustedParents.ToList();
            tempConfig.TrustedCommands = _config.TrustedCommands.ToList();

            tempConfig.MasterPasswordHash = HashDPAPIPassword(newPass);

            string recoveryCode = GenerateRecoveryCode();
            tempConfig.EncryptedRecoveryCode = HashDPAPIPassword(recoveryCode);

            try
            {
                bool success = await ConfigManager.SaveConfigViaIPCAsync(tempConfig);
                if (!success) throw new Exception("Service IPC returned failure.");

                _config = tempConfig;

                OldPasswordBox.Password = string.Empty;
                NewPasswordBox.Password = string.Empty;
                ConfirmPasswordBox.Password = string.Empty;
                LoadConfiguration();

                await ShowRecoveryKeyDialogAsync("Recovery Code Generated", recoveryCode, "Your offline recovery code is:");
                ShowSuccess("Master Password updated successfully.");
            }
            catch (Exception ex)
            {
                ShowError($"Failed to save configuration: {ex.Message}");
            }
        }

        private async Task ShowRecoveryKeyDialogAsync(string title, string recoveryCode, string subtitle)
        {
            var codeTextBox = new TextBox { Text = recoveryCode, IsReadOnly = true, Margin = new Thickness(0, 8, 8, 0), HorizontalAlignment = HorizontalAlignment.Stretch };
            var copyBtn = new Button { Content = "Copy to Clipboard", Margin = new Thickness(0, 8, 0, 0) };
            copyBtn.Click += (s, e) =>
            {
                var dp = new Windows.ApplicationModel.DataTransfer.DataPackage();
                dp.SetText(recoveryCode);
                Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(dp);
                copyBtn.Content = "Copied!";
            };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            Grid.SetColumn(codeTextBox, 0);
            Grid.SetColumn(copyBtn, 1);
            grid.Children.Add(codeTextBox);
            grid.Children.Add(copyBtn);

            var stackPanel = new StackPanel 
            { 
                Children = 
                { 
                    new TextBlock { Text = $"{subtitle}\n\nPlease save this securely offline. You will need it to reset your password if you forget it.", TextWrapping = TextWrapping.Wrap }, 
                    grid 
                } 
            };

            ContentDialog dialog = new ContentDialog
            {
                Title = title,
                Content = stackPanel,
                CloseButtonText = "I have saved it",
                XamlRoot = this.Content.XamlRoot
            };
            await dialog.ShowAsync();
        }

        private async void ViewRecovery_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_config.EncryptedRecoveryCode))
            {
                ShowError("No recovery key available to view. Please change your master password to generate one.");
                return;
            }

            var passwordBox = new PasswordBox { PlaceholderText = "Enter Master Password" };
            var errorTextBlock = new TextBlock { Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Red), Visibility = Visibility.Collapsed, Margin = new Thickness(0, 8, 0, 0) };
            var stackPanel = new StackPanel { Children = { new TextBlock { Text = "Verify your Master Password to view your recovery key.", Margin = new Thickness(0, 0, 0, 8) }, passwordBox, errorTextBlock } };

            var dialog = new ContentDialog
            {
                Title = "Verify Password",
                Content = stackPanel,
                PrimaryButtonText = "Verify",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = this.Content.XamlRoot
            };

            bool isValid = false;
            dialog.Closing += (s, args) =>
            {
                if (args.Result == ContentDialogResult.Primary && !isValid)
                {
                    if (VerifyDPAPIPassword(passwordBox.Password, _config.MasterPasswordHash))
                    {
                        isValid = true;
                    }
                    else
                    {
                        args.Cancel = true;
                        passwordBox.Password = string.Empty;
                        errorTextBlock.Text = "Incorrect password. Please try again.";
                        errorTextBlock.Visibility = Visibility.Visible;
                    }
                }
            };

            var result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary && isValid)
            {
                try
                {
                    byte[] encryptedBytes = Convert.FromBase64String(_config.EncryptedRecoveryCode);
                    string recoveryCode = CryptoHelper.UnprotectLocalData(encryptedBytes);
                    
                    await ShowRecoveryKeyDialogAsync("Recovery Key Backup", recoveryCode, "Your current recovery code is:");
                }
                catch (Exception ex)
                {
                    ShowError($"Failed to decrypt recovery key: {ex.Message}");
                }
            }
        }

        private string GenerateRecoveryCode()
        {
            var random = new Random();
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, 16).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private async System.Threading.Tasks.Task SaveConfigAndNotifyAsync(string message = "Configuration saved successfully.")
        {
            try
            {
                var freshConfig = ConfigManager.LoadConfig();
                freshConfig.TimeoutMinutes = _config.TimeoutMinutes;
                freshConfig.PollingIntervalMs = _config.PollingIntervalMs;
                freshConfig.UnlockMode = _config.UnlockMode;
                freshConfig.IsActive = _config.IsActive;
                freshConfig.EnableLogging = _config.EnableLogging;
                freshConfig.ProtectedApps = _config.ProtectedApps.ToList();
                freshConfig.TrustedParents = _config.TrustedParents.ToList();
                freshConfig.TrustedCommands = _config.TrustedCommands.ToList();

                bool success = await ConfigManager.SaveConfigViaIPCAsync(freshConfig);
                if (success)
                    ShowSuccess(message);
                else
                    ShowError("Failed to save configuration via IPC. Service might be unavailable.");
            }
            catch (Exception ex)
            {
                ShowError($"Failed to save configuration: {ex.Message}");
            }
        }

        private void ShowError(string message)
        {
            StatusInfoBar.Severity = InfoBarSeverity.Error;
            StatusInfoBar.Message = message;
            StatusInfoBar.IsOpen = true;
        }

        private void ShowSuccess(string message)
        {
            StatusInfoBar.Severity = InfoBarSeverity.Success;
            StatusInfoBar.Message = message;
            StatusInfoBar.IsOpen = true;
        }

        private void ShowInfo(string message)
        {
            StatusInfoBar.Severity = InfoBarSeverity.Warning; 
            StatusInfoBar.Message = message;
            StatusInfoBar.IsOpen = true;
        }

        private async void DeactivateSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            if (_config == null || DeactivateSwitch == null) return;
            
            if (_config.IsActive != DeactivateSwitch.IsOn)
            {
                _config.IsActive = DeactivateSwitch.IsOn;
                await SaveConfigAndNotifyAsync(_config.IsActive ? "Protection Activated." : "Protection Deactivated.");
            }
        }

        // --- DPAPI Helper Methods ---
        private bool VerifyDPAPIPassword(string input, string base64Hash)
        {
            if (string.IsNullOrEmpty(base64Hash)) return false;
            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(base64Hash);
                string decrypted = CryptoHelper.UnprotectLocalData(encryptedBytes);
                return input == decrypted;
            }
            catch
            {
                return false;
            }
        }

        private string HashDPAPIPassword(string input)
        {
            byte[] encryptedBytes = CryptoHelper.ProtectLocalData(input);
            return Convert.ToBase64String(encryptedBytes);
        }
    }
}