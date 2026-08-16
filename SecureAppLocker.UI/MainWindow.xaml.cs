using System;
using System.IO;
using System.IO.Pipes;
using System.Threading.Tasks;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;
using Windows.Graphics;
using WinRT.Interop;

namespace SecureAppLocker.UI
{
	public sealed partial class MainWindow : Window
	{
		private string _appKey = string.Empty;
		private string _targetPath = string.Empty;
		
		private bool _isTrustedRun = false;
		private bool _isElevated = false;

		public MainWindow()
		{
			this.InitializeComponent();
			
			// Taskbar Icon Injection
			var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
			Microsoft.UI.WindowId windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
			Microsoft.UI.Windowing.AppWindow appWindow = Microsoft.UI.Windowing.AppWindow.GetFromWindowId(windowId);
			appWindow.SetIcon("Assets\\logo.ico");

			this.SystemBackdrop = new Microsoft.UI.Xaml.Media.MicaBackdrop();
			CustomizeWindowStructure();
			this.Closed += MainWindow_Closed;

			ParseCommandLineArguments();
		}

		private void ParseCommandLineArguments()
		{
			string[] args = Environment.GetCommandLineArgs();
			for (int i = 0; i < args.Length; i++)
			{
				if (args[i].Equals("--elevated", StringComparison.OrdinalIgnoreCase))
				{
					_isElevated = true;
				}
				else if (args[i].Equals("--trusted-run", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
				{
					_isTrustedRun = true;
					string target = args[i + 1];
					UpdatePrompt("TRUSTED_RUN_MODE", Path.GetFileName(target), target);
				}
			}
		}

		public void UpdatePrompt(string appKey, string displayName, string targetPath)
		{
			_appKey = appKey;
			_targetPath = targetPath;
			
			if (_isTrustedRun && _isElevated)
			{
				AppPathText.Text = $"🛡️ [Elevated] {displayName}";
			}
			else
			{
				AppPathText.Text = displayName;
			}
			
			PasswordInput.Password = string.Empty;
			PasswordInput.Header = string.Empty;

			ExtractAndDisplayIcon(targetPath);
		}

		private async void ExtractAndDisplayIcon(string targetPath)
		{
			try
			{
				if (System.IO.File.Exists(targetPath))
				{
					using var sysIcon = System.Drawing.Icon.ExtractAssociatedIcon(targetPath);
					if (sysIcon != null)
					{
						using var bmp = sysIcon.ToBitmap();
						using var ms = new System.IO.MemoryStream();
						bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);

						using var memStream = new Windows.Storage.Streams.InMemoryRandomAccessStream();
						using var dataWriter = new Windows.Storage.Streams.DataWriter(memStream);
						dataWriter.WriteBytes(ms.ToArray());
						await dataWriter.StoreAsync();
						memStream.Seek(0);

						var bitmapImage = new Microsoft.UI.Xaml.Media.Imaging.BitmapImage();
						await bitmapImage.SetSourceAsync(memStream);

						AppIconImage.Source = bitmapImage;
						AppIconImage.Visibility = Visibility.Visible;
						DefaultLockIcon.Visibility = Visibility.Collapsed;
						return;
					}
				}
			}
			catch (Exception)
			{
				// Ignore and fallback to default lock icon
			}

			AppIconImage.Visibility = Visibility.Collapsed;
			DefaultLockIcon.Visibility = Visibility.Visible;
		}

		private void CustomizeWindowStructure()
		{
			IntPtr hWnd = WindowNative.GetWindowHandle(this);
			WindowId wndId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hWnd);
			AppWindow appWindow = AppWindow.GetFromWindowId(wndId);

			int width = 460;
			int height = 280;

			var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(wndId, Microsoft.UI.Windowing.DisplayAreaFallback.Primary);
			if (displayArea != null)
			{
				int x = (displayArea.WorkArea.Width - width) / 2;
				int y = (displayArea.WorkArea.Height - height) / 2;
				appWindow.MoveAndResize(new Windows.Graphics.RectInt32(x, y, width, height));
			}
			else
			{
				appWindow.Resize(new Windows.Graphics.SizeInt32 { Width = width, Height = height });
			}

			if (AppWindowTitleBar.IsCustomizationSupported())
			{
				var titleBar = appWindow.TitleBar;
				titleBar.ExtendsContentIntoTitleBar = true;
				titleBar.ButtonBackgroundColor = Microsoft.UI.Colors.Transparent;
			}
		}

		private void MainWindow_Closed(object sender, WindowEventArgs args)
		{
			args.Handled = true;
			SendIpcCommand($"CANCEL|{_appKey}");
			this.AppWindow.Hide();
			Environment.Exit(0);
		}

		private async void SubmitButton_Click(object sender, RoutedEventArgs e)
		{
			await VerifyPasswordAsync();
		}

		private async void PasswordInput_KeyDown(object sender, KeyRoutedEventArgs e)
		{
			if (e.Key == Windows.System.VirtualKey.Enter)
			{
				await VerifyPasswordAsync();
			}
		}

		private void CancelButton_Click(object sender, RoutedEventArgs e)
		{
			SendIpcCommand($"CANCEL|{_appKey}");
			this.AppWindow.Hide();
			Environment.Exit(0);
		}

		private async Task VerifyPasswordAsync()
		{
			string enteredPassword = PasswordInput.Password;
			if (string.IsNullOrEmpty(enteredPassword)) return;

			PasswordInput.IsEnabled = false;
			PasswordInput.Header = "Verifying...";
			
			string? response = null;

			try
			{
				using var client = new NamedPipeClientStream(".", "SecureAppLocker_CommandPipe", PipeDirection.InOut);
				await client.ConnectAsync(2000);

				using var writer = new StreamWriter(client) { AutoFlush = true };
				using var reader = new StreamReader(client);

				if (_isTrustedRun)
				{
					await writer.WriteLineAsync($"TRUSTED_RUN|{_targetPath}|{enteredPassword}");
				}
				else
				{
					await writer.WriteLineAsync($"UNLOCK|{_appKey}|{enteredPassword}");
				}
				
				response = await reader.ReadLineAsync();
			}
			catch (Exception)
			{
				// Network transport failed or pipe broke during dispose.
				// We ignore it here because we will evaluate the 'response' variable below.
			}

			// Handle the UI logic safely OUTSIDE the try-catch block
			PasswordInput.IsEnabled = true;

			if (response == "SUCCESS")
			{
				this.AppWindow.Hide();

				if (!string.IsNullOrEmpty(_targetPath) && File.Exists(_targetPath))
				{
					try
					{
						var psi = new System.Diagnostics.ProcessStartInfo
						{
							FileName = _targetPath,
							UseShellExecute = true,
							WorkingDirectory = Path.GetDirectoryName(_targetPath) ?? string.Empty
						};

						if (_isElevated)
						{
							psi.Verb = "runas";
						}

						System.Diagnostics.Process.Start(psi);
					}
					catch { }
				}
				
				Environment.Exit(0);
			}
			else if (response == "INVALID" || response == "FAIL")
			{
				PasswordInput.Password = string.Empty;
				PasswordInput.Header = new Microsoft.UI.Xaml.Controls.TextBlock { Text = "Incorrect password.", Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Red) };
			}
			else
			{
				// Covers TimeoutException, IOException, or completely null responses
				PasswordInput.Password = string.Empty;
				PasswordInput.Header = new Microsoft.UI.Xaml.Controls.TextBlock { Text = "Error contacting Service.", Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Red) };
			}
		}

		private void SendIpcCommand(string command)
		{
			if (string.IsNullOrEmpty(_appKey)) return;

			Task.Run(async () =>
			{
				try
				{
					using var client = new NamedPipeClientStream(".", "SecureAppLocker_CommandPipe", PipeDirection.Out);
					// Fast connection attempt, fails gracefully
					await client.ConnectAsync(2000);

					using var writer = new StreamWriter(client);
					writer.AutoFlush = true;
					await writer.WriteLineAsync(command);
				}
				catch (Exception) { }
			});
		}
	}
}