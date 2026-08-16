using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;

namespace SecureAppLocker.UI
{
	public partial class App : Application
	{
		private MainWindow? _mainWindow;

		public App()
		{
			this.InitializeComponent();
			this.UnhandledException += App_UnhandledException;
		}

		protected override void OnLaunched(LaunchActivatedEventArgs args)
		{
			base.OnLaunched(args);

			var dispatcherQueue = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();

			// Initialize the main window to keep the application alive.
			_mainWindow = new MainWindow();
			_mainWindow.Activate();

			// Run persistent background listener in the user session
			string[] cmdArgs = Environment.GetCommandLineArgs();
			bool isManualRun = cmdArgs.Any(a => a.Equals("--trusted-run", StringComparison.OrdinalIgnoreCase));

			if (!isManualRun)
			{
				_mainWindow.AppWindow.Hide();
				Task.Run(() => StartPersistentListenerAsync(dispatcherQueue));
			}
			else
			{
				_mainWindow.AppWindow.Show();
			}
		}

		private async Task StartPersistentListenerAsync(Microsoft.UI.Dispatching.DispatcherQueue dispatcherQueue)
		{
			var pipeSecurity = new PipeSecurity();
			pipeSecurity.AddAccessRule(new PipeAccessRule(
				new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
				PipeAccessRights.ReadWrite,
				AccessControlType.Allow));
			pipeSecurity.AddAccessRule(new PipeAccessRule(
				new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
				PipeAccessRights.FullControl,
				AccessControlType.Allow));

			while (true)
			{
				try
				{
					using var server = NamedPipeServerStreamAcl.Create(
						"SecureAppLocker_TriggerPipe",
						PipeDirection.In,
						NamedPipeServerStream.MaxAllowedServerInstances,
						PipeTransmissionMode.Message,
						PipeOptions.Asynchronous,
						0, 0, pipeSecurity);

					await server.WaitForConnectionAsync();

					using var reader = new StreamReader(server);
					string? message = await reader.ReadLineAsync();

					if (!string.IsNullOrEmpty(message) && message.StartsWith("TRIGGER|"))
					{
						var parts = message.Split('|');
						if (parts.Length >= 3)
						{
							string appKey = parts[1];
							string targetPath = parts[2];

							string displayName = Path.GetFileNameWithoutExtension(targetPath);
							try
							{
								if (File.Exists(targetPath))
								{
									var versionInfo = FileVersionInfo.GetVersionInfo(targetPath);
									if (!string.IsNullOrEmpty(versionInfo.FileDescription))
									{
										displayName = versionInfo.FileDescription;
									}
								}
							}
							catch { }

							dispatcherQueue?.TryEnqueue(() =>
							{
								if (_mainWindow == null)
								{
									_mainWindow = new MainWindow();
								}
								
								_mainWindow.UpdatePrompt(appKey, displayName, targetPath);
								
								// Bring the window to the foreground
								_mainWindow.AppWindow.Show();
								_mainWindow.Activate();
							});
						}
					}
				}
				catch (UnauthorizedAccessException)
				{
					return;
				}
				catch (Exception ex)
				{
					File.AppendAllText("ui_crash.log", $"[{DateTime.Now}] Exception: {ex}\n");
					await Task.Delay(500);
				}
			}
		}
		
		private void App_UnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
		{
			File.AppendAllText("ui_crash.log", $"[{DateTime.Now}] Unhandled XAML Exception: {e.Exception}\n");
		}
	}
}