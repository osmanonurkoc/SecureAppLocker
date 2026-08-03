using System;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Collections.Generic;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Linq;
using SecureAppLocker.Core;

namespace SecureAppLocker.Service
{
	public class AppInfo
	{
		public string FilePath { get; set; } = string.Empty;
		public string DisplayName { get; set; } = string.Empty;
	}

	public class Worker : BackgroundService
	{
		[System.Runtime.InteropServices.DllImport("wtsapi32.dll", SetLastError = true)]
		private static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, int wtsInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);

		[System.Runtime.InteropServices.DllImport("wtsapi32.dll", SetLastError = false)]
		private static extern void WTSFreeMemory(IntPtr memory);

		[System.Runtime.InteropServices.DllImport("kernel32.dll")]
		private static extern int WTSGetActiveConsoleSessionId();

		private readonly ILogger<Worker> _logger;
		private FileSystemWatcher? _configWatcher;

		private readonly ConcurrentDictionary<string, DateTime> _authCache;
		private readonly ConcurrentDictionary<string, AppInfo> _pendingApps;
		private readonly ConcurrentDictionary<string, bool> _activePrompts;
		private readonly ConcurrentDictionary<int, byte> _knownPids;
		private readonly ConcurrentDictionary<int, string> _approvedPids;
		private readonly ConcurrentDictionary<int, bool> _safePids;
		private readonly object _promptLock = new object();

		private LockerConfig _appConfig = new LockerConfig();

		public Worker(ILogger<Worker> logger)
		{
			_logger = logger;
			_authCache = new ConcurrentDictionary<string, DateTime>();
			_pendingApps = new ConcurrentDictionary<string, AppInfo>();
			_activePrompts = new ConcurrentDictionary<string, bool>();
			_knownPids = new ConcurrentDictionary<int, byte>();
			_approvedPids = new ConcurrentDictionary<int, string>();
			_safePids = new ConcurrentDictionary<int, bool>();
		}

		private void LoadDynamicConfiguration()
		{
			try
			{
				string configPath = ConfigManager.GetConfigFilePath();
				if (!System.IO.File.Exists(configPath))
				{
					_logger.LogInformation("Config missing. Self-healing with default...");
					// Let LoadConfig handle default creation to ensure passwords are set
				}

				var newConfig = ConfigManager.LoadConfig();
				Interlocked.Exchange(ref _appConfig, newConfig);
				_logger.LogInformation($"Config loaded. Mode: {_appConfig.UnlockMode}, Protected Apps: {_appConfig.ProtectedApps.Count}");
			}
			catch (Exception ex)
			{
				_logger.LogError($"Failed to load config, self-healing... {ex.Message}");
				var defaultCfg = ConfigManager.LoadConfig(); // This will recreate the default config properly if it doesn't exist
				Interlocked.Exchange(ref _appConfig, defaultCfg);
			}
		}

		private void SetupConfigWatcher()
		{
			string configPath = ConfigManager.GetConfigFilePath();
			string directory = Path.GetDirectoryName(configPath) ?? string.Empty;
			string fileName = Path.GetFileName(configPath);

			_configWatcher = new FileSystemWatcher(directory, fileName)
			{
				NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime,
				EnableRaisingEvents = true
			};

			FileSystemEventHandler onConfigChanged = (s, e) =>
			{
				_logger.LogInformation("Config modification detected. Hot-reloading...");
				Thread.Sleep(300); // Give file time to close
				LoadDynamicConfiguration();
			};

			_configWatcher.Changed += onConfigChanged;
			_configWatcher.Created += onConfigChanged;
			
			_configWatcher.Renamed += (s, e) =>
			{
				_logger.LogInformation("Config file renamed. Hot-reloading...");
				Thread.Sleep(300);
				LoadDynamicConfiguration();
			};
		}

		protected override async Task ExecuteAsync(CancellationToken stoppingToken)
		{
			_logger.LogInformation("Locker Service started (Pure Session-Independent Pipe Mode).");

			try
			{
				ConfigManager.EnforceSecurityACLs();
				_logger.LogInformation("Security ACLs enforced on configuration directory.");
			}
			catch (Exception ex)
			{
				_logger.LogDebug($"Failed to enforce ACLs: {ex.Message}");
			}

			LoadDynamicConfiguration();
			SetupConfigWatcher();

			// 0. Start WTS Session Lock Watcher
			_ = Task.Run(() => StartSessionLockWatcherAsync(stoppingToken), stoppingToken);

			// 1. Start the micro-polling process interception watcher concurrently
			_ = Task.Run(() => StartProcessWatcherAsync(stoppingToken), stoppingToken);

			// 2. Start the Command Pipe (for SecureAppLocker.UI unlocks) concurrently
			_ = Task.Run(() => StartCommandPipeServerAsync(stoppingToken), stoppingToken);

			// 3. CRITICAL FIX: Start the Config Pipe (for SecureAppLocker.Manager) concurrently
			_ = Task.Run(() => StartConfigPipeServerAsync(stoppingToken), stoppingToken);

			// Keep the main worker thread alive
			try { await Task.Delay(Timeout.Infinite, stoppingToken); } catch (TaskCanceledException) { }
		}

		private async Task StartSessionLockWatcherAsync(CancellationToken token)
		{
			_logger.LogInformation("WTS Active Polling for Session Lock started.");
			bool wasLocked = false;
			
			while (!token.IsCancellationRequested)
			{
				bool isLocked = false;
				int sessionId = WTSGetActiveConsoleSessionId();
				
				if (sessionId != unchecked((int)0xFFFFFFFF))
				{
					IntPtr buffer = IntPtr.Zero;
					try
					{
						if (WTSQuerySessionInformation(IntPtr.Zero, sessionId, 25 /* WTSSessionInfoEx */, out buffer, out uint bytesReturned))
						{
							// SessionFlags is at offset 16 on 64-bit and 12 on 32-bit.
							int offset = IntPtr.Size == 8 ? 16 : 12;
							if (bytesReturned >= offset + 4)
							{
								int sessionFlags = System.Runtime.InteropServices.Marshal.ReadInt32(buffer, offset);
								if (sessionFlags == 1 /* WTS_SESSIONSTATE_LOCK */)
								{
									isLocked = true;
								}
							}
						}
					}
					catch (Exception ex)
					{
						_logger.LogDebug($"WTSQuerySessionInformation failed: {ex.Message}");
					}
					finally
					{
						if (buffer != IntPtr.Zero)
						{
							WTSFreeMemory(buffer);
						}
					}
				}

				if (isLocked && !wasLocked)
				{
					_logger.LogInformation("Windows Session Locked (WTS Polling). Invalidating all credential caches...");
					_authCache.Clear();
					_approvedPids.Clear();
				}
				
				wasLocked = isLocked;
				await Task.Delay(1000, token); // Poll every 1 second
			}
		}

		public override Task StopAsync(CancellationToken cancellationToken)
		{
			_configWatcher?.Dispose();
			_logger.LogInformation("Locker Service stopped securely.");
			return base.StopAsync(cancellationToken);
		}

		private async Task StartProcessWatcherAsync(CancellationToken token)
		{
			_logger.LogInformation("Hybrid Process Watcher started.");

			while (!token.IsCancellationRequested)
			{
				HashSet<int> currentTickPids = new HashSet<int>();
				var currentConfig = _appConfig;

				if (currentConfig.IsActive && currentConfig.ProtectedApps.Count > 0)
				{
					var activeApps = currentConfig.ProtectedApps.Where(a => a.IsEnabled).ToList();
					var allProcs = Process.GetProcesses();

					foreach (var p in allProcs)
					{
						currentTickPids.Add(p.Id);

						if (_safePids.ContainsKey(p.Id) || _knownPids.ContainsKey(p.Id))
							continue;

						bool isTarget = false;
						string matchedAppKey = string.Empty;
						string matchedProcName = p.ProcessName;

						var directMatch = activeApps.FirstOrDefault(a =>
							p.ProcessName.Equals(System.IO.Path.GetFileNameWithoutExtension(a.Name), StringComparison.OrdinalIgnoreCase));

						if (directMatch != null)
						{
							isTarget = true;
							matchedAppKey = System.IO.Path.GetFileNameWithoutExtension(directMatch.Name).ToLowerInvariant();
						}
						else
						{
							try
							{
								var module = p.MainModule;
								if (module != null)
								{
									string filePath = module.FileName;
									string fileName = System.IO.Path.GetFileName(filePath);
									var vi = module.FileVersionInfo;

									string originalName = vi.OriginalFilename ?? string.Empty;
									string productName = vi.ProductName ?? string.Empty;

									if (string.IsNullOrWhiteSpace(originalName) && string.IsNullOrWhiteSpace(productName))
									{
										originalName = fileName;
									}

									var metaMatch = activeApps.FirstOrDefault(a =>
										(!string.IsNullOrWhiteSpace(a.OriginalFileName) && originalName.Equals(a.OriginalFileName, StringComparison.OrdinalIgnoreCase)) ||
										(!string.IsNullOrWhiteSpace(a.ProductName) && productName.Equals(a.ProductName, StringComparison.OrdinalIgnoreCase)) ||
										(!string.IsNullOrWhiteSpace(a.Name) && fileName.Equals(a.Name, StringComparison.OrdinalIgnoreCase))
									);

									if (metaMatch != null)
									{
										isTarget = true;
										matchedAppKey = System.IO.Path.GetFileNameWithoutExtension(metaMatch.Name).ToLowerInvariant();
									}
								}
							}
							catch { }
						}

						if (isTarget)
						{
							_knownPids.TryAdd(p.Id, 1);
							HandleDetectedProcess(p, matchedAppKey, matchedProcName);
						}
						else
						{
							_safePids.TryAdd(p.Id, true);
						}
					}

					foreach (var p in allProcs) { p.Dispose(); }
				}

				foreach (var pid in _knownPids.Keys.ToList())
				{
					if (!currentTickPids.Contains(pid))
					{
						_knownPids.TryRemove(pid, out _);
						_approvedPids.TryRemove(pid, out _);
					}
				}

				foreach (var pid in _safePids.Keys.ToList())
				{
					if (!currentTickPids.Contains(pid))
					{
						_safePids.TryRemove(pid, out _);
					}
				}

				int delay = currentConfig.PollingIntervalMs >= 50 ? currentConfig.PollingIntervalMs : 300;
				await Task.Delay(delay, token);
			}
		}

		private void HandleDetectedProcess(Process p, string appKey, string procName)
		{
			try
			{
				if (p.HasExited) return;

				bool isGlobalUnlocked = string.Equals(_appConfig.UnlockMode, "Global", StringComparison.OrdinalIgnoreCase) &&
										_authCache.TryGetValue("GLOBAL_UNLOCK", out DateTime globalExpiry) &&
										DateTime.Now < globalExpiry;

				bool isAppUnlocked = _authCache.TryGetValue(appKey, out DateTime appExpiry) &&
									 DateTime.Now < appExpiry;

				bool isActiveAppImmunity = _approvedPids.Values.Contains(appKey);

				if (isGlobalUnlocked || isAppUnlocked || isActiveAppImmunity)
				{
					_approvedPids.TryAdd(p.Id, appKey);
					return;
				}

				lock (_promptLock)
				{
					bool blockPrompt = false;

					if (string.Equals(_appConfig.UnlockMode, "Global", StringComparison.OrdinalIgnoreCase))
					{
						if (_activePrompts.Count > 0) blockPrompt = true;
					}
					else
					{
						if (_activePrompts.ContainsKey(appKey)) blockPrompt = true;
					}

					if (blockPrompt)
					{
						p.Kill();
						return;
					}
				}

				string targetPath = procName;
				try
				{
					if (p.MainModule != null && !string.IsNullOrEmpty(p.MainModule.FileName))
					{
						targetPath = p.MainModule.FileName;
					}
				}
				catch { }

				p.Kill();
				_logger.LogInformation($"Process {procName} natively killed.");

				if (_appConfig.EnableLogging)
				{
					LogManager.WriteLog("KILLED", procName, $"Path: {targetPath}");
				}

				TriggerPasswordUI(appKey, targetPath);
			}
			catch (Exception ex)
			{
				_logger.LogDebug($"Failed to inspect or kill process {procName} (PID: {p.Id}): {ex.Message}");
			}
		}

		private void TriggerPasswordUI(string appKey, string targetPath)
		{
			// Mark the password prompt as triggered
			_activePrompts[appKey] = true;
			_pendingApps[appKey] = new AppInfo { FilePath = targetPath };

			Task.Run(async () =>
			{
				int maxRetries = 3;
				int currentRetry = 0;
				bool success = false;
				string message = $"TRIGGER|{appKey}|{targetPath}";

				while (currentRetry < maxRetries && !success)
				{
					using (var pipeClient = new NamedPipeClientStream(".", "SecureAppLocker_TriggerPipe", PipeDirection.Out, PipeOptions.Asynchronous))
					{
						try
						{
							await pipeClient.ConnectAsync(1500);

							using (var writer = new StreamWriter(pipeClient))
							{
								writer.AutoFlush = true;
								await writer.WriteLineAsync(message);
								success = true; 
								_logger.LogInformation($"UI triggered successfully via Named Pipe for {appKey}.");
							}
						}
						catch (TimeoutException)
						{
							currentRetry++;
							_logger.LogInformation($"UI companion not responding (Timeout). Retry {currentRetry}/{maxRetries}...");
							await Task.Delay(500); // Short delay before the next attempt
						}
						catch (Exception ex)
						{
							// Removed "break;". If the pipe doesn't exist (yet), it throws an exception; it should keep retrying.
							currentRetry++;
							_logger.LogError($"Failed to contact UI companion via pipe: {ex.Message}. Retry {currentRetry}/{maxRetries}...");
							await Task.Delay(500);
						}
					}
				}

				if (!success)
				{
					_logger.LogWarning($"Giving up on triggering UI for {appKey}. Clearing pending prompt state.");
					_activePrompts.TryRemove(appKey, out _);
					_pendingApps.TryRemove(appKey, out _);
				}
			});
		}

		private PipeSecurity CreateCommonPipeSecurity()
		{
			var pipeSecurity = new PipeSecurity();
			
			// CRITICAL: Block all incoming LAN connections
			pipeSecurity.AddAccessRule(new PipeAccessRule(
				new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
				PipeAccessRights.FullControl,
				AccessControlType.Deny));

			// Allow Interactive Session 1 UI
			pipeSecurity.AddAccessRule(new PipeAccessRule(
				new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
				PipeAccessRights.ReadWrite,
				AccessControlType.Allow));

			// Allow NT Service / SYSTEM
			pipeSecurity.AddAccessRule(new PipeAccessRule(
				new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
				PipeAccessRights.FullControl,
				AccessControlType.Allow));

			return pipeSecurity;
		}

		private async Task StartCommandPipeServerAsync(CancellationToken stoppingToken)
		{
			var pipeSecurity = CreateCommonPipeSecurity();
			_logger.LogInformation("Command IPC Server is listening for UI signals on SecureAppLocker_CommandPipe.");

			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					var pipeServer = NamedPipeServerStreamAcl.Create(
						"SecureAppLocker_CommandPipe",
						PipeDirection.InOut,
						NamedPipeServerStream.MaxAllowedServerInstances,
						PipeTransmissionMode.Byte,
						PipeOptions.Asynchronous,
						4096, 4096, pipeSecurity);

					await pipeServer.WaitForConnectionAsync(stoppingToken);

					_ = Task.Run(async () =>
					{
						try
						{
							using (pipeServer)
							using (var reader = new StreamReader(pipeServer))
							using (var writer = new StreamWriter(pipeServer) { AutoFlush = true })
							{
								var request = await reader.ReadLineAsync();
								if (string.IsNullOrEmpty(request)) return;

								int separatorIndex = request.IndexOf('|');
								if (separatorIndex > 0)
								{
									string command = request.Substring(0, separatorIndex);

									if (command == "UNLOCK")
									{
										var parts = request.Split('|');
										if (parts.Length >= 3)
										{
											string appKey = parts[1].Trim().ToLowerInvariant();
											string password = parts[2];
											var currentConfig = _appConfig;

											bool isValid = false;
											try
											{
												byte[] encryptedBytes = Convert.FromBase64String(currentConfig.MasterPasswordHash);
												string decryptedPassword = CryptoHelper.UnprotectLocalData(encryptedBytes);
												isValid = (password == decryptedPassword);
											}
											catch (System.Security.Cryptography.CryptographicException)
											{
												isValid = false;
											}
											catch (Exception)
											{
												isValid = false;
											}

											if (isValid)
											{
												int timeout = currentConfig.TimeoutMinutes > 0 ? currentConfig.TimeoutMinutes : 5;

												if (string.Equals(currentConfig.UnlockMode, "Global", StringComparison.OrdinalIgnoreCase))
												{
													_authCache["GLOBAL_UNLOCK"] = DateTime.Now.AddMinutes(timeout);
													_logger.LogInformation($"GLOBAL Access Granted for {timeout} minutes.");
													if (currentConfig.EnableLogging) LogManager.WriteLog("UNLOCK_GLOBAL", "ALL", $"Timeout: {timeout}m");
												}
												else
												{
													_authCache[appKey] = DateTime.Now.AddMinutes(timeout);
													_logger.LogInformation($"Access Granted for {appKey} for {timeout} minutes.");
													if (currentConfig.EnableLogging) LogManager.WriteLog("UNLOCK_APP", appKey, $"Timeout: {timeout}m");
												}

												if (pipeServer.IsConnected)
												{
													await writer.WriteLineAsync("SUCCESS");
												}

												if (_pendingApps.TryRemove(appKey, out AppInfo? info))
												{
													_logger.LogInformation($"App unlock successful for {appKey}.");
												}

												_activePrompts.TryRemove(appKey, out _);
											}
											else
											{
												if (pipeServer.IsConnected)
												{
													await writer.WriteLineAsync("INVALID");
												}
												_logger.LogWarning($"Invalid password attempt for {appKey}.");
												if (currentConfig.EnableLogging) LogManager.WriteLog("INVALID_PASSWORD", appKey, "Wrong master password entered.");
											}
										}
									}
									else if (command == "CANCEL")
									{
										var parts = request.Split('|');
										if (parts.Length >= 2)
										{
											string appKey = parts[1];
											_pendingApps.TryRemove(appKey, out _);
											_activePrompts.TryRemove(appKey, out _);
											_logger.LogInformation($"Prompt cancelled by user. Lock cleared for: {appKey}");
										}
									}
								}
							}
						}
						catch (IOException ex)
						{
							if (!ex.Message.Contains("Pipe is broken", StringComparison.OrdinalIgnoreCase))
							{
								_logger.LogWarning($"UI client disconnected unexpectedly: {ex.Message}");
							}
						}
						catch (Exception ex)
						{
							_logger.LogError(ex, "UI client handler failed.");
						}
					}, stoppingToken);
				}
				catch (UnauthorizedAccessException uae)
				{
					_logger.LogError($"Command Server access denied: {uae.Message}");
					try { await Task.Delay(2000, stoppingToken); } catch { }
				}
				catch (OperationCanceledException) { break; }
				catch (Exception ex)
				{
					_logger.LogError($"Command Server connection error: {ex.GetType().Name} - {ex.Message}");
					try { await Task.Delay(2000, stoppingToken); } catch { }
				}
			}
		}

		private async Task StartConfigPipeServerAsync(CancellationToken stoppingToken)
		{
			var pipeSecurity = CreateCommonPipeSecurity();
			_logger.LogInformation("Config IPC Server is listening for Manager signals.");

			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					var pipeServer = NamedPipeServerStreamAcl.Create(
						"SecureAppLocker_ConfigPipe",
						PipeDirection.InOut,
						NamedPipeServerStream.MaxAllowedServerInstances,
						PipeTransmissionMode.Byte,
						PipeOptions.Asynchronous,
						4096, 4096, pipeSecurity);

					await pipeServer.WaitForConnectionAsync(stoppingToken);

					_ = Task.Run(async () =>
					{
						try
						{
							using (pipeServer)
							using (var reader = new StreamReader(pipeServer))
							using (var writer = new StreamWriter(pipeServer) { AutoFlush = true })
							{
								var request = await reader.ReadLineAsync();
								if (string.IsNullOrEmpty(request)) return;

								int separatorIndex = request.IndexOf('|');
								if (separatorIndex > 0)
								{
									string command = request.Substring(0, separatorIndex);

									if (command == "UPDATE_CONFIG")
									{
										try
										{
											string json = request.Substring(separatorIndex + 1);
											_logger.LogInformation($"[DEBUG] IPC Server: Received UPDATE_CONFIG with JSON length {json.Length}");
											var config = System.Text.Json.JsonSerializer.Deserialize<LockerConfig>(json, ConfigManager.JsonOptions);
											if (config != null)
											{
												ConfigManager.SaveConfigLocal(config);
												Interlocked.Exchange(ref _appConfig, config);
												_authCache.Clear();
												_approvedPids.Clear();
												_logger.LogInformation("Configuration updated securely via IPC.");
												if (pipeServer.IsConnected)
												{
													await writer.WriteLineAsync("SUCCESS");
												}
											}
										}
										catch (Exception ex)
										{
											_logger.LogError($"Failed to update config via IPC: {ex.Message}");
											if (pipeServer.IsConnected)
											{
												try { await writer.WriteLineAsync("ERROR"); } catch { }
											}
										}
									}
								}
							}
						}
						catch (IOException ex)
						{
							if (ex.Message.Contains("Pipe is broken", StringComparison.OrdinalIgnoreCase)) { }
							else _logger.LogWarning($"Manager client disconnected unexpectedly: {ex.Message}");
						}
						catch (Exception ex)
						{
							_logger.LogError(ex, "Manager client handler failed.");
						}
					}, stoppingToken);
				}
				catch (UnauthorizedAccessException uae)
				{
					_logger.LogError($"Config Server access denied: {uae.Message}");
					try { await Task.Delay(2000, stoppingToken); } catch { }
				}
				catch (OperationCanceledException) { break; }
				catch (Exception ex)
				{
					_logger.LogError($"Config Server connection error: {ex.GetType().Name} - {ex.Message}");
					try { await Task.Delay(2000, stoppingToken); } catch { }
				}
			}
		}
	}
}
