using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using Common.DeviceDetection;
using Common.Host;
using Common.Internal;
using Contract.Central;
using Microsoft.Win32;
using Razer.AccountManager;
using Razer.ActionService;

namespace Common.RazerCentral.Accounts
{
    public class AccountsManager : IAccounts
    {
        private enum ServiceInitStatus
        {
            UNINITIALIZED,
            PENDING,
            INITIALIZED
        }

        private readonly ITextLogger _logger;

        private readonly IProcessExtensions _processExtensions;

        private readonly IServiceStatus _serviceStatus;

        private readonly ISystemEvents _systemEvents;

        private readonly IDeviceDetection _deviceDetection;

        private readonly IApplicationNotication _applicationNotification;

        private AccountManagerClient _accountManager;

        private volatile ServiceInitStatus _accountManagerInit;

        private volatile SettingSourceEnum _settingSourceEnum = SettingSourceEnum.Undefined;

        private volatile SyncStatus _lastSyncStatus = SyncStatus.Failed_Unknown;

        private ConcurrentBag<DataSyncItemInfo> _conflictItems = new ConcurrentBag<DataSyncItemInfo>();

        private volatile bool _bSyncActivity;

        private volatile bool _bIsAccountLoggedIn;

        private volatile bool _bWindowsLoggedin = true;

        private readonly IThreadSafeList<PluggedDevice> _pluggedDevices;

        private readonly IEnumerable<IDeviceInstance> _deviceInstances;

        private bool m_bWindowsUserTokenAvailable;

        private System.Timers.Timer _syncTimer;

        private volatile bool _bOngoingSync;

        private volatile bool _bIsInitialSyncOn;

        private volatile Dictionary<string, bool> ExitSynapseList = new Dictionary<string, bool>();

        private volatile bool _bLocked;

        private readonly List<string> _commonPaths = new List<string> {"Macros", "LightingPack", "AppSettings", "GlobalShortcuts", "LinkedGames", "LinkedLightPackGames", "Data"};

        private readonly object _lock = new object();

        private readonly object _uiLock = new object();

        private RazerUser _RzUser;

        private bool _bFirstLogin = true;

        private bool IsExitSynapse
        {
            get
            {
                string systemUser = GetSystemUser();
                if (ExitSynapseList.ContainsKey(systemUser))
                {
                    return ExitSynapseList[systemUser];
                }

                ExitSynapseList.Add(systemUser, value: false);
                return false;
            }
            set
            {
                string systemUser = GetSystemUser();
                if (ExitSynapseList.ContainsKey(systemUser))
                {
                    ExitSynapseList[systemUser] = value;
                }
                else
                {
                    ExitSynapseList.Add(systemUser, value: false);
                }
            }
        }

        private List<string> InitialSyncPaths { get; set; } = new List<string>();


        private List<string> InitialSystemSyncPaths { get; set; } = new List<string>();


        public event OnLoginStateChanged LoginComplete;

        public event OnLogoutStateChanged LogoutStarted;

        public event OnLogoutStateChanged LogoutComplete;

        public event OnLogoutStateChanged PostLogoutComplete;

        public event OnSyncProgressDelegate OnSyncProgress;

        public event OnSyncCompleteDelegate OnSyncComplete;

        public event OnSyncCompleteDelegate OnSyncCompleteSR;

        public event OnUserSettingsChangedDelegate OnInitLoadUserSettings;

        public event OnUserSettingsChangedDelegate OnPreLoadUserSettings;

        public event OnUserSettingsChangedDelegate OnCompletedPreLoadUserSettings;

        public event OnUserSettingsChangedDelegate OnAccountInitialized;

        public event OnUserSettingsChangedDelegate OnPostLoadUserSettings;

        public event OnUserSettingsChangedDelegate OnCompletedPostLoadUserSettings;

        public event OnUserSettingsChangedDelegate OnPostLoadUserSettingsSR;

        public event OnUserProfileLoadedDelegate OnUserProfileLoaded;

        public event OnInitialSyncEvalCompleteDelegate OnInitialSyncEvalCompleteEvent;

        public AccountsManager(ITextLogger logger, IDeviceDetection deviceDetection, IProcessExtensions processExtensions, IServiceStatus serviceStatus, ISystemEvents systemEvents, IApplicationNotication applicationNotication, IThreadSafeList<PluggedDevice> pluggedDevices, IEnumerable<IDeviceInstance> deviceInstances)
        {
            _logger = logger;
            _deviceDetection = deviceDetection;
            _processExtensions = processExtensions;
            _serviceStatus = serviceStatus;
            _systemEvents = systemEvents;
            _applicationNotification = applicationNotication;
            _pluggedDevices = pluggedDevices;
            _deviceInstances = deviceInstances;
            _deviceDetection.PreDeviceAdded += _deviceDetection_PreDeviceAdded;
            _deviceDetection.PreDeviceRemoved += _deviceDetection_PreDeviceRemoved;
            _deviceDetection.DeviceDetectionStopped += _deviceDetection_DeviceDetectionStopped;
            _serviceStatus.OnServiceStatusChangedEvent += _serviceStatus_OnServiceStatusChangedEvent;
            _systemEvents.OnSessionChangedEvent += _systemEvents_OnSessionChangedEvent;
            _systemEvents.OnPostPowerStatusChangedEvent += _systemEvents_OnPostPowerStatusChangedEvent;
            InitializeAccountManagerClient();
            _syncTimer = new System.Timers.Timer();
            bool result = false;
            if (bool.TryParse(ConfigurationManager.AppSettings["enable_sync"], out result) && result)
            {
                double result2 = 0.0;
                if (!double.TryParse(ConfigurationManager.AppSettings["sync_interval"], out result2))
                {
                    result2 = 300000.0;
                }

                _syncTimer.AutoReset = false;
                _syncTimer.Interval = result2;
                _syncTimer.Elapsed += _syncTimer_Elapsed;
            }
        }

        private void _deviceDetection_DeviceDetectionStopped()
        {
            _accountManagerInit = ServiceInitStatus.UNINITIALIZED;
            _RzUser = null;
        }

        private void _syncTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            StartSync();
        }

        private void _deviceDetection_PreDeviceAdded(PreDeviceDetection_EventArgs args)
        {
            new Task(delegate { RegisterPlugin(args); }).Start();
        }

        private void RegisterPlugin(PreDeviceDetection_EventArgs args)
        {
            if (!IsLoggedInUser(bRazerCentralOnly: true))
            {
                return;
            }

            _logger.Debug($"RegisterPlugin PID:{args.Device.PID} EID:{args.Device.EID} VID:{args.Device.VID}");
            IEnumerable<IDeviceInstance> deviceInstances = _deviceInstances;
            if (deviceInstances != null && !deviceInstances.Any((IDeviceInstance x) => x.Product_ID.Equals(args.Device.PID) && x.Edition_ID.Equals(args.Device.EID) && x.Vendor_ID.Equals(args.Device.VID)))
            {
                _logger.Debug($"RegisterPlugin PID:{args.Device.PID} EID:{args.Device.EID} VID:{args.Device.VID} not yet installed. Skipping RegisterPlugin.");
                return;
            }

            try
            {
                RazerDevice razerDevice = new RazerDevice(args.Device.PID, (byte) args.Device.EID, args.Device.VID);
                razerDevice.SerialNumber = args.Device.SERIAL;
                _accountManager?.RegisterPlugin(new List<RazerDevice> {razerDevice});
            }
            catch (Exception arg)
            {
                _logger.Error($"Exception occurred during RegisterPlugin {arg}");
            }
        }

        private void _deviceDetection_PreDeviceRemoved(PreDeviceDetection_EventArgs args)
        {
            new Task(delegate { RegisterUnplug(args); }).Start();
        }

        private void RegisterUnplug(PreDeviceDetection_EventArgs args)
        {
            if (!IsLoggedInUser(bRazerCentralOnly: true))
            {
                return;
            }

            _logger.Debug($"RegisterUnplug PID:{args.Device.PID} EID:{args.Device.EID} VID:{args.Device.VID}");
            IEnumerable<IDeviceInstance> deviceInstances = _deviceInstances;
            if (deviceInstances != null && !deviceInstances.Any((IDeviceInstance x) => x.Product_ID.Equals(args.Device.PID) && x.Edition_ID.Equals(args.Device.EID) && x.Vendor_ID.Equals(args.Device.VID)))
            {
                _logger.Debug($"RegisterUnplug PID:{args.Device.PID} EID:{args.Device.EID} VID:{args.Device.VID} not yet installed. Skipping RegisterUnplug.");
                return;
            }

            try
            {
                RazerDevice razerDevice = new RazerDevice(args.Device.PID, (byte) args.Device.EID, args.Device.VID);
                razerDevice.SerialNumber = args.Device.SERIAL;
                _accountManager?.RegisterUnplug(new List<RazerDevice> {razerDevice});
            }
            catch (Exception arg)
            {
                _logger.Error($"Exception occurred during RegisterUnplug {arg}");
            }
        }

        private void RegisterDevicePlugins()
        {
            if (_pluggedDevices.List.Count() <= 0)
            {
                return;
            }

            try
            {
                List<RazerDevice> list = new List<RazerDevice>();
                foreach (PluggedDevice device in _pluggedDevices.List)
                {
                    IEnumerable<IDeviceInstance> deviceInstances = _deviceInstances;
                    if (deviceInstances != null && !deviceInstances.Any((IDeviceInstance x) => x.Product_ID.Equals(device.PID) && x.Edition_ID.Equals(device.EID) && x.Vendor_ID.Equals(device.VID)))
                    {
                        _logger.Debug($"RegisterDevicePlugins PID:{device.PID} EID:{device.EID} VID:{device.VID} not yet installed. Skipping RegisterPlugin.");
                        continue;
                    }

                    RazerDevice razerDevice = new RazerDevice(device.PID, (byte) device.EID, device.VID);
                    razerDevice.SerialNumber = device.SERIAL;
                    list.Add(razerDevice);
                }

                _accountManager?.RegisterPlugin(list);
            }
            catch (Exception arg)
            {
                _logger.Error($"Exception occurred during RegisterPlugin {arg}");
            }
        }

        private void StartAutoRegistration()
        {
            try
            {
                _logger.Info("Starting Auto Registration.");
                _accountManager?.StartAutoRegistration();
                _logger.Info("Auto Registration Completed.");
            }
            catch (Exception arg)
            {
                _logger.Error($"Exception occurred during StartAutoRegistration {arg}");
            }
        }

        private void StopAutoRegistration()
        {
            try
            {
                _logger.Info("Stopping Auto Registration.");
                _accountManager?.StopAutoRegistration();
                _logger.Info("Auto Registration Stopped.");
            }
            catch (Exception arg)
            {
                _logger.Error($"Exception occurred during StopAutoRegistration {arg}");
            }
        }

        private void _serviceStatus_OnServiceStatusChangedEvent(ServiceStatus status)
        {
            if (status == ServiceStatus.Stopped)
            {
                try
                {
                    StopAutoRegistration();
                    UninitAccountManagerClient();
                }
                catch (Exception arg)
                {
                    _logger.Error($"Exception occurred during _serviceStatus_OnServiceStatusChangedEvent {arg}");
                }
            }
        }

        private void _systemEvents_OnSessionChangedEvent(SessionSwitchReason reason)
        {
            _logger.Debug($"AccountsManager OnSessionChangedEvent {reason}");
            switch (reason)
            {
                case SessionSwitchReason.ConsoleConnect:
                case SessionSwitchReason.SessionLogon:
                    _bWindowsLoggedin = true;
                    InitializeAccountManagerClient();
                    break;
                case SessionSwitchReason.ConsoleDisconnect:
                case SessionSwitchReason.SessionLogoff:
                    _bWindowsLoggedin = false;
                    m_bWindowsUserTokenAvailable = false;
                    UninitAccountManagerClient();
                    break;
                case SessionSwitchReason.SessionLock:
                    _applicationNotification.Notify("SessionLock");
                    _accountManagerInit = ServiceInitStatus.UNINITIALIZED;
                    _RzUser = null;
                    _bLocked = true;
                    break;
                case SessionSwitchReason.SessionUnlock:
                    _bLocked = false;
                    RefreshAccountSettings(UserSettingsChangedEnum.SessionUnlock);
                    break;
                case SessionSwitchReason.RemoteConnect:
                case SessionSwitchReason.RemoteDisconnect:
                    break;
            }
        }

        private void _systemEvents_OnPostPowerStatusChangedEvent(PowerModes powerStatus)
        {
            if (powerStatus == PowerModes.Resume)
            {
                _logger.Info($"_systemEvents_OnPostPowerStatusChangedEvent: _bLocked {_bLocked} _bWindowsLoggedin {_bWindowsLoggedin}");
                if (!_bLocked && _bWindowsLoggedin)
                {
                    RefreshAccountSettings(UserSettingsChangedEnum.PowerResume);
                }
            }
        }

        private void RefreshAccountSettings(UserSettingsChangedEnum status, bool bForce = false)
        {
            _logger.Info($"RefreshAccountSettings {status} IsAccountOnline {_bIsAccountLoggedIn} ExitSynapse {IsExitSynapse} Force {bForce}");
            if (bForce || (!IsExitSynapse && IsLoggedInUser(bRazerCentralOnly: true)))
            {
                if (_bFirstLogin)
                {
                    ShowLoginUI();
                }
                else
                {
                    HandleLoginEvent(SynapseLoginResult.Success);
                }
            }
        }

        private void InitializeAccountManagerClient()
        {
            lock (_lock)
            {
                _logger.Info("InitializeAccountManagerClient - Enter.");
                if (_accountManager == null)
                {
                    _logger.Info($"{RazerCentralProperties.ProjectName} {RazerCentralProperties.ProjectCode}");
                    _accountManager = new AccountManagerClient(RazerCentralProperties.ProjectName, RazerCentralProperties.ProjectCode);
                    _accountManager.LoginComplete += LoginCompleteHandler;
                    _accountManager.LogoutStarted += LogoutStartedHandler;
                    _accountManager.LogoutComplete += LogoutCompleteHandler;
                    _accountManager.UserProfileUpdated += UserProfileUpdated;
                    _accountManager.AccountConversionComplete += AccountConversionComplete;
                }

                _logger.Info("InitializeAccountManagerClient - Done.");
            }
        }

        private void UninitAccountManagerClient()
        {
            lock (_lock)
            {
                if (_accountManager != null)
                {
                    _accountManagerInit = ServiceInitStatus.UNINITIALIZED;
                    _RzUser = null;
                    CancelSync();
                    _accountManager.LoginComplete -= LoginCompleteHandler;
                    _accountManager.LogoutStarted -= LogoutStartedHandler;
                    _accountManager.LogoutComplete -= LogoutCompleteHandler;
                    _accountManager.UserProfileUpdated -= UserProfileUpdated;
                    _accountManager.AccountConversionComplete -= AccountConversionComplete;
                    _accountManager?.Dispose();
                    _accountManager = null;
                }
            }
        }

        private void UserProfileUpdated(object sender, UserProfileUpdatedEventArgs e)
        {
            if (e != null)
            {
                this.OnUserProfileLoaded?.Invoke();
            }
        }

        private void AccountConversionComplete(object sender, AccountConversionEventArgs e)
        {
            if (e != null)
            {
                _RzUser = _accountManager?.GetCurrentUser();
                bool flag = _RzUser != null;
                _logger.Debug($"AccountConversionComplete event received. Refreshing RzUser result {flag}");
                _applicationNotification?.Notify("accountconverted");
            }
            else
            {
                _logger.Error("AccountConversionComplete: e is null");
            }
        }

        private void LoginCompleteHandler(object sender, LoginEventArgs e)
        {
            _bFirstLogin = false;
            SynapseLoginResult result = (SynapseLoginResult) e.Result;
            if (result == SynapseLoginResult.Success || result == SynapseLoginResult.RefreshSucceeded)
            {
                _RzUser = _accountManager?.GetCurrentUser();
            }

            if (Process.GetProcessesByName("Razer Synapse 3").Length == 0 && Process.GetProcessesByName("Synapse3.TestClient").Length == 0)
            {
                _accountManagerInit = ServiceInitStatus.UNINITIALIZED;
                _logger.Info("LoginCompleteHandler: No Synapse 3 clients running. ignoring login event.");
                return;
            }

            try
            {
                IsExitSynapse = false;
                _logger.Info($"LoginCompleteHandler: Result-{result}");
                this.LoginComplete?.Invoke(new LoginAccountsEventArgs(result));
                _logger.Info("LoginCompleteHandler event done.");
                HandleLoginEvent(result);
            }
            catch (TimeoutException)
            {
                _logger.Error("Timeout waiting for response from the service.");
            }
            catch (IOException ex2)
            {
                _logger.Error("Failed to communicate with the service: " + ex2);
            }
            catch (Exception arg)
            {
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
            }
        }

        private void HandleLoginEvent(SynapseLoginResult result)
        {
            if (_accountManagerInit == ServiceInitStatus.PENDING)
            {
                _logger.Info($"HandleLoginEvent: status is in {_accountManagerInit} state.");
                return;
            }

            _logger.Info("HandleLoginEvent: Locking HandleLoginEvent event.");
            lock (_lock)
            {
                _logger.Info($"HandleLoginEvent: {result}");
                if (result != 0)
                {
                    return;
                }

                _accountManagerInit = ServiceInitStatus.PENDING;
                IsExitSynapse = false;
                _bIsAccountLoggedIn = true;
                new Task(StartAutoRegistration).Start();
                new Task(RegisterDevicePlugins).Start();
                _deviceDetection.Start(bMultiThread: false);
                if (_RzUser != null && (GetRazerUser()?.Online ?? false))
                {
                    if (_RzUser.IsGuest)
                    {
                        _logger.Info("HandleLoginEvent: User is guest, skipping initial sync.");
                        goto IL_013e;
                    }

                    if (!TriggerInitialSync())
                    {
                        goto IL_013e;
                    }

                    return;
                }

                if (_RzUser == null)
                {
                    _logger.Info("HandleLoginEvent: Not coming from login event.");
                }
                else
                {
                    _logger.Info("HandleLoginEvent: User is offline, skipping initial sync.");
                }

                goto IL_013e;
                IL_013e:
                NotifyUserSettings(UserSettingsChangedEnum.UserLogin);
            }
        }

        private void LogoutStartedHandler(object sender, LogoutEventArgs e)
        {
            try
            {
                _syncTimer?.Stop();
                _logger.Info($"LogoutStartedHandler: Reason-{e.Reason}");
                this.LogoutStarted?.Invoke(new LogoutAccountsEventArgs((SynapseLogoutReason) e.Reason));
            }
            catch (Exception arg)
            {
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
            }
        }

        private void LogoutCompleteHandler(object sender, LogoutEventArgs e)
        {
            try
            {
                bool isExitSynapse = IsExitSynapse;
                if (e.User == null)
                {
                    _logger.Info("LogoutCompleteHandler: User is null, this event is from Exit Synapse api.");
                    IsExitSynapse = true;
                }

                _logger.Info($"LogoutCompleteHandler: Reason-{e.Reason}");
                _bIsAccountLoggedIn = false;
                _RzUser = null;
                CancelSync();
                _accountManagerInit = ServiceInitStatus.UNINITIALIZED;
                _lastSyncStatus = SyncStatus.Failed_Unknown;
                _settingSourceEnum = SettingSourceEnum.Undefined;
                if (!isExitSynapse)
                {
                    this.LogoutComplete?.Invoke(new LogoutAccountsEventArgs((SynapseLogoutReason) e.Reason));
                    this.PostLogoutComplete?.Invoke(new LogoutAccountsEventArgs((SynapseLogoutReason) e.Reason));
                }
            }
            catch (Exception arg)
            {
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
            }
        }

        public bool TryLogin()
        {
            _logger.Info("TryLogin: Started.");
            bool result = false;
            bool flag = false;
            LoginResult loginResult = LoginResult.Failed;
            try
            {
                InitializeAccountManagerClient();
                if (Process.GetProcessesByName("RazerInstaller").Length != 0 && !IsLoggedInUser(bRazerCentralOnly: true))
                {
                    _logger.Info("TryLogin: LWI is running. abort...");
                    return false;
                }

                _logger.Info($"TryLogin: _bLocked {_bLocked} _bWindowsLoggedin {_bWindowsLoggedin}");
                if (!_bLocked && _bWindowsLoggedin && _accountManager != null)
                {
                    loginResult = _accountManager.TryLogin();
                    _logger.Info($"TryLogin returned {loginResult}");
                    result = true;
                }
            }
            catch (Exception arg)
            {
                flag = true;
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
                result = false;
            }

            if (loginResult == LoginResult.FailedNoCredentials || flag)
            {
                try
                {
                    _logger.Info("StartLogin started.");
                    _accountManager.StartLogin();
                    return result;
                }
                catch (Exception arg2)
                {
                    _logger.Error($"{arg2}: {MethodBase.GetCurrentMethod().Name}");
                    return false;
                }
            }

            return result;
        }

        public bool ShowLoginUI()
        {
            lock (_uiLock)
            {
                _logger.Info("ShowLoginUI: Started.");
                bool result = false;
                try
                {
                    InitializeAccountManagerClient();
                    if (_accountManager != null)
                    {
                        bool flag = IsLoggedInUser(bRazerCentralOnly: true);
                        if (!flag && _accountManagerInit.Equals(ServiceInitStatus.PENDING))
                        {
                            _logger.Info($"ShowLoginUI: status is in {_accountManagerInit} state.");
                            return true;
                        }

                        if (!flag || (_accountManagerInit.Equals(ServiceInitStatus.UNINITIALIZED) && !_bIsInitialSyncOn && !IsExitSynapse))
                        {
                            if (!flag || _bFirstLogin)
                            {
                                _logger.Info("StartUi: Calling StartLogin.");
                                _accountManager.StartLogin();
                            }
                            else
                            {
                                _logger.Info($"StartUi: RefreshAccountSettings ExitSynapse: {IsExitSynapse}.");
                                RefreshAccountSettings(UserSettingsChangedEnum.UserLogin, bForce: true);
                            }
                        }
                        else if (flag && _accountManagerInit.Equals(ServiceInitStatus.UNINITIALIZED) && !_bIsInitialSyncOn && IsExitSynapse)
                        {
                            _logger.Info($"StartUi: RefreshAccountSettings ExitSynapse: {IsExitSynapse}.");
                            RefreshAccountSettings(UserSettingsChangedEnum.UserLogin, bForce: true);
                        }
                        else if (IsLoggedInUser() && !_bIsInitialSyncOn)
                        {
                            _logger.Info("StartUi: OnPostLoadUserSettingsSR.");
                            this.OnPostLoadUserSettingsSR?.Invoke(UserSettingsChangedEnum.CloudSync);
                        }

                        result = true;
                        _logger.Info("StartUi: Successful.");
                    }
                    else
                    {
                        _logger.Warn("Account Manager is null");
                    }
                }
                catch (Exception arg)
                {
                    _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
                    result = false;
                }

                return result;
            }
        }

        private void LaunchNatasha()
        {
            Process[] processesByName = Process.GetProcessesByName("Razer Central");
            if (processesByName.Length == 0)
            {
                _logger.Info("LaunchNatasha: StartUi() - STARTED.");
                _accountManager.StartUi();
                _logger.Info("LaunchNatasha: StartUi() - DONE.");
            }
        }

        public bool Logout()
        {
            _logger.Info("Logout: Start.");
            bool flag = false;
            try
            {
                if (IsLoggedInUser(bRazerCentralOnly: true))
                {
                    _accountManager?.StartLogout();
                    flag = true;
                }
                else
                {
                    _logger.Warn("No user logged in");
                }
            }
            catch (Exception arg)
            {
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
                flag = false;
            }

            _logger.Info($"Logout: {flag} - End.");
            return flag;
        }

        public uint SetSettings(string path, string filename, byte[] contents)
        {
            uint result = 3u;
            try
            {
                if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(filename))
                {
                    return 3u;
                }

                RzSetting setting = new RzSetting(path, filename, contents);
                if (_accountManager != null)
                {
                    if (IsLoggedInUser())
                    {
                        SaveResult saveResult = _accountManager.SetSetting(setting, SettingSaveType.ServerAsync);
                        result = (uint) saveResult;
                        if (saveResult == SaveResult.Success)
                        {
                            ResetSyncTimer();
                            return result;
                        }

                        return result;
                    }

                    return result;
                }

                return result;
            }
            catch (Exception arg)
            {
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
                return 3u;
            }
        }

        public uint SetSettings(string path, string filename, byte[] contents, SettingSaveTypeEnum saveType)
        {
            uint result = 3u;
            try
            {
                if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(filename))
                {
                    return 3u;
                }

                RzSetting setting = new RzSetting(path, filename, contents);
                if (_accountManager != null)
                {
                    if (IsLoggedInUser())
                    {
                        SettingSaveType settingSaveType = SettingSaveType.LocalOnly;
                        SaveResult saveResult = _accountManager.SetSetting(setting, saveType switch
                        {
                            SettingSaveTypeEnum.LocalOnly => SettingSaveType.LocalOnly,
                            SettingSaveTypeEnum.Server => SettingSaveType.Server,
                            SettingSaveTypeEnum.ServerAsync => SettingSaveType.ServerAsync,
                            SettingSaveTypeEnum.Shared => SettingSaveType.Shared,
                            SettingSaveTypeEnum.Application => SettingSaveType.Application,
                            _ => SettingSaveType.LocalOnly,
                        });
                        result = (uint) saveResult;
                        if (saveResult == SaveResult.Success)
                        {
                            if (saveType == SettingSaveTypeEnum.ServerAsync)
                            {
                                ResetSyncTimer();
                                return result;
                            }

                            return result;
                        }

                        return result;
                    }

                    return result;
                }

                return result;
            }
            catch (Exception arg)
            {
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
                return 3u;
            }
        }

        public bool GetSettings(string path, string filename, ref byte[] contents)
        {
            bool result = false;
            try
            {
                if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(filename))
                {
                    return false;
                }

                RzSetting rzSetting = new RzSetting(path, filename, contents);
                if (_accountManager != null)
                {
                    if (IsLoggedInUser())
                    {
                        SettingReadResult setting = _accountManager.GetSetting(path, filename, SettingSource.Local);
                        if (setting != null)
                        {
                            if (setting.Success)
                            {
                                contents = setting.Setting.Value;
                                return setting.Success;
                            }

                            return result;
                        }

                        return result;
                    }

                    return result;
                }

                return result;
            }
            catch (TimeoutException arg)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name} Timeout waiting for response from the service: {arg}");
                return false;
            }
            catch (IOException arg2)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name} Failed to communicate with the service: {arg2}");
                return false;
            }
            catch (Exception arg3)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name}: {arg3}");
                return false;
            }
        }

        public bool GetSettingList(string path, string filenamePattern, ref List<string> filenames)
        {
            bool flag = false;
            try
            {
                if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(filenamePattern) || filenames == null)
                {
                    return false;
                }

                if (_accountManager != null && _bIsAccountLoggedIn)
                {
                    filenames.Clear();
                    foreach (SettingDefinition setting in _accountManager.GetSettingList(path, filenamePattern, SettingSource.Local))
                    {
                        filenames.Add($"{setting.Path}\\{setting.Name}");
                    }
                }

                return filenames.Count > 0;
            }
            catch (Exception arg)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name}: {arg}");
                return false;
            }
        }

        public IList<SettingDefinitionInfo> GetSettingList(string path, SettingSourceEnum settingSource)
        {
            List<SettingDefinitionInfo> settings = new List<SettingDefinitionInfo>();
            try
            {
                if (_accountManager != null && _bIsAccountLoggedIn)
                {
                    List<SettingDefinition> settingList = _accountManager.GetSettingList(path, (SettingSource) settingSource);
                    settingList.ForEach(delegate(SettingDefinition s) { settings.Add(new SettingDefinitionInfo(s.Name, s.Path, s.Timestamp)); });
                }
            }
            catch (Exception arg)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name}: {arg}");
            }

            return settings;
        }

        public IList<SettingDefinitionInfo> GetSettingList(string path, string name, SettingSourceEnum settingSource)
        {
            List<SettingDefinitionInfo> settings = new List<SettingDefinitionInfo>();
            try
            {
                if (_accountManager != null && _bIsAccountLoggedIn)
                {
                    List<SettingDefinition> settingList = _accountManager.GetSettingList(path, name, (SettingSource) settingSource);
                    settingList.ForEach(delegate(SettingDefinition s) { settings.Add(new SettingDefinitionInfo(s.Name, s.Path, s.Timestamp)); });
                }
            }
            catch (Exception arg)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name}: {arg}");
            }

            return settings;
        }

        public uint DeleteSettings(string path, string filename)
        {
            uint result = 3u;
            try
            {
                if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(filename))
                {
                    return 3u;
                }

                if (_accountManager != null)
                {
                    if (IsLoggedInUser())
                    {
                        RzSetting setting = new RzSetting(path, filename);
                        return (uint) _accountManager.DeleteSetting(setting, SettingSaveType.ServerAsync);
                    }

                    return result;
                }

                return result;
            }
            catch (Exception arg)
            {
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
                return 3u;
            }
        }

        public uint DeleteFolder(string path)
        {
            uint result = 3u;
            try
            {
                if (_accountManager != null)
                {
                    if (_bIsAccountLoggedIn)
                    {
                        return (uint) _accountManager.DeleteAll(path, SettingSaveType.ServerAsync);
                    }

                    return result;
                }

                return result;
            }
            catch (Exception arg)
            {
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
                return 3u;
            }
        }

        public void StartSync()
        {
            if (_bOngoingSync)
            {
                _logger.Info("StartSync: On going sync. Resetting sync timer.");
                ResetSyncTimer();
                return;
            }

            try
            {
                if (IsLoggedInUser(IsInitialSyncOn()))
                {
                    List<string> list = new List<string>(_commonPaths);
                    foreach (IDeviceInstance deviceInstance in _deviceInstances)
                    {
                        if (deviceInstance.Base_Product_ID.Equals(0u) && deviceInstance.Edition_ID.Equals(0u) && !deviceInstance.Product_ID.Equals(0u))
                        {
                            list.Add($"Devices\\{deviceInstance.Product_ID}");
                        }
                    }

                    list.AddRange(GetSystemPathsEligibleToSync(list));
                    _logger.Info(string.Format("StartSync: StartSync - last status: {0} sync started using these paths {1}", _lastSyncStatus, string.Join(", ", list)));
                    if (_lastSyncStatus == SyncStatus.Complete)
                    {
                        while (!_conflictItems.IsEmpty)
                        {
                            _conflictItems.TryTake(out var _);
                        }
                    }

                    _accountManager?.StartSync(list, SyncProgressHandler, SyncCompleteHandler);
                    _bOngoingSync = true;
                }
                else
                {
                    _logger.Info("StartSync: user not yet logged in.");
                }
            }
            catch (TimeoutException arg)
            {
                _logger.Error($"StartSync: {arg}");
                ResetSyncTimer();
            }
            catch (IOException arg2)
            {
                _logger.Error($"StartSync: {arg2}");
                ResetSyncTimer();
            }
            catch (Exception arg3)
            {
                _logger.Error($"StartSync: {arg3}");
                ResetSyncTimer();
            }
        }

        public bool StartInitialSync(IEnumerable<string> paths)
        {
            bool flag = false;
            if (!_bOngoingSync)
            {
                try
                {
                    if (IsLoggedInUser(bRazerCentralOnly: true))
                    {
                        _accountManager?.StartSync(paths, SyncProgressHandler, SyncCompleteHandler);
                        _bOngoingSync = true;
                        flag = true;
                    }
                    else
                    {
                        _logger.Info("StartInitialSync: user not yet logged in.");
                        flag = false;
                    }
                }
                catch (TimeoutException arg)
                {
                    _logger.Error($"StartInitialSync: {arg}");
                    flag = false;
                }
                catch (IOException arg2)
                {
                    _logger.Error($"StartInitialSync: {arg2}");
                    flag = false;
                }
                catch (Exception arg3)
                {
                    _logger.Error($"StartInitialSync: {arg3}");
                    flag = false;
                }
            }
            else
            {
                _logger.Info("StartInitialSync: On going sync.");
                flag = true;
            }

            this.OnInitialSyncEvalCompleteEvent?.Invoke(flag);
            return flag;
        }

        public void CancelSync()
        {
            try
            {
                if (_bOngoingSync)
                {
                    _accountManager?.CancelSync();
                    _bOngoingSync = false;
                }
            }
            catch (TimeoutException arg)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name} Timeout waiting for response from the service, Cancel sync failed: {arg}");
            }
            catch (IOException arg2)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name}  Failed to communicate with the service, Cancel sync failed: {arg2}");
            }
            catch (Exception arg3)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name} Cancel sync failed: {arg3}");
            }
        }

        public void SyncProgressHandler(SyncProgressEventArgs args)
        {
            _bOngoingSync = true;
            string path = args.CurrentItem.Path;
            Guid empty = Guid.Empty;
            if (!path.Contains(empty.ToString()))
            {
                string name = args.CurrentItem.Name;
                empty = Guid.Empty;
                if (!name.Contains(empty.ToString()))
                {
                    DataSyncItem.SyncAction action = args.CurrentItem.Action;
                    DataSyncItemInfo currentItem = new DataSyncItemInfo
                    {
                        Action = (SyncActionEnum) args.CurrentItem.Action,
                        LocalTime = args.CurrentItem.LocalTime,
                        Name = args.CurrentItem.Name,
                        Path = args.CurrentItem.Path,
                        ServerTime = args.CurrentItem.ServerTime
                    };
                    if (action == DataSyncItem.SyncAction.Add || action == DataSyncItem.SyncAction.Conflicted || action == DataSyncItem.SyncAction.DeleteLocal || action == DataSyncItem.SyncAction.Download)
                    {
                        _bSyncActivity = true;
                    }

                    if (currentItem.Action == SyncActionEnum.Conflicted)
                    {
                        if (_RzUser == null)
                        {
                            _RzUser = _accountManager?.GetCurrentUser();
                        }

                        bool flag = _RzUser?.IsGuest ?? false;
                        if (currentItem.Name.Contains("DeviceInfo.xml") || flag)
                        {
                            _logger.Info($"Resolving common conflicts using {SettingSourceEnum.Local} for file Path: {currentItem.Path} Name: {currentItem.Name}");
                            if (ResolveConflict(currentItem, SettingSourceEnum.Local))
                            {
                                return;
                            }
                        }

                        if (!_conflictItems.Any((DataSyncItemInfo x) => x.Path.Equals(currentItem.Path)))
                        {
                            _conflictItems.Add(currentItem);
                        }

                        if (_settingSourceEnum != SettingSourceEnum.Undefined)
                        {
                            _logger.Info($"Resolving confict using {_settingSourceEnum} for file Path: {currentItem.Path} Name: {currentItem.Name}");
                            if (ResolveConflict(currentItem, _settingSourceEnum))
                            {
                                return;
                            }
                        }
                    }

                    this.OnSyncProgress?.Invoke(new SyncProgressEventArgsInfo
                    {
                        CompleteItems = args.CompleteItems,
                        CurrentItem = currentItem,
                        TotalItems = args.TotalItems
                    });
                    return;
                }
            }

            _logger.Debug($"SyncProgressHandler: Encountered invalid guid Path: {args.CurrentItem.Path} Name: {args.CurrentItem.Name}");
        }

        public void SyncCompleteHandler(SyncStatus status)
        {
            _logger.Info($"SyncCompleteHandler: status {status} sync_activity {_bSyncActivity}");
            _bOngoingSync = false;
            bool flag = IsInitialSyncOn();
            if (!flag && (status.Equals(SyncStatus.Failed_Unknown) || status.Equals(SyncStatus.Failed_OfflineMode) || status.Equals(SyncStatus.Failed_NetworkError)))
            {
                _logger.Info($"SyncCompleteHandler: Received {status} resetting sync timer.");
                ResetSyncTimer();
            }

            if (_bSyncActivity && status == SyncStatus.Complete)
            {
                if (status == SyncStatus.Complete)
                {
                    _bIsInitialSyncOn = false;
                }

                this.OnSyncComplete?.Invoke((SyncStatusEnum) status);
                _logger.Info($"SyncCompleteHandler: bInitSync {flag} settingSourceEnum {_settingSourceEnum} lastSyncStatus{_lastSyncStatus}");
                UserSettingsChangedEnum userSettingsChangedEnum = ((flag || _settingSourceEnum != SettingSourceEnum.Undefined || _lastSyncStatus == SyncStatus.Conflicted) ? UserSettingsChangedEnum.UserLogin : UserSettingsChangedEnum.CloudSync);
                _logger.Debug($"SyncCompleteHandler: Calling NotifyUserSettings using: {userSettingsChangedEnum}");
                NotifyUserSettings(userSettingsChangedEnum);
                _bSyncActivity = false;
            }

            _lastSyncStatus = status;
            this.OnSyncCompleteSR?.Invoke((SyncStatusEnum) status);
        }

        private void NotifyUserSettings(UserSettingsChangedEnum status)
        {
            try
            {
                if (IsLoggedInUser(bRazerCentralOnly: true))
                {
                    _accountManagerInit = ServiceInitStatus.INITIALIZED;
                    this.OnInitLoadUserSettings?.Invoke(status);
                    this.OnPreLoadUserSettings?.Invoke(status);
                    this.OnCompletedPreLoadUserSettings?.Invoke(status);
                    this.OnAccountInitialized?.Invoke(status);
                    this.OnPostLoadUserSettings?.Invoke(status);
                    this.OnCompletedPostLoadUserSettings?.Invoke(status);
                    this.OnPostLoadUserSettingsSR?.Invoke(status);
                }
                else
                {
                    _logger.Error("FirtSyncCompletedNotification: IsLoggedIn returned false");
                }
            }
            catch (Exception ex)
            {
                _accountManagerInit = ServiceInitStatus.INITIALIZED;
                this.OnPostLoadUserSettingsSR?.Invoke(status);
                _logger.Error($"NotifyUserSettings: Exception message {ex} - obj {ex}");
            }
        }

        public BigDataPushStatusEnum PushBigData(List<string> dataFiles)
        {
            BigDataPushStatusEnum result = BigDataPushStatusEnum.Pending;
            try
            {
                if (_accountManager != null)
                {
                    result = (BigDataPushStatusEnum) _accountManager.PushBigData(dataFiles.ToArray());
                    return result;
                }

                return result;
            }
            catch (Exception arg)
            {
                _logger.Error($"{arg}: {MethodBase.GetCurrentMethod().Name}");
                return result;
            }
        }

        public DateTime? GetLastSyncDate()
        {
            DateTime? result = null;
            try
            {
                result = _accountManager?.GetLastSyncDate();
                return result;
            }
            catch (Exception ex)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name} GetLastSyncDate - {ex}", ex);
                return result;
            }
        }

        public bool ResolveConflict(DataSyncItemInfo item, SettingSourceEnum source)
        {
            try
            {
                if (_accountManager != null)
                {
                    bool flag = true;
                    foreach (DataSyncItemInfo conflictItem in _conflictItems)
                    {
                        _logger.Debug($"ResolveConflict: using {source} {conflictItem.Path} {conflictItem.Name}");
                        if (_accountManager.ResolveConflict(conflictItem.Path, conflictItem.Name, (SettingSource) source) == SaveResult.Success)
                        {
                            _logger.Debug($"ResolveConflict: resolved {source} {conflictItem.Path} {conflictItem.Name}");
                            continue;
                        }

                        flag = false;
                        _logger.Debug($"ResolveConflict: error {source} {conflictItem.Path} {conflictItem.Name}");
                    }

                    if (flag)
                    {
                        _settingSourceEnum = source;
                        while (!_conflictItems.IsEmpty)
                        {
                            _conflictItems.TryTake(out var _);
                        }

                        if (flag)
                        {
                            StartSync();
                        }
                    }

                    return flag;
                }
            }
            catch (TimeoutException arg)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name} Timeout waiting for response from the service, Resolution failed: {arg}");
            }
            catch (IOException arg2)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name} Failed to communicate with the service, Resolution failed {arg2}");
            }
            catch (Exception arg3)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name}: Resolution failed: {arg3}");
            }

            return false;
        }

        public byte[] GetRazerUserAvatar()
        {
            if (IsLoggedInUser(bRazerCentralOnly: true))
            {
                ImageConverter imageConverter = new ImageConverter();
                Bitmap bitmap = _accountManager?.GetUserProfile().Avatar;
                if (bitmap != null)
                {
                    return (byte[]) imageConverter.ConvertTo(bitmap, typeof(byte[]));
                }
            }

            return null;
        }

        public RazerUserInfo GetRazerUser()
        {
            if (IsLoggedInUser(bRazerCentralOnly: true))
            {
                try
                {
                    if (_RzUser == null)
                    {
                        _RzUser = _accountManager?.GetCurrentUser();
                    }

                    RazerUserInfo razerUserInfo = new RazerUserInfo(_RzUser.Id, (!string.IsNullOrEmpty(_RzUser.Token)) ? _RzUser.Token : _RzUser.Id, _RzUser.LoginId, string.Empty, (!string.IsNullOrEmpty(_RzUser.Token)) ? _RzUser.Token : _RzUser.Id);
                    NetworkMonitor networkMonitor = new NetworkMonitor();
                    razerUserInfo.Online = networkMonitor.NetworkIsUp;
                    return razerUserInfo;
                }
                catch (Exception arg)
                {
                    _logger.Error(string.Format($"GetRazerUser Exception: {arg}"));
                }
            }

            return null;
        }

        public bool IsLoggedInUser(bool bRazerCentralOnly = false)
        {
            bool result = false;
            try
            {
                if (!m_bWindowsUserTokenAvailable)
                {
                    m_bWindowsUserTokenAvailable = _processExtensions.IsWindowsUserLoggedIn();
                    _logger.Info($"IsLoggedInUser: IsWindowsUserLoggedIn returned {m_bWindowsUserTokenAvailable}");
                    if (!m_bWindowsUserTokenAvailable)
                    {
                        _logger.Error("IsLoggedInUser: IsWindowsUserLoggedIn returned false. Delay later.");
                        return false;
                    }

                    Thread.Sleep(3000);
                }

                if (bRazerCentralOnly)
                {
                    for (int i = 0; i < 2; i++)
                    {
                        try
                        {
                            return _accountManager?.IsLoggedIn() ?? false;
                        }
                        catch (TimeoutException arg)
                        {
                            _logger.Error($"IsLoggedInUser: {arg}. Retrying..");
                            result = false;
                        }
                        catch (Exception arg2)
                        {
                            _logger.Error($"IsLoggedInUser: {arg2}");
                            return false;
                        }

                        Thread.Sleep(100);
                    }

                    return result;
                }

                return _accountManagerInit.Equals(ServiceInitStatus.INITIALIZED);
            }
            catch (Exception arg3)
            {
                _logger.Error($"{MethodBase.GetCurrentMethod().Name}: IsLoggedInUser failed - {arg3}");
                return false;
            }
        }

        public string GetSystemUser()
        {
            return _processExtensions.LoggedInUser();
        }

        public void ScheduleSync()
        {
            ResetSyncTimer();
        }

        private void ResetSyncTimer()
        {
            _logger.Info($"ResetSyncTimer: Sync schedule to execute on {DateTime.Now.AddMilliseconds(_syncTimer.Interval)}");
            _syncTimer.Stop();
            _syncTimer.Start();
        }

        public bool IsInitialSyncOn()
        {
            return _bIsInitialSyncOn;
        }

        public bool IsOnGoingSync()
        {
            return _bOngoingSync;
        }

        public bool ExitSynapse()
        {
            LogoutCompleteHandler(this, new LogoutEventArgs(null, LogoutReason.UserInitiated));
            return true;
        }

        public bool InitialSyncContinued()
        {
            if (IsInitialSyncOn())
            {
                _bIsInitialSyncOn = false;
                NotifyUserSettings(UserSettingsChangedEnum.UserLogin);
                return true;
            }

            return false;
        }

        private bool TriggerInitialSync()
        {
            if (!IsInitialSyncOn())
            {
                InitialSyncPaths = new List<string>();
                InitialSyncPaths.Clear();
                InitialSyncPaths = GetDevicePathsEligibleToSync();
                if (InitialSyncPaths == null || InitialSyncPaths.Count <= 0)
                {
                    _bIsInitialSyncOn = false;
                    return IsInitialSyncOn();
                }

                InitialSystemSyncPaths = new List<string>();
                InitialSystemSyncPaths.Clear();
                InitialSystemSyncPaths = GetSystemPathsEligibleToSync(InitialSyncPaths);
                InitialSyncPaths.AddRange(InitialSystemSyncPaths);
                if (InitialSyncPaths == null || InitialSyncPaths.Count <= 0)
                {
                    _bIsInitialSyncOn = false;
                    return IsInitialSyncOn();
                }

                InitialSyncPaths.InsertRange(0, _commonPaths);
            }

            if (StartInitialSync(InitialSyncPaths))
            {
                _bIsInitialSyncOn = true;
                _logger.Info(string.Format("TriggerInitialSync: Initial cloud sync started using these paths {0}", string.Join(", ", InitialSyncPaths)));
            }
            else
            {
                _bIsInitialSyncOn = false;
                _logger.Error("TriggerInitialSync: Failed to trigger initial sync.");
            }

            return IsInitialSyncOn();
        }

        private List<string> GetDevicePathsEligibleToSync()
        {
            List<string> list = new List<string>();
            IList<SettingDefinitionInfo> settingList = GetSettingList("Devices", "DeviceInfo.xml", SettingSourceEnum.Local);
            if (settingList == null)
            {
                return list;
            }

            bool flag = true;
            foreach (IDeviceInstance instance in _deviceInstances)
            {
                if (instance.Base_Product_ID.Equals(0u) && instance.Edition_ID.Equals(0u) && !instance.Product_ID.Equals(0u) && !settingList.Any((SettingDefinitionInfo x) => x.Path.Contains($"Devices\\{instance.Product_ID}")))
                {
                    _logger.Info($"PathsEligibleForInitialSync: Can't find setting list for device {instance.Name} {instance.Product_ID} Adding to list.");
                    list.Add($"Devices\\{instance.Product_ID}");
                    flag = false;
                }
            }

            if (!flag)
            {
                _logger.Info("PathsEligibleForInitialSync: Some device/s local settings are not available. Check cloud..");
                IList<SettingDefinitionInfo> settingList2 = GetSettingList("Devices", "DeviceInfo.xml", SettingSourceEnum.Server);
                if (settingList2 == null || settingList2.Count == 0)
                {
                    _logger.Error("PathsEligibleForInitialSync: Failed to retrieve cloud settings.");
                    return null;
                }

                for (int num = list.Count - 1; num >= 0; num--)
                {
                    string path = list[num];
                    if (!settingList2.Any((SettingDefinitionInfo x) => x.Path.Contains(path)))
                    {
                        _logger.Debug($"PathsEligibleForInitialSync: {path} not in cloud. Removing...");
                        list.RemoveAt(num);
                    }
                }
            }

            return list;
        }

        private List<string> GetSystemPathsEligibleToSync(List<string> listLocal)
        {
            List<string> list = new List<string>();
            IList<SettingDefinitionInfo> settingList = GetSettingList("Devices", "SystemInfo.xml", SettingSourceEnum.Server);
            if (settingList == null)
            {
                return list;
            }

            bool flag = false;
            foreach (IDeviceInstance deviceInstance in _deviceInstances)
            {
                if (deviceInstance.Base_Product_ID.Equals(0u) && deviceInstance.Edition_ID.Equals(0u) && !deviceInstance.Product_ID.Equals(0u) && deviceInstance.Type.Equals(10u))
                {
                    flag = true;
                    break;
                }
            }

            if (flag)
            {
                foreach (SettingDefinitionInfo item in settingList)
                {
                    if (!listLocal.Any((string x) => x.Contains(item.Path)))
                    {
                        list.Add(item.Path);
                    }
                }

                return list;
            }

            return list;
        }
    }
}