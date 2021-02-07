# Ongoing fixes for `Common.RazerCentral.dll`

## Installation

> Note: It is a good idea to make a backup of any directory or files before overwriting

> Note: It seems that all the assemblies in the `C:\ProgramData\Razer\Synapse3\Service\Bin` directory are loaded, so do not store the backups in this directory

1. Download the archive from the appropriate [release](https://github.com/tasadar2/Razer-Common.RazerCentral/releases)
1. Exit `Razer Synapse`
    - Due to some cross-app communication, this needs to be restarted with the service in order for the devices to be found correctly
    - This can be done from the Razer Central icon in the taskbar notification area, or by terminating the `Razer Synapse 3.exe` process
1. Stop the windows service `Razer Synapse Service`
1. Extract the downloaded files to `C:\ProgramData\Razer\Synapse3\Service\Staging\Bin\Framework\Common\Common.Central`, overwriting what is there
1. Extract the downloaded files to `C:\ProgramData\Razer\Synapse3\Service\Bin`, overwriting what is there
    - This might be optional, I think this is pulled from the Framework directory as a startup self-update process
1. Start the windows service `Razer Synapse Service`
1. Start `Razer Synapse`
    - This can be run with the start menu entry

## Fixes

- Removed the questionable rapid disposal of a service that seems to be built to be long running
    - Occasionally the host process takes ~5% of my 12 core CPU, that bothers me for a simple keyboard controller, especially since the ancient Belkin Nostromo software took 0% of my single core CPU back in the day.

      One of the issues is that the `NetworkMonitor` constructor subscribes to two events, but onlyunsubscribes from one, and the act of subscribing to these events are not the simplestimplementations from what ive seen.

      ```csharp
      public NetworkMonitor()
      {
          ...
          NetworkChange.NetworkAddressChanged += AddressChangedCallback;
          NetworkChange.NetworkAvailabilityChanged += NetworkAvailabilityCallback;
      }

      public void Dispose()
      {
          NetworkChange.NetworkAddressChanged -= AddressChangedCallback;
      }
      ```

      The disturbing part is that the purpose of this long running service is to update the `NetworkIsUp` member, but this member, just manually executes what is already cached in `m_lastNetworkState`...

      To avoid any mis-assumptions, I ended up caching the long running service, instead of altering the behavior of the `NetworkMonitor`, which seems to have solved the occasional CPU usage as well as one of the memory leaks.
