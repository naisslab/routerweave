# Data collection and ground truth

Run the commands from this directory in PowerShell on Windows with Python 3.11 or later. The router must support SSH and tcpdump, and the collection host must trust its SSH host key. Android collection uses ADB. The native UI adapter also requires a JDK, an Android SDK platform, and Android SDK Build Tools. iOS collection uses go-ios and WebDriverAgent.

```powershell
python -m pip install -r requirements.txt
$env:ROUTERWEAVE_ROUTER_HOST = Read-Host 'Router address'
$env:ROUTERWEAVE_SSH_KEY = Read-Host 'Path to SSH private key'
```

| Entry point | Purpose |
| --- | --- |
| `scripts/collection/collect_mobile.ps1` | Automate Android and iOS apps, record activity events, capture router traffic, and attribute packets to apps. |
| `scripts/collection/collect_windows.ps1` | Run Windows activity plans, record foreground processes and activity intervals, and optionally capture router traffic. |
| `scripts/collection/collect_iot.ps1` | Run a local IoT configuration and record device responses alongside router traffic. |
| `python -m collection_core --help` | Extract activity intervals and ground truth from existing records. |

The Android single-app plan for QQ Music runs for 30 minutes. Add `-Preview` to inspect the plan. For iOS, use `ios-music-single-app` and `-IosUdid`.

```powershell
$serial = Read-Host 'ADB device serial'
.\scripts\collection\collect_mobile.ps1 -CollectionTaskId android-music-single-app -AppName qqmusic -Serial $serial -RootOut runs/collection/android-music
```

Windows can record foreground processes and capture router traffic directly. The default automation example opens Notepad. Use `-Plan` to supply a Windows JSON plan with your own applications, websites, and actions. The command below records the foreground process selected by the operator.

```powershell
.\scripts\collection\collect_windows.ps1 -CollectionTaskId windows-workstation-traffic-probe -NoAutomation -DurationSeconds 15 -EnableRouterCapture -DeviceIp (Read-Host 'Local IP address on the LAN') -RootOut runs/collection/windows-probe
```

The [Google Home example](examples/google_home_plug.json) records one power-on and one power-off operation. Set the plug name as displayed in Google Home and its Wi-Fi MAC address, or pass your own JSON file to `--plan`.

```powershell
$env:ROUTERWEAVE_DEVICE_NAME = Read-Host 'Plug name in Google Home'
$env:ROUTERWEAVE_DEVICE_MAC = Read-Host 'Plug Wi-Fi MAC address'
.\scripts\collection\collect_iot.ps1 -CollectionTaskId iot-google-home-operations -Platform google_home -RunRoot runs/collection/google-home -PythonModule collection.runtime.ios.iot_google_home_capture -CollectorArguments @('--plan', 'examples/google_home_plug.json')
```

For manual annotations, open the collection tool with `.\scripts\collection\collect_mobile.ps1 -ManualGroundTruth -EventMarkerOnly -CollectionTaskId manual-smart-plug -RootOut runs/collection/manual`. Use **Try demo** in the timeline panel to rehearse annotations without hardware. For live capture the marker matches the supplied MAC to an online router client.

For scheduled IoT runs, set `ROUTERWEAVE_CONFIG_DIR` to the directory containing your own `collection_tasks.json`. Register the task with `kind: iot`, `collection_type: iot_routine`, its control platform, a positive `minimum_duration_seconds`, and a `metadata.routine_plan_id` matching the plan. Binding paths can be relative to the routine JSON file.

## Inputs and outputs

The synthetic example runs without a device. Each JSONL event contains a timestamp with a time-zone offset, a step name, and an execution result. The sustained activity begins 2 seconds into the trace and ends at 12 seconds. The expected interval is `[[946684802.0, 946684812.0]]` in Unix seconds.

```powershell
python -B -m collection_core mobile examples/synthetic_mobile_events.jsonl --sustain-only
```

| Inputs | Interpretation |
| --- | --- |
| Mobile activity events, router PCAP, and Android UID/socket evidence or an iOS process capture | `network_capture_windows.json` lists capture intervals. The `--sustain-only` option selects intervals for successful sustained steps. Browsing captures can also include navigation. App attribution requires app-level evidence. |
| Windows foreground samples in `ground_truth.csv` and actions in `usage_windows.jsonl` | Match the target process to activity intervals by sample time. Formal single-app plans require at least 1,800 seconds with the target in the foreground. The 15-second example checks the collection path. |
| IoT device plan, state observations, command times, and traffic | `sample_windows.json` records each command, its result, time window, and validity. Traffic observed around a command establishes an association. Confirming a physical state change requires a separate observation. |

Repeat Windows collections measure duration from verifiable foreground samples. This criterion can yield different decisions for playback or idle samples accepted by manual review in earlier experiments. Each run records its process exclusion list for use in traffic comparisons. Validation runs discard raw captures after validation and retain summaries. Reproducing the paper’s results also requires the original data, recording-level splits, and downstream models.
