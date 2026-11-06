# COMPortInspectorConsole

Standalone C# console application for 64-bit Windows. Lists local and RDP-redirected COM device mappings and locally detectable processes with matching open handles. Multiple owners are listed separately. It does not open, reset, configure, read, or write any COM port.

## Files

- `COMPortInspector.sln`: solution.
- `COMPortInspectorConsole.csproj`: .NET 10 Windows project, x64.
- `Program.cs`: complete source, including native interop and isolated handle-query helper.
- `bin\Release\net10.0-windows\COMPortInspectorConsole.exe`: compiled executable.

## Run

Open a PowerShell window as administrator, then run:

```powershell
Set-Location "$env:TEMP\COM ports scanner"
& '.\bin\Release\net10.0-windows\COMPortInspectorConsole.exe'
```

This build requires the .NET 10 x64 runtime.

Interactive scans display `Press any key to close...` after completion or a reported scan failure. The prompt is skipped when standard input is redirected, and for `--help`, `--self-test`, and internal helper mode.

While inspecting handles, the application displays a rotating `| / - \` spinner on one line, refreshed every 150 milliseconds. Elapsed seconds are shown only in the `SCAN COMPLETE` message. Animation is disabled when output is redirected. Leave the window open until `SCAN COMPLETE` and the results appear; large or elevated scans can take several minutes.

For a framework-dependent portable folder targeting another PC with .NET 10 installed:

```powershell
dotnet publish '.\COMPortInspectorConsole.csproj' -c Release -r win-x64 --self-contained false -o '.\publish'
```

To include the runtime for a PC without .NET 10, use `--self-contained true` instead.

## Build and validate

Requires the .NET 10 SDK:

```powershell
dotnet build '.\COMPortInspector.sln' -c Release
& '.\bin\Release\net10.0-windows\COMPortInspectorConsole.exe' --self-test
```

Self-tests open only Windows NUL, verify that local and redirected mappings with the same COM number remain distinct, test ownership detection against only the self-test process, deliberately stall a helper to verify timeout isolation, and forcibly terminate a test parent to verify its helper also exits. No physical or virtual COM port is opened.

## Reading the results

The table includes Port, Mapping, PID, Process / ownership, and Device columns.

- `Local (active)`: local device mapping currently targeted by this session's COM name.
- `RDP (active)`: this session's COM name targets a redirected client port.
- `Local (masked)`: a local serial-device registry mapping exists, but this session's COM name targets something else (or has no active DOS mapping).
- `Unknown - no owner detected`: inconclusive, NOT a report that the port is free.

For example, COM3 can have both an active RDP mapping and a masked local USB mapping. The scanner inspects handles against each device separately, lists any locally detectable owners against the correct row, and warns about the name collision. It cannot list client-side processes from the remote machine; run the scanner on that client PC too.

## How it works

1. Enumerates active session COM targets with QueryDosDevice and merges local device mappings from HKLM\HARDWARE\DEVICEMAP\SERIALCOMM, preserving local mappings masked by RDP redirection.
2. Takes a system handle snapshot using NtQuerySystemInformation (SystemExtendedHandleInformation).
3. Identifies the File object type using a known local file handle; no fixed Windows object-type index is assumed.
4. Uses OpenProcess and DuplicateHandle to inspect candidate handles in a separate helper process.
5. Uses NtQueryObject to compare object names with COM device mappings and reports owning PIDs/process names.
6. Terminates only its own helper if a native query takes too long. Each protocol operation has a two-second timeout. The total scan duration depends on the number of handles and timed-out queries.
7. Assigns each helper to a Windows job with kill-on-job-close enabled. Only the parent owns the job handle, so closing the console or abruptly terminating the parent also terminates its helper, without relying on managed exit handlers.

## Limitations

- Run elevated for better coverage. Elevation does not bypass all protected-process restrictions.
- `Unknown - no owner detected` does not prove a port is free. The scanner reports unavailable processes/handles and timed-out queries; results are a snapshot subject to process and handle races.
- The scanner reports handles, not whether an application is actively transmitting. It never closes another application's original handle or terminates an owning process.
- QueryDosDevice reflects the caller's device namespace/session. RDP mappings may shadow physical ports with the same COM number.
- A mapping beginning with `\Device\RdpDrPort\` is an RDP-redirected port. Run the scanner on the client PC as well to identify programs holding the physical client-side port. A server-side scan cannot enumerate client-side processes.
- Native NT handle enumeration/object-query interfaces are Windows-specific and may change. Device drivers may expose names that cannot be matched to the DOS alias; these are not guaranteed detectable.
- The original sensor-test repository and its solution are not changed by this tool.
