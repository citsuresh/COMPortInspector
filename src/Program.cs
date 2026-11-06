using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace COMPortInspectorConsole;

internal static class Program
{
    private const int QueryTimeoutMilliseconds = 2000;

    private static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
        {
            Console.Error.WriteLine("This scanner requires 64-bit Windows and a 64-bit process.");
            return 1;
        }

        if (args is ["--worker"])
            return RunWorker();
        if (args is ["--lifetime-probe"])
        {
            using var worker = Worker.Start();
            await worker.Process.StandardInput.WriteLineAsync("TEST-STALL");
            await worker.Process.StandardInput.FlushAsync();
            Console.WriteLine("WORKER:" + worker.Process.Id);
            await Task.Delay(Timeout.Infinite);
            return 0;
        }
        if (args is ["--help"])
        {
            Console.WriteLine("COMPortInspectorConsole.exe [--self-test | --help]");
            Console.WriteLine("Lists local and RDP COM mappings and locally detectable owning processes.");
            Console.WriteLine("Run as administrator for best coverage. No COM port is opened or configured.");
            return 0;
        }
        if (args.Length != 0 && args is not ["--self-test"])
        {
            Console.Error.WriteLine("Unknown arguments. Use --help.");
            return 1;
        }

        try
        {
            if (args is ["--self-test"])
                return await SelfTestAsync();

            using var identity = WindowsIdentity.GetCurrent();
            bool elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            Console.WriteLine("COM Port Scanner");
            if (!elevated)
                Console.WriteLine("WARNING: Not elevated. Run as administrator to inspect more processes.");

            var ports = GetPorts();
            if (ports.Count == 0)
            {
                Console.WriteLine("No COM ports were reported by the session namespace or local serial-device registry.");
                return 0;
            }

            Console.WriteLine("SCANNING... Please wait. Scanning all process handles can take several minutes.");
            Console.WriteLine("Results will appear below when the scan completes. Do not close this window.");
            var elapsed = Stopwatch.StartNew();
            var scan = ScanAsync(ports);
            const string spinner = "|/-\\";
            int frame = 0;
            try
            {
                while (!scan.IsCompleted)
                {
                    if (!Console.IsOutputRedirected)
                        Console.Write($"\rSCANNING... {spinner[frame++ % spinner.Length]} Please wait...");
                    await Task.WhenAny(scan, Task.Delay(TimeSpan.FromMilliseconds(150)));
                }
            }
            finally
            {
                if (!Console.IsOutputRedirected)
                    Console.WriteLine();
            }
            var result = await scan;
            Console.WriteLine($"SCAN COMPLETE ({elapsed.Elapsed.TotalSeconds:F0} seconds).");
            Console.WriteLine();
            Console.WriteLine($"{"Port",-8} {"Mapping",-15} {"PID",-8} {"Process / ownership",-32} Device");
            foreach (var port in ports)
            {
                var owners = result.Owners.Where(o => o.Mapping == port).OrderBy(o => o.Pid).ToArray();
                string mapping = (port.IsRedirected ? "RDP" : "Local") +
                    (port.IsCurrentMapping ? " (active)" : " (masked)");
                if (owners.Length == 0)
                    Console.WriteLine($"{port.Name,-8} {mapping,-15} {"-",-8} {"Unknown - no owner detected",-32} {port.Device}");
                foreach (var owner in owners)
                    Console.WriteLine($"{port.Name,-8} {mapping,-15} {owner.Pid,-8} {owner.ProcessName,-32} {port.Device}");
            }

            Console.WriteLine();
            Console.WriteLine("Active = device targeted by this session's COM name. Masked = local registry mapping not active here.");
            foreach (var collision in ports.GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
                Console.WriteLine($"WARNING: {collision.Key} has multiple device mappings; check which device your test should use.");
            Console.WriteLine($"Inspected {result.QueriedHandles} handles; {result.UnavailableProcesses} processes unavailable; " +
                $"{result.UnavailableHandles} handles unavailable; {result.TimedOutQueries} queries timed out.");
            Console.WriteLine("Unknown ownership does NOT prove a port is free. Protected processes, access restrictions,");
            Console.WriteLine("handle-query failures, and processes opening/closing handles can limit this snapshot.");
            if (ports.Any(p => p.IsRedirected))
                Console.WriteLine("RDP client-side owners are NOT visible here. Run this scanner on the client PC too.");
            if (result.FirstQueryError is not null)
                Console.WriteLine("First handle-query error: " + result.FirstQueryError);
            return 0;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidOperationException or
            TimeoutException or OverflowException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Scanner failed: " + ex.Message);
            return 1;
        }
        finally
        {
            if (args.Length == 0 && !Console.IsInputRedirected)
            {
                Console.WriteLine();
                Console.WriteLine("Press any key to close...");
                Console.ReadKey(intercept: true);
            }
        }
    }

    private static List<Port> GetPorts()
    {
        var names = QueryDevice(null).Where(n => Regex.IsMatch(n, @"^COM\d+$", RegexOptions.IgnoreCase));
        // QueryDosDevice's first target is current; subsequent targets can be stale definitions.
        var active = names.Select(n => new Port(n.ToUpperInvariant(), QueryDevice(n).First(), true)).ToList();
        var local = new List<Port>();
        using var serial = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DEVICEMAP\SERIALCOMM");
        if (serial is null)
            Console.WriteLine("Local serial-device registry key is absent; inspecting only session mappings.");
        else
        {
            foreach (string device in serial.GetValueNames())
            {
                if (!device.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (serial.GetValue(device) is not string port || !Regex.IsMatch(port, @"^COM\d+$", RegexOptions.IgnoreCase))
                    throw new InvalidOperationException("Invalid serial-device registry mapping for " + device);
                local.Add(new Port(port.ToUpperInvariant(), device, false));
            }
        }
        return MergePorts(active, local);
    }

    private static List<Port> MergePorts(IEnumerable<Port> active, IEnumerable<Port> local) =>
        active.Concat(local)
            .GroupBy(p => (p.Name.ToUpperInvariant(), p.Device.ToUpperInvariant()))
            .Select(g => new Port(g.First().Name, g.First().Device, g.Any(p => p.IsCurrentMapping)))
            .OrderBy(p => p.Name.Length).ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ThenByDescending(p => p.IsCurrentMapping).ThenBy(p => p.Device, StringComparer.OrdinalIgnoreCase).ToList();

    private static bool MatchesDevice(Port port, string name) =>
        name.Equals(port.Device, StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith(port.Device + "\\", StringComparison.OrdinalIgnoreCase);

    private static string[] QueryDevice(string? name)
    {
        for (int length = 4096; length <= 1024 * 1024; length *= 2)
        {
            var buffer = new char[length];
            uint written = Native.QueryDosDevice(name, buffer, buffer.Length);
            if (written != 0)
                return new string(buffer, 0, checked((int)written)).Split('\0', StringSplitOptions.RemoveEmptyEntries);
            int error = Marshal.GetLastWin32Error();
            if (error != 122)
                throw new Win32Exception(error, "QueryDosDevice failed for " + (name ?? "device list"));
        }
        throw new InvalidOperationException("Device-name buffer exceeded its safety limit.");
    }

    private static List<Native.HandleEntry> GetHandles()
    {
        int size = 1024 * 1024;
        while (size <= 256 * 1024 * 1024)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                int status = Native.NtQuerySystemInformation(64, buffer, size, out int needed);
                if (status == unchecked((int)0xC0000004))
                {
                    size = checked(Math.Max(size * 2, needed + 65536));
                    continue;
                }
                if (status < 0)
                    throw new InvalidOperationException($"System handle enumeration failed: NTSTATUS 0x{status:X8}.");

                long count = Marshal.ReadInt64(buffer);
                int entrySize = Marshal.SizeOf<Native.HandleEntry>();
                if (count < 0 || count > (size - 16) / entrySize)
                    throw new InvalidOperationException("Windows returned an invalid handle table length.");
                var handles = new List<Native.HandleEntry>(checked((int)count));
                for (int i = 0; i < count; i++)
                    handles.Add(Marshal.PtrToStructure<Native.HandleEntry>(IntPtr.Add(buffer, 16 + i * entrySize)));
                return handles;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        throw new InvalidOperationException("System handle table exceeded its safety limit.");
    }

    private static async Task<ScanResult> ScanAsync(IReadOnlyList<Port> ports, int? onlyProcessId = null)
    {
        // Derive the File object type index; its numeric value varies between Windows versions.
        using var sample = File.OpenHandle(Assembly.GetExecutingAssembly().Location);
        var handles = GetHandles();
        var sampleEntry = handles.Single(h => h.ProcessId == (nuint)Environment.ProcessId &&
            h.HandleValue == (nuint)sample.DangerousGetHandle());
        var candidates = handles.Where(h => h.ObjectTypeIndex == sampleEntry.ObjectTypeIndex &&
            h.ProcessId > 0 && h.ProcessId <= int.MaxValue &&
            (onlyProcessId is null || h.ProcessId == (nuint)onlyProcessId.Value)).GroupBy(h => (int)h.ProcessId);
        var result = new ScanResult();
        Worker? worker = null;
        try
        {
            foreach (var group in candidates)
            {
                using var process = Native.OpenProcess(0x0040, false, group.Key);
                if (process.IsInvalid)
                {
                    result.UnavailableProcesses++;
                    continue;
                }
                string? processName = null;
                foreach (var handle in group)
                {
                    worker ??= Worker.Start();
                    if (!Native.DuplicateHandle(process, (IntPtr)handle.HandleValue, worker.Process.Handle,
                        out IntPtr duplicate, 0, false, 0x00000002))
                    {
                        result.UnavailableHandles++;
                        continue;
                    }
                    result.QueriedHandles++;
                    string response;
                    try
                    {
                        response = await worker.RequestAsync(duplicate.ToInt64().ToString());
                    }
                    catch (TimeoutException)
                    {
                        result.TimedOutQueries++;
                        worker.Dispose();
                        worker = null;
                        continue;
                    }
                    if (response.StartsWith("ERROR:", StringComparison.Ordinal))
                    {
                        result.UnavailableHandles++;
                        result.FirstQueryError ??= response;
                        continue;
                    }
                    if (!response.StartsWith("NAME:", StringComparison.Ordinal))
                        throw new InvalidOperationException("Unexpected helper response: " + response);
                    string name = Encoding.Unicode.GetString(Convert.FromBase64String(response[5..]));
                    foreach (var port in ports)
                    {
                        if (!MatchesDevice(port, name))
                            continue;
                        processName ??= GetProcessName(group.Key);
                        result.Owners.Add(new Owner(port, group.Key, processName));
                    }
                }
            }
        }
        finally
        {
            worker?.Dispose();
        }
        return result;
    }

    private static string GetProcessName(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.ProcessName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception)
        {
            Console.Error.WriteLine($"Cannot read name for PID {pid}: {ex.Message}");
            return "(name unavailable)";
        }
    }

    private static int RunWorker()
    {
        while (Console.ReadLine() is { } line)
        {
            if (line == "TEST-STALL")
                Thread.Sleep(Timeout.Infinite);
            if (!long.TryParse(line, out long value))
            {
                Console.WriteLine("ERROR:Invalid helper input");
                continue;
            }
            using var handle = new SafeFileHandle(new IntPtr(value), ownsHandle: true);
            Console.WriteLine(ReadObjectName(handle));
        }
        return 0;
    }

    private static string ReadObjectName(SafeFileHandle handle)
    {
        for (int size = 1024; size <= 1024 * 1024; size *= 2)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                int status = Native.NtQueryObject(handle, 1, buffer, size, out _);
                if (status is unchecked((int)0xC0000004) or unchecked((int)0x80000005) or unchecked((int)0xC0000023))
                    continue;
                if (status < 0)
                    return $"ERROR:NtQueryObject returned NTSTATUS 0x{status:X8}";
                var name = Marshal.PtrToStructure<Native.UnicodeString>(buffer);
                string text = name.Length == 0 ? "" : Marshal.PtrToStringUni(name.Buffer, name.Length / 2) ?? "";
                return "NAME:" + Convert.ToBase64String(Encoding.Unicode.GetBytes(text));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return "ERROR:Object name exceeded its safety limit";
    }

    private static async Task<int> SelfTestAsync()
    {
        var redirected = new Port("COM3", @"\Device\RdpDrPort\;COM3:2\tsclient\COM3", true);
        var physical = new Port("COM3", @"\Device\Null", false);
        var activeLocal = new Port("COM21", @"\Device\USBSER000", true);
        var mappings = MergePorts([redirected, activeLocal],
            [physical, new Port("com21", @"\device\usbser000", false)]);
        if (mappings.Count != 3 || !mappings.Contains(physical) || !mappings.Contains(redirected) ||
            !mappings.Contains(activeLocal) || !redirected.IsRedirected || physical.IsRedirected ||
            MatchesDevice(physical, @"\Device\NullOther") ||
            !MatchesDevice(redirected, redirected.Device.ToUpperInvariant()))
            throw new InvalidOperationException("Self-test failed: local/RDP mapping merge or device matching is incorrect.");
        Console.WriteLine("PASS: Preserved masked local COM3 alongside active RDP COM3 and deduplicated local mappings.");
        using var nul = Native.CreateFile("NUL", 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (nul.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not open NUL for the self-test.");
        var result = await ScanAsync(mappings, Environment.ProcessId);
        if (!result.Owners.Any(o => o.Pid == Environment.ProcessId && o.Mapping == physical) ||
            result.Owners.Any(o => o.Mapping == redirected))
            throw new InvalidOperationException("Self-test failed: physical/RDP COM3 ownership was not distinguished.");
        Console.WriteLine("PASS: Detected this process's NUL handle only on the synthetic physical COM3, not redirected COM3.");
        using var worker = Worker.Start();
        bool timedOut = false;
        try { await worker.RequestAsync("TEST-STALL"); }
        catch (TimeoutException) { timedOut = true; }
        if (!timedOut)
            throw new InvalidOperationException("Self-test failed: stalled helper did not time out.");
        Console.WriteLine("PASS: Stalled handle-query helper timed out and is terminated on disposal.");
        using var probe = Process.Start(CreateStartInfo("--lifetime-probe")) ??
            throw new InvalidOperationException("Could not start the parent-exit probe.");
        try
        {
            string? reply = await probe.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10));
            if (reply is null || !reply.StartsWith("WORKER:", StringComparison.Ordinal) ||
                !int.TryParse(reply[7..], out int childPid))
                throw new InvalidOperationException("Parent-exit probe failed: " + reply);
            using var child = Process.GetProcessById(childPid);
            probe.Kill();
            await probe.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            Console.WriteLine("PASS: Abrupt parent termination also terminated its stalled helper.");
        }
        finally
        {
            if (!probe.HasExited)
            {
                probe.Kill();
                if (!probe.WaitForExit(5000))
                    Console.Error.WriteLine($"WARNING: Probe PID {probe.Id} did not exit within five seconds.");
            }
        }
        Console.WriteLine("Self-tests passed. No COM ports were opened.");
        return 0;
    }

    private static ProcessStartInfo CreateStartInfo(string argument)
    {
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate the scanner executable.");
        var info = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            info.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        info.ArgumentList.Add(argument);
        return info;
    }

    private sealed class Worker : IDisposable
    {
        public Process Process { get; }
        private readonly Task<string> errors;
        private readonly JobHandle job;

        private Worker(Process process, JobHandle job)
        {
            Process = process;
            this.job = job;
            errors = process.StandardError.ReadToEndAsync();
        }

        public static Worker Start()
        {
            var job = Native.CreateJobObject(IntPtr.Zero, null);
            Process? process = null;
            bool transferred = false;
            try
            {
                if (job.IsInvalid)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the helper lifetime job.");
                var limits = new Native.JobExtendedLimitInformation();
                limits.BasicLimitInformation.LimitFlags = 0x00002000;
                if (!Native.SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf<Native.JobExtendedLimitInformation>()))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not configure kill-on-close for the helper job.");
                process = Process.Start(CreateStartInfo("--worker")) ??
                    throw new InvalidOperationException("Could not start the handle-query helper.");
                // The worker cannot query a handle until we assign its job and send its first request.
                if (!Native.AssignProcessToJobObject(job, process.Handle))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not assign the helper to its lifetime job.");
                var worker = new Worker(process, job);
                transferred = true;
                return worker;
            }
            finally
            {
                if (!transferred)
                {
                    job.Dispose();
                    if (process is not null)
                    {
                        try
                        {
                            if (!process.HasExited)
                            {
                                process.Kill();
                                if (!process.WaitForExit(5000))
                                    Console.Error.WriteLine($"WARNING: Helper PID {process.Id} did not exit within five seconds.");
                            }
                        }
                        finally { process.Dispose(); }
                    }
                }
            }
        }

        public async Task<string> RequestAsync(string request)
        {
            await Process.StandardInput.WriteLineAsync(request).WaitAsync(TimeSpan.FromMilliseconds(QueryTimeoutMilliseconds));
            await Process.StandardInput.FlushAsync().WaitAsync(TimeSpan.FromMilliseconds(QueryTimeoutMilliseconds));
            string? reply = await Process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromMilliseconds(QueryTimeoutMilliseconds));
            if (reply is null)
                throw new InvalidOperationException("Handle-query helper closed its output unexpectedly: " +
                    await errors.WaitAsync(TimeSpan.FromMilliseconds(QueryTimeoutMilliseconds)));
            return reply;
        }

        public void Dispose()
        {
            try
            {
                job.Dispose();
                if (!Process.WaitForExit(5000))
                    Console.Error.WriteLine($"WARNING: Helper PID {Process.Id} did not exit within five seconds.");
            }
            finally
            {
                Process.Dispose();
            }
        }
    }

    private sealed class JobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public JobHandle() : base(ownsHandle: true) { }
        protected override bool ReleaseHandle() => Native.CloseHandle(handle);
    }

    private sealed record Port(string Name, string Device, bool IsCurrentMapping)
    {
        public bool IsRedirected => Device.StartsWith(@"\Device\RdpDrPort\", StringComparison.OrdinalIgnoreCase);
    }
    private sealed record Owner(Port Mapping, int Pid, string ProcessName);
    private sealed class ScanResult
    {
        public HashSet<Owner> Owners { get; } = [];
        public int QueriedHandles { get; set; }
        public int UnavailableProcesses { get; set; }
        public int UnavailableHandles { get; set; }
        public int TimedOutQueries { get; set; }
        public string? FirstQueryError { get; set; }
    }

    private static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct JobBasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public nuint MinimumWorkingSetSize;
            public nuint MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public nuint Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JobExtendedLimitInformation
        {
            public JobBasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public nuint ProcessMemoryLimit;
            public nuint JobMemoryLimit;
            public nuint PeakProcessMemoryUsed;
            public nuint PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct HandleEntry
        {
            public IntPtr Object;
            public nuint ProcessId;
            public nuint HandleValue;
            public uint GrantedAccess;
            public ushort CreatorBackTraceIndex;
            public ushort ObjectTypeIndex;
            public uint HandleAttributes;
            public uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint QueryDosDevice(string? device, [Out] char[] target, int length);
        [DllImport("ntdll.dll")]
        internal static extern int NtQuerySystemInformation(int informationClass, IntPtr buffer, int length, out int returnLength);
        [DllImport("ntdll.dll")]
        internal static extern int NtQueryObject(SafeFileHandle handle, int informationClass, IntPtr buffer, int length, out int returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateHandle(SafeProcessHandle sourceProcess, IntPtr sourceHandle,
            IntPtr targetProcess, out IntPtr targetHandle, uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern JobHandle CreateJobObject(IntPtr security, string? name);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(JobHandle job, int informationClass,
            ref JobExtendedLimitInformation information, int length);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(JobHandle job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
    }
}
