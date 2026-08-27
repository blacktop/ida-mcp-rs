param(
    [string]$Binary = "..\target\aarch64-pc-windows-msvc\release\ida-mcp.exe",
    [switch]$ExpectDebugger
)

$ErrorActionPreference = "Stop"

function Invoke-StdioCase {
    param([string[]]$Arguments)

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Resolve-Path $Binary).Path
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Arguments = (@("serve") + $Arguments) -join " "

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw "failed to start $Binary"
    }
    $stderrRead = $process.StandardError.ReadToEndAsync()
    $failure = $null
    try {
        $process.StandardInput.WriteLine('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"windows-debugger-gate","version":"0.1"},"capabilities":{}}}')
        $process.StandardInput.WriteLine('{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}')
        $process.StandardInput.WriteLine('{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
        $process.StandardInput.Flush()
        $process.StandardInput.Close()

        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline) {
            $remaining = [Math]::Max(
                1,
                [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
            )
            $read = $process.StandardOutput.ReadLineAsync()
            if (-not $read.Wait($remaining)) {
                throw "timed out waiting for tools/list"
            }
            $line = $read.Result
            if ($null -eq $line) {
                throw "server closed stdout before tools/list"
            }
            try {
                $message = $line | ConvertFrom-Json
            } catch {
                continue
            }
            if ($message.id -eq 2) {
                return $message
            }
        }
        throw "timed out waiting for tools/list"
    } catch {
        $failure = $_
        throw
    } finally {
        if (-not $process.HasExited) {
            $process.Kill()
        }
        $process.WaitForExit()
        if ($null -ne $failure) {
            $stderr = $stderrRead.Result.Trim()
            if ($stderr.Length -gt 0) {
                Write-Host "server stderr:`n$stderr"
            }
        }
        $process.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "missing server binary: $Binary"
}

$default = Invoke-StdioCase -Arguments @()
$defaultDebug = @($default.result.tools | Where-Object { $_.name.StartsWith("debug_") })
if ($defaultDebug.Count -ne 0) {
    throw "default Windows tools/list unexpectedly advertised debugger tools"
}

$enabled = Invoke-StdioCase -Arguments @("--enable-debugger")
$enabledDebug = @($enabled.result.tools | Where-Object { $_.name.StartsWith("debug_") })
if ($ExpectDebugger) {
    if (-not ($enabledDebug.name -contains "debug_status")) {
        throw "Windows debugger gate expected debug_status but it was not advertised"
    }
} elseif ($enabledDebug.Count -ne 0) {
    throw "Windows debugger tools were advertised before the native integration gate was enabled"
}

Write-Host "Windows native stdio debugger capability gate passed"
