param(
    [string]$ApkPath = 'C:\WorkSpace\Temp\AccessDexLikeSource\Tools\ASC\douyinneice.apk',
    [int]$Threads = 8,
    [int]$Warmup = 1,
    [int]$Samples = 3
)

$ErrorActionPreference = 'Stop'
& cargo build --release | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw ('cargo build --release exited with {0}' -f $LASTEXITCODE)
}
$binary = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\release\rust_ASC.exe'))
function Measure-Once {
    $output = & $binary findrefs --thread $Threads --debug $ApkPath string https 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw ('findrefs exited with {0}: {1}' -f $LASTEXITCODE, $output) }
    $match = [regex]::Match($output, '\[APK\] for_each_findrefs total=([0-9.]+) us')
    if (-not $match.Success) { throw 'findrefs core timing was not emitted' }
    return [double]$match.Groups[1].Value / 1000.0
}
function Normalize-ReferenceLine([string]$line) { return [regex]::Replace($line, '[\t ]+', ' ') }
1..$Warmup | ForEach-Object { [void](Measure-Once) }
$timings = @(1..$Samples | ForEach-Object { Measure-Once }) | Sort-Object
$median = $timings[[int](($timings.Count - 1) / 2)]
$referencePath = 'C:\WorkSpace\Temp\AccessDexLikeSource\rust_ASC\bench_findrefs_core.txt'
$actualPath = Join-Path $env:TEMP 'rust-asc-findrefs-actual.txt'
& $binary findrefs --thread $Threads $ApkPath string https -o $actualPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw ('findrefs correctness run exited with {0}' -f $LASTEXITCODE) }
$pattern = '^classes[^ ]* \| .* \| matched='
$reference = @(Select-String -LiteralPath $referencePath -Pattern $pattern | ForEach-Object { Normalize-ReferenceLine $_.Line })
$actual = @(Select-String -LiteralPath $actualPath -Pattern $pattern | ForEach-Object { Normalize-ReferenceLine $_.Line })
if ($reference.Count -ne $actual.Count) { throw ('reference count mismatch: expected {0}, got {1}' -f $reference.Count, $actual.Count) }
$referenceSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$reference)
$actualSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$actual)
if (-not $referenceSet.SetEquals($actualSet)) { throw 'reference content mismatch' }
Remove-Item -LiteralPath $actualPath -Force
Write-Output ('findrefs correctness: {0} lines, normalized exact set match' -f $actual.Count)
Write-Output ('METRIC findrefs_core_ms={0:F3}' -f $median)
Write-Output ('METRIC findrefs_core_min_ms={0:F3}' -f $timings[0])
Write-Output ('METRIC findrefs_core_max_ms={0:F3}' -f $timings[-1])
