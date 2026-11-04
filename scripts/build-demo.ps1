$ErrorActionPreference = 'Stop'
$TaskRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$TaskDemo = Join-Path $TaskRoot 'demo'
$TaskManifestPath = Join-Path $TaskRoot 'library/include/libssh2-oh-manifest.json'
if (-not (Test-Path -LiteralPath (Join-Path $TaskRoot 'dist/libssh2-oh-0.1.0.har')) -or
    -not (Test-Path -LiteralPath $TaskManifestPath)) {
    throw 'Build the library HAR with scripts/build-har.ps1 first'
}
$TaskExpectedArchive = (Get-Content -Raw -LiteralPath $TaskManifestPath | ConvertFrom-Json).archiveSha256
$TaskSdk = $null
foreach ($TaskScope in @('Process', 'User', 'Machine')) {
    $TaskValue = [Environment]::GetEnvironmentVariable('DEVECO_CLI_CLT_PATH', $TaskScope)
    if ($TaskValue) { $TaskSdk = (Resolve-Path -LiteralPath $TaskValue).Path; break }
}
if (-not $TaskSdk) { throw 'DEVECO_CLI_CLT_PATH is required' }
$env:DEVECO_CLI_CLT_PATH = $TaskSdk
$TaskOldStudio = $env:DEVECO_CLI_STUDIO_PATH
Push-Location -LiteralPath $TaskDemo
try {
    Remove-Item Env:DEVECO_CLI_STUDIO_PATH -ErrorAction SilentlyContinue
    & (Join-Path $TaskSdk 'bin/ohpm.bat') install --all
    if ($LASTEXITCODE -ne 0) { throw 'Demo dependency installation failed' }
    # 版本号相同不代表静态库相同，构建前核对实际安装的 HAR 依赖。
    $TaskArchive = @('entry/oh_modules/libssh2-oh/libs/arm64-v8a/libssh2.a',
        'oh_modules/libssh2-oh/libs/arm64-v8a/libssh2.a') |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $TaskArchive -or (Get-FileHash -LiteralPath $TaskArchive).Hash.ToLowerInvariant() -ne $TaskExpectedArchive) {
        throw 'Demo dependency differs from the current library build'
    }
    & devecocli.cmd check arkts entry/src/main/ets/pages/Index.ets entry/src/main/ets/entryability/EntryAbility.ets --project $TaskDemo
    if ($LASTEXITCODE -ne 0) { throw 'Demo ArkTS precheck failed' }
    # 外部静态 .a 的变化不一定触发 Hvigor 增量重链，始终重新构建当前 demo。
    & devecocli.cmd build clean
    if ($LASTEXITCODE -ne 0) { throw 'Demo clean failed' }
    & devecocli.cmd build --modules entry
    if ($LASTEXITCODE -ne 0) { throw 'Demo build failed' }
} finally {
    Pop-Location
    if ($null -ne $TaskOldStudio) { $env:DEVECO_CLI_STUDIO_PATH = $TaskOldStudio }
}
$TaskBase = Join-Path $TaskDemo 'entry/build/default/outputs/default/entry-default'
$TaskHap = if (Test-Path -LiteralPath ($TaskBase + '-signed.hap')) {
    $TaskBase + '-signed.hap'
} else { $TaskBase + '-unsigned.hap' }
if (-not (Test-Path -LiteralPath $TaskHap)) { throw 'Expected demo HAP is missing' }
$TaskLibraries = @(& jar tf $TaskHap | Where-Object { $_ -match '(^|/)libs?/.*\.so$' })
if ($TaskLibraries.Count -ne 2 -or @($TaskLibraries | Where-Object {
    $_ -notmatch '/(libohdemo|libc\+\+_shared)\.so$'
}).Count -gt 0) { throw 'Unexpected demo native libraries' }
Get-FileHash -Algorithm SHA256 -LiteralPath $TaskHap
