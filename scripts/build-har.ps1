param(
    [ValidateSet('debug', 'release')][string]$BuildMode = 'release',
    [string]$NativeInstall,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'

# 只读取指定环境来源，避免把开发机路径写入可公开工程。
$TaskRepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (-not $NativeInstall) { $NativeInstall = Join-Path $TaskRepoRoot 'native/prebuilt/arm64-v8a' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $TaskRepoRoot 'dist' }
$TaskSdk = $null
foreach ($TaskScope in @('Process', 'User', 'Machine')) {
    $TaskCandidate = [Environment]::GetEnvironmentVariable('DEVECO_CLI_CLT_PATH', $TaskScope)
    if (-not [string]::IsNullOrWhiteSpace($TaskCandidate)) { $TaskSdk = $TaskCandidate; break }
}
if (-not $TaskSdk -or -not (Test-Path -LiteralPath $TaskSdk -PathType Container)) {
    throw 'DEVECO_CLI_CLT_PATH must identify the local Command Line Tools root'
}
$env:DEVECO_CLI_CLT_PATH = (Resolve-Path -LiteralPath $TaskSdk).Path
$TaskWorkspace = $TaskRepoRoot
& python (Join-Path $PSScriptRoot 'prepare.py') --native-install $NativeInstall
if ($LASTEXITCODE -ne 0) { throw 'HAR native input preparation failed' }

Push-Location -LiteralPath $TaskWorkspace
$TaskPreviousStudio = [Environment]::GetEnvironmentVariable('DEVECO_CLI_STUDIO_PATH', 'Process')
try {
    # CLI 优先使用 Studio 覆盖值；本工程显式限定为已核实的 CLT。
    Remove-Item Env:DEVECO_CLI_STUDIO_PATH -ErrorAction SilentlyContinue
    & devecocli.cmd check arkts library/Index.ets --project $TaskWorkspace
    if ($LASTEXITCODE -ne 0) { throw 'libssh2-oh ArkTS entry check failed' }
    & devecocli.cmd build --modules libssh2_oh --assemble-type assembleHar --build-mode $BuildMode
    if ($LASTEXITCODE -ne 0) { throw 'libssh2-oh HAR build failed' }
} finally {
    if ($null -ne $TaskPreviousStudio) { $env:DEVECO_CLI_STUDIO_PATH = $TaskPreviousStudio }
    Pop-Location
}

# 固定产物名称便于离线安装；保留 Hvigor 原始输出并审计复制后的最终包。
$TaskBuiltHar = Join-Path $TaskWorkspace 'library/build/default/outputs/default/libssh2_oh.har'
if (-not (Test-Path -LiteralPath $TaskBuiltHar -PathType Leaf)) {
    throw 'Expected HAR output was not generated'
}
$TaskOutputDir = $OutputDirectory
New-Item -ItemType Directory -Force -Path $TaskOutputDir | Out-Null
$TaskOutput = Join-Path $TaskOutputDir 'libssh2-oh-0.1.1.har'
Copy-Item -LiteralPath $TaskBuiltHar -Destination $TaskOutput -Force
& python (Join-Path $PSScriptRoot 'prepare.py') --verify-har $TaskOutput
if ($LASTEXITCODE -ne 0) { throw 'HAR content audit failed' }
$TaskHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $TaskOutput).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($TaskOutput + '.sha256'), ($TaskHash + '  libssh2-oh-0.1.1.har' + "`n"))
Get-FileHash -Algorithm SHA256 -LiteralPath $TaskOutput
