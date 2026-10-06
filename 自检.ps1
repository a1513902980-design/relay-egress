# 自检.ps1 —— 不需要 VPS 也能跑：验证这个网关「不会偷偷直连」的 9 条性质。
# 全部在本机回环上跑（起一个假隧道、一个回显服务），不碰外网、不改系统、不要管理员。
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$HERE = $PSScriptRoot
$s = Join-Path $HERE 'gw_selftest.mjs'
if (-not (Test-Path $s)) { Write-Output ("找不到 gw_selftest.mjs：" + $s); exit 2 }
$node = 'node'
$cfg = Join-Path $HERE '配置.json'
if (Test-Path $cfg) { try { $c = Get-Content $cfg -Raw -Encoding UTF8 | ConvertFrom-Json; if ("$($c.nodePath)" -ne '') { $node = "$($c.nodePath)" } } catch { } }
& $node $s
exit $LASTEXITCODE
