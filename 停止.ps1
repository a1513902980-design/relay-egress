# 停止.ps1 —— 关掉这个文件夹拉起来的一切（浏览器 / 网关 / 隧道）。卸载 = 直接删文件夹。
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$HERE = $PSScriptRoot
$CFG = Join-Path $HERE '配置.json'
$GWD = Join-Path $HERE 'run'
$PROF = Join-Path $HERE 'browser-profile'
$TP = 1080; $GP = 8877
if (Test-Path $CFG) { try { $c = Get-Content $CFG -Raw -Encoding UTF8 | ConvertFrom-Json; if ([int]$c.tunnelPort) { $TP = [int]$c.tunnelPort }; if ([int]$c.gatewayPort) { $GP = [int]$c.gatewayPort } } catch { } }

Write-Output "== 关浏览器窗口（只关它自己的 profile）=="
$n = 0
$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -and ($_.CommandLine -like ("*" + $PROF + "*")) }
foreach ($p in $procs) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue; $n++ }
Write-Output ("   关掉 " + $n + " 个进程")

Write-Output "== 停网关（唯一出网口）=="
$g = Get-NetTCPConnection -LocalPort $GP -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($g) { Stop-Process -Id $g.OwningProcess -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1 }
Remove-Item (Join-Path $GWD 'state.json') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $GWD 'gateway.pid') -Force -ErrorAction SilentlyContinue
if (Get-NetTCPConnection -LocalPort $GP -State Listen -ErrorAction SilentlyContinue) { Write-Output ("   [!] " + $GP + " 仍在监听") } else { Write-Output ("   [OK] " + $GP + " 已停") }

Write-Output "== 关隧道 =="
$t = Get-NetTCPConnection -LocalPort $TP -State Listen -ErrorAction SilentlyContinue
if ($t) {
  $t | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 1
}
if (Get-NetTCPConnection -LocalPort $TP -State Listen -ErrorAction SilentlyContinue) { Write-Output ("   [!] " + $TP + " 仍在监听") } else { Write-Output ("   [OK] " + $TP + " 已停") }
Write-Output "全停。卸载：删掉整个文件夹即可（不改系统任何东西）。"
