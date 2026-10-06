# 启动.ps1  [-Url "https://..."] [-NoBrowser]   —— 一键：隧道 + 网关 + 浏览器
# 这个文件夹做什么：让浏览器的每一个请求都从你自己的 VPS 出去（本机只做渲染与解密，VPS 只搬密文）。
# 为什么不会偷偷用你的家宽：唯一能拨号出去的是 gateway.mjs，它的代码里只有一条上游 = 127.0.0.1:<隧道端口>；
#                          隧道断了就是请求失败，没有"直连兜底"这条路径。
# 需要：Node 18+（只要 node 在 PATH 或 配置.json 的 nodePath 指对），你自己的 VPS + SSH 私钥。
# 不需要：管理员权限、系统证书库、系统代理、防火墙规则、任何第三方 npm 包。
param([string]$Url = '', [switch]$NoBrowser)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$HERE = $PSScriptRoot
$CFG  = Join-Path $HERE '配置.json'
$GW   = Join-Path $HERE 'gateway.mjs'
$GWD  = Join-Path $HERE 'run'
$GWLOG = Join-Path $GWD 'gateway.log'
$GWST  = Join-Path $GWD 'state.json'
$GWPIDF = Join-Path $GWD 'gateway.pid'
$PROF = Join-Path $HERE 'browser-profile'

function Say($s) { Write-Output $s }
function Fail($code, $msg) { Say ("[x] " + $msg); exit $code }

if (-not (Test-Path $CFG)) { Fail 2 ("找不到 配置.json：" + $CFG) }
if (-not (Test-Path $GW))  { Fail 2 ("找不到 gateway.mjs：" + $GW) }
$c = $null
try { $c = (Get-Content $CFG -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { Fail 2 "配置.json 读不了（JSON 格式错？）" }
$VPS = "$($c.vps)"; $KEY = "$($c.sshKey)"
$TP = [int]$c.tunnelPort; $GP = [int]$c.gatewayPort
if (-not $VPS -or $VPS -like '*你的服务器*') { Fail 2 "先在 配置.json 里填你自己的 vps（形如 root@1.2.3.4）" }
if (-not $TP) { $TP = 1080 }
if (-not $GP) { $GP = 8877 }
$NODE = if ("$($c.nodePath)" -ne '') { "$($c.nodePath)" } else { 'node' }
if (-not $Url) { $Url = if ("$($c.默认网址)" -ne '') { "$($c.默认网址)" } else { 'https://example.com/' } }
New-Item -ItemType Directory -Force -Path $GWD | Out-Null

Say "== 唯一出网口 · 一键 =="
Say ("   VPS = " + $VPS + " ；隧道 127.0.0.1:" + $TP + " ；网关 127.0.0.1:" + $GP)

function DirectExit() {
  $r = (& curl.exe --noproxy '*' -s -m 12 http://ip.3322.net 2>$null | Out-String).Trim()
  if ($r -match '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') { return $r } else { return '' }
}
function TunnelExit([int]$p) {
  $r = (& curl.exe -s -m 20 --socks5-hostname ("127.0.0.1:" + $p) https://ifconfig.me/ip 2>$null | Out-String).Trim()
  if ($r -match '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') { return $r } else { return '' }
}

Say "[1/3] 隧道（ssh -D，只由本机发起；VPS 不加任何监听）"
$listen = Get-NetTCPConnection -LocalPort $TP -State Listen -ErrorAction SilentlyContinue
if ($listen -and (TunnelExit $TP)) { Say ("   · 已在跑，出口 = " + (TunnelExit $TP)) }
else {
  if ($listen) { $listen | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 2 }
  if (-not (Test-Path $KEY)) { Fail 3 ("找不到私钥：" + $KEY + "（改 配置.json 的 sshKey）") }
  $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
  Start-Process -FilePath $ssh -ArgumentList @('-i', $KEY, '-N', '-D', ("127.0.0.1:" + $TP), '-o', 'BatchMode=yes',
    '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30', '-o', 'StrictHostKeyChecking=accept-new', $VPS) `
    -WindowStyle Hidden -RedirectStandardError (Join-Path $GWD 'tunnel.log')
  $ok = ''
  for ($i = 1; $i -le 8; $i++) { Start-Sleep -Seconds 2; $ok = TunnelExit $TP; if ($ok) { break } }
  if (-not $ok) { Fail 3 ("隧道没通。看 " + (Join-Path $GWD 'tunnel.log') + "；常见原因：私钥不对 / VPS 地址不对 / ssh 需要密码（本脚本用 BatchMode，不接受交互）") }
  Say ("   · 已开，出口 = " + $ok)
}

Say "[2/3] 网关（唯一出网口）"
$gwc = Get-NetTCPConnection -LocalPort $GP -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($gwc) { Stop-Process -Id $gwc.OwningProcess -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1 }
Start-Process -FilePath $NODE -ArgumentList @($GW, '--port', $GP, '--up', $TP, '--log', $GWLOG, '--state', $GWST, '--pid', $GWPIDF) -WindowStyle Hidden
$ready = $false
for ($i = 1; $i -le 12; $i++) { Start-Sleep -Seconds 1; if (Test-Path $GWLOG) { if ((Get-Content $GWLOG -Raw -Encoding UTF8) -like '*GW_READY*') { $ready = $true; break } } }
if (-not $ready) {
  $tail = ''
  if (Test-Path $GWLOG) { $tail = ((Get-Content $GWLOG -Tail 3 -Encoding UTF8) -join ' | ') }
  Fail 4 ("网关没起来。日志尾：" + $tail + "（端口被占 / node 版本太老 / 隧道没开 都可能）")
}
$d = DirectExit
$viaGw = (& curl.exe -s -m 20 -x ("http://127.0.0.1:" + $GP) http://ip.3322.net 2>$null | Out-String).Trim()
if (-not ($viaGw -match '^[0-9]{1,3}(\.[0-9]{1,3}){3}$')) { Fail 5 "经网关的请求没返回出口 IP（网关没转发成功）" }
if ($d -and ($viaGw -eq $d)) { Fail 6 ("经网关的出口 = 本机直连出口（" + $d + "）=> 这是泄漏，拒绝继续") }
Say ("   · 网关就绪：经它出去 = " + $viaGw + " ；本机直连 = " + $d + " （两者必须不同）")

Say "[3/3] 浏览器窗口（它自己的 profile，只走这个网关；不发任何直连）"
if ($NoBrowser) { Say "   · 按 -NoBrowser 跳过" ; Say ("MODE=READY gateway=127.0.0.1:" + $GP + " exit=" + $viaGw); exit 0 }
New-Item -ItemType Directory -Force -Path $PROF | Out-Null
$browser = @(
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $browser) { Fail 7 "没找到 Chrome/Edge；可自己加 --proxy-server=socks5://127.0.0.1:8877 启动任意浏览器" }
$old = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
       Where-Object { $_.CommandLine -and ($_.CommandLine -like ("*" + $PROF + "*")) }
if ($old) { foreach ($p in $old) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 2 }
Start-Process -FilePath $browser -ArgumentList @(
  ("--user-data-dir=" + $PROF),
  ("--proxy-server=socks5://127.0.0.1:" + $GP),
  "--proxy-bypass-list=<-loopback>",
  "--disable-quic",
  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
  "--no-first-run", "--no-default-browser-check", "--new-window", $Url
)
Say ("   · 已打开：" + $Url)
Say ""
Say "------------ 结论 ------------"
Say ("现在：这个窗口里每个请求都从你的 VPS 出去（出口 " + $viaGw + "）")
Say "验证：在窗口里打开 http://ip.3322.net —— 显示的必须是上面那个出口 IP，不是你家宽 IP"
Say ("停：双击 停止.ps1 ；卸载：删掉整个文件夹")
Say "注意：窗口能上网是因为网关在跑；网关一停，这个窗口就打不开网（这就是随时可停）"
Say "------------------------------"
Say ("MODE=READY gateway=127.0.0.1:" + $GP + " exit=" + $viaGw)
