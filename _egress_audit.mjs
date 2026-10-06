#!/usr/bin/env node
/*
 * _egress_audit.mjs —— 只读「出网进程审计」（C 方案的第三层证据，不需要管理员）
 *
 * 它回答一个问题：我们这条链路上的进程，有没有谁偷偷直连出去？
 *   链路进程 = 网关(8877 监听者) + 抓包层(8899 监听者) + 抓包层的工作进程(whistle/pfork) + 抓包浏览器(本机独立 profile)
 *   判定     = 这些进程持有的连接里，远端地址不是回环的条数（必须为 0）
 *
 * 只读：不杀进程、不改配置、不需要管理员。它只读两张系统表（netstat / Win32_Process）。
 * 用法：
 *   node tools\_egress_audit.mjs [--gw-port 8877] [--layer-port 8899] [--profile <dir>] [--json] [--verbose]
 *                               [--no-descendants] [--ps-net]
 *   --no-descendants  只用"按端口/命令行抓进程"的旧口径（不带子进程），用于 A/B 对照
 *   --ps-net          连接表改用 Get-NetTCPConnection（慢 3 秒以上，仅用于 A/B 对照；默认走 netstat）
 * 输出（ASCII 键=值，给 PowerShell 解析）：
 *   AUDIT_CHAIN=5            本链路进程数（含子进程；加固前是"只按端口/命令行"的旧口径）
 *   AUDIT_DESC=0             其中靠"子进程追加"这条加固进来的个数
 *   AUDIT_ESTABLISHED=41     这些进程持有的连接总数
 *   AUDIT_NONLOOPBACK=0      其中远端不是回环的条数（必须 0）
 *   AUDIT_LEAK=pid=123 remote=1.2.3.4:443 name=node state=ESTABLISHED   （每条泄漏一行）
 *   AUDIT_OTHERS=8           全机非回环连接总数（供人看，别家的进程也算，仅参考）
 *   AUDIT_SCAN=netstat onepass conns=312 used=146      本次扫描方式与规模
 *   AUDIT_STATES=...         链路上连接的按状态计数（--verbose 才打印，排障用）
 *   AUDIT_TW=...             链路上进程的 TIME_WAIT 统计（**仅参考**，不参与判定，见文末注释）
 *   AUDIT_MS=812             这次审计自己花了多少毫秒（连续采样时要盯的成本）
 *   AUDIT_OK / AUDIT_LEAK
 * exit 0 = 干净；exit 1 = 有泄漏或审计本身失败（失败一律按"不干净"处理）
 *
 * 2026-10-06 第二轮改动（为「连续采样」做的三轮性能改造，每一步都留了 A/B 开关）：
 *   · 起因：运行期守卫改成"每 45 秒都查一次审计"，就得先把单次成本压下来。
 *   · 第一轮（进程表）：旧版每轮调用 PowerShell 的 Get-NetTCPConnection 一"个进程"一次（O(进程数) 次 cmdlet 调用）。
 *     改成进程表取 1 次、连接表取 1 次，余下在内存里算。
 *   · 第二轮（连接表）：量到单次仍要 5.5~7.1s，拆开成本：PS 启动 0.36s ／ Win32_Process 全表 0.42s
 *     ／ **Get-NetTCPConnection 1.5~2.8s** ／ netstat -ano -p TCP 0.05~0.10s ⇒ 连接表改用 netstat。
 *     语义不变（仍只看同样这 7 种状态），状态名在中文 Windows 上仍是英文，行内按空白分列。
 *   · 第三轮（监听者）：最后还剩两个 `Get-NetTCPConnection -LocalPort … -State Listen`（实测各 1.2~2.1s），
 *     改从**同一次 netstat** 的 LISTENING 行里取监听者 PID ⇒ 全程只有 1 次 netstat + 1 次 Win32_Process。
 *   · 对照结果见 out\_audit_perf.txt（同一时刻交替跑，判定必须完全一致）。
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const argOf = (n, d) => {
  const i = argv.indexOf('--' + n);
  const v = i !== -1 ? argv[i + 1] : undefined;
  return v && !String(v).startsWith('--') ? String(v) : d;
};
const GWPORT = argOf('gw-port', '8877');
const LPORT = argOf('layer-port', '8899');
// 2026-10-06 加固：默认把链路上进程的**子进程**也算进链路（T-C2 实测出过一个缺口：
// 假网关把"直连出去"这个动作丢给子进程做，只按端口/命令行抓进程的旧版审计看不见它）。
// --no-descendants 保留旧口径，用于 A/B 对照（证明这条加固确实补上了那个缺口）。
const NODESC = argv.includes('--no-descendants');
// 连接表默认用 netstat（快 30 倍以上）。--ps-net 走老的 Get-NetTCPConnection 路径，
// 用来做 A/B（证明换扫描方式后判定结果一致），也是 netstat 用不了时的对照口径。
const PSNET = argv.includes('--ps-net');
const HERE = path.dirname(fileURLToPath(import.meta.url));
const WF = path.dirname(HERE);
// profile 的默认值：本机工作流布局（tools\whistle\browser-profile）优先，其次用"打包给别人用"那种布局（与本脚本同级）
const DEF_PROFILE = fs.existsSync(path.join(WF, 'tools', 'whistle', 'browser-profile'))
  ? path.join(WF, 'tools', 'whistle', 'browser-profile')
  : path.join(WF, 'browser-profile');
const PROFILE = argOf('profile', DEF_PROFILE);
const VERBOSE = argv.includes('--verbose');

function ps(script) {
  return new Promise((resolve) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script],
      { windowsHide: true, maxBuffer: 8 * 1024 * 1024, timeout: 60000 },
      (err, stdout) => resolve(err && !stdout ? '' : String(stdout || '')));
  });
}

const esc = (s) => String(s).replace(/'/g, "''");
const DESC = !NODESC;
// PowerShell 的布尔字面量必须写 $true/$false：写成裸 true 会被当成"命令名"去执行，
// 在 $ErrorActionPreference='SilentlyContinue' 下错误被吞掉、条件静默变成假
// —— 2026-10-06 实测踩过：整块加固代码没跑，而输出看上去一切正常。
const DESCPS = DESC ? '$true' : '$false';
const PSNETPS = PSNET ? '$true' : '$false';
const SCRIPT = `
$ErrorActionPreference = 'SilentlyContinue'
$gw = ${GWPORT}; $lp = ${LPORT}; $prof = '${esc(PROFILE)}'
# 看哪几种连接状态（"一端 FIN 之后"的连接会落到 CloseWait/FinWait，只看 Established 会漏）
$stateList = @('Established','SynSent','SynReceived','CloseWait','FinWait1','FinWait2','LastAck')
$nsSet = @{ 'ESTABLISHED'=1; 'SYN_SENT'=1; 'SYN_RECEIVED'=1; 'CLOSE_WAIT'=1; 'FIN_WAIT_1'=1; 'FIN_WAIT_2'=1; 'LAST_ACK'=1 }

# ===== scan 1: 连接表（一次）。同时拿到监听者 PID、看判定的连接、以及仅参考的 TIME_WAIT =====
$scanKind = 'netstat'
$scannedRows = 0
$listenPids = @{}
$conns = @()
$twAll = @()
if (${PSNETPS}) {
  # --- 老口径（慢，仅 A/B 对照）：监听者与连接都走 Get-NetTCPConnection ---
  $scanKind = 'ps'
  foreach ($p in @($gw, $lp)) {
    $l = Get-NetTCPConnection -LocalPort $p -State Listen | Select-Object -First 1
    if ($l) { $listenPids[[string]$p] = [int]$l.OwningProcess }
  }
  $allConn = @(Get-NetTCPConnection -State $stateList)
  $scannedRows = @($allConn).Count
  foreach ($c in $allConn) {
    $conns += [pscustomobject]@{ pid = [int]$c.OwningProcess; state = [string]$c.State;
      remote = [string]$c.RemoteAddress; rport = [string]$c.RemotePort }
  }
  foreach ($ln in @(netstat -ano -p TCP)) {
    $t = @($ln.Trim() -split '\\s+')
    if ($t.Count -ge 5 -and $t[0] -eq 'TCP' -and $t[3].ToUpper() -eq 'TIME_WAIT' -and $t[4] -match '^[0-9]+$') {
      $rr = [string]$t[2]; $ri = $rr.LastIndexOf(':')
      $twAll += [pscustomobject]@{ pid = [int]$t[4]; remote = $(if ($ri -gt 0) { $rr.Substring(0, $ri).Trim('[', ']') } else { $rr }) }
    }
  }
} else {
  # --- 快口径：一次 netstat 拿三样东西（监听者 / 判定用连接 / TIME_WAIT）---
  # 中文 Windows 上本行按空白分列：TCP  <本地地址>  <外部地址>  <状态>  <PID>，状态名是英文
  $nsRows = @(netstat -ano -p TCP)
  $scannedRows = @($nsRows).Count
  foreach ($ln in $nsRows) {
    $t = @($ln.Trim() -split '\\s+')
    if ($t.Count -lt 5) { continue }
    if ($t[0] -ne 'TCP') { continue }
    if ($t[4] -notmatch '^[0-9]+$') { continue }
    $pid2 = [int]$t[4]
    $st = $t[3].ToUpper()
    $local = [string]$t[1]
    $remote = [string]$t[2]
    if ($st -eq 'LISTENING') {
      $li = $local.LastIndexOf(':')
      if ($li -gt 0) {
        $port = $local.Substring($li + 1)
        if (($port -eq [string]$gw) -and (-not $listenPids.ContainsKey([string]$gw))) { $listenPids[[string]$gw] = $pid2 }
        if (($port -eq [string]$lp) -and (-not $listenPids.ContainsKey([string]$lp))) { $listenPids[[string]$lp] = $pid2 }
      }
      continue
    }
    $ri = $remote.LastIndexOf(':')
    if ($ri -lt 1) { continue }
    $raddr = $remote.Substring(0, $ri).Trim('[', ']')
    $rport = $remote.Substring($ri + 1)
    if ($st -eq 'TIME_WAIT') { $twAll += [pscustomobject]@{ pid = $pid2; remote = $raddr } ; continue }
    if (-not $nsSet.ContainsKey($st)) { continue }
    $conns += [pscustomobject]@{ pid = $pid2; state = $st; remote = $raddr; rport = $rport }
  }
  if ($conns.Count -eq 0 -and $scannedRows -gt 0) { $scanKind = 'netstat_empty' }
}

# ===== scan 2: 进程表（一次）。挑出链路进程，再补上它们的子进程（T-C2 的缺口）=====
$allPr = @(Get-CimInstance Win32_Process)
$pids = New-Object System.Collections.ArrayList
foreach ($p in @($gw, $lp)) { if ($listenPids.ContainsKey([string]$p)) { [void]$pids.Add([int]$listenPids[[string]$p]) } }
foreach ($pr in $allPr) {
  $cl = $pr.CommandLine
  if (-not $cl) { continue }
  if ($pr.Name -like 'node*') {
    if ($cl -match 'whistle|pfork|starting') { [void]$pids.Add([int]$pr.ProcessId) }
  } elseif ($pr.Name -eq 'msedge.exe') {
    if ($prof -ne '' -and ($cl -like ('*' + $prof + '*'))) { [void]$pids.Add([int]$pr.ProcessId) }
  }
}
$pids = @($pids | Where-Object { $_ -gt 0 } | Sort-Object -Unique)

$descAdded = 0
$descDbg = 'skipped'
if (${DESCPS}) {
  try {
    $inChain = @{}
    foreach ($x in $pids) { $inChain[[int]$x] = 1 }
    for ($d = 0; $d -lt 5; $d++) {
      $add = @()
      foreach ($pr in $allPr) {
        $cpid = [int]$pr.ProcessId
        if ($inChain.ContainsKey([int]$pr.ParentProcessId) -and (-not $inChain.ContainsKey($cpid))) { $add += $cpid }
      }
      if ($add.Count -eq 0) { break }
      foreach ($x in $add) { $inChain[[int]$x] = 1 }
      $descAdded += $add.Count
    }
    $pids = @($inChain.Keys | Sort-Object)
    $descDbg = 'all=' + $allPr.Count + ' chain=' + $inChain.Count + ' added=' + $descAdded
  } catch { $descDbg = 'err=' + $_.Exception.Message }
}

# ===== 判定：链路上这些进程，有没有谁连着非回环的远端 =====
$inSet = @{}
foreach ($x in $pids) { $inSet[[int]$x] = 1 }
$nm = @{}
$chainEst = 0
$rows = @()
$nonLoopAll = 0
$byState = @{}
foreach ($c in $conns) {
  $op = [int]$c.pid
  $ra = [string]$c.remote
  $non = ($ra -ne '' -and $ra -notlike '127.*' -and $ra -ne '::1' -and $ra -ne '0.0.0.0' -and $ra -ne '::')
  if ($non) { $nonLoopAll++ }
  if (-not $inSet.ContainsKey($op)) { continue }
  $chainEst++
  if (-not $byState.ContainsKey($c.state)) { $byState[$c.state] = 0 }
  $byState[$c.state]++
  if ($non) {
    if (-not $nm.ContainsKey($op)) { $px = Get-Process -Id $op; $nm[$op] = $(if ($px) { $px.ProcessName } else { '?' }) }
    $rows += [pscustomobject]@{ pid = $op; name = $nm[$op]; remote = ($ra + ':' + $c.rport); state = $c.state }
  }
}
$stateStr = ''
foreach ($k in ($byState.Keys | Sort-Object)) { $stateStr += ($k + '=' + $byState[$k] + ' ') }

foreach ($c in ($conns | Where-Object {
      $_.remote -ne '' -and $_.remote -notlike '127.*' -and $_.remote -ne '::1' -and $_.remote -ne '0.0.0.0' -and $_.remote -ne '::'
    } | Select-Object -First 12)) {
  $op = [int]$c.pid
  if (-not $nm.ContainsKey($op)) { $px = Get-Process -Id $op; $nm[$op] = $(if ($px) { $px.ProcessName } else { '?' }) }
  $others += ($nm[$op] + '@' + $c.remote + ':' + $c.rport)
}

# --- 仅参考、不参与判定：链路上进程的 TIME_WAIT（泄漏连接 FIN 之后会在这儿停留 2~4 分钟）---
# 暂不并入判定：T-C 三态是用上面这 7 种状态验过的，换集合就要把三态重新验一遍（见 10_C方案…txt 待办）。
$twChain = 0; $twNon = 0
foreach ($c in $twAll) {
  if (-not $inSet.ContainsKey([int]$c.pid)) { continue }
  $twChain++
  $ra = [string]$c.remote
  if ($ra -ne '' -and $ra -notlike '127.*' -and $ra -ne '::1' -and $ra -ne '0.0.0.0' -and $ra -ne '::') { $twNon++ }
}

[pscustomobject]@{ chainPids = $pids; chainEstablished = $chainEst; nonLoopAll = $nonLoopAll;
  descendants = $descAdded; descDbg = $descDbg; scans = $scanKind; connsScanned = $scannedRows;
  connsUsed = @($conns).Count; byState = $stateStr.Trim(); twChain = $twChain; twNon = $twNon;
  listenGw = $(if ($listenPids.ContainsKey([string]$gw)) { $listenPids[[string]$gw] } else { 0 });
  listenLp = $(if ($listenPids.ContainsKey([string]$lp)) { $listenPids[[string]$lp] } else { 0 });
  leaks = @($rows); others = @($others) } | ConvertTo-Json -Compress -Depth 5
`;

const t0 = Date.now();
const raw = await ps(SCRIPT);
const ms = Date.now() - t0;
if (argv.includes('--json')) console.log('AUDIT_RAW_JSON=' + raw.trim());
if (argv.includes('--json')) console.log('AUDIT_PS_HAVE_DESC_IF=' + (SCRIPT.match(/if \((\$true|\$false)\) \{/) || ['none'])[0]);
if (argv.includes('--json')) console.log('AUDIT_DESC_MODE=' + (DESC ? 'on' : 'off'));
let j = null;
try { j = JSON.parse(raw.trim()); } catch { /* ignore */ }
if (!j) {
  console.log('AUDIT_FAIL=audit_script_no_json');
  console.log('AUDIT_RAW=' + raw.trim().slice(0, 200).replace(/\r?\n/g, ' '));
  console.log('AUDIT_MS=' + ms);
  console.log('AUDIT_LEAK');
  process.exit(1);
}
const chain = j.chainPids || [];
const leaks = j.leaks || [];
const scan = String(j.scans || 'unknown');
console.log('AUDIT_CHAIN=' + chain.length);
console.log('AUDIT_DESC=' + (j.descendants || 0) + ' ' + (j.descDbg || ''));
console.log('AUDIT_ESTABLISHED=' + (j.chainEstablished || 0));
console.log('AUDIT_NONLOOPBACK=' + leaks.length);
console.log('AUDIT_OTHERS=' + (j.nonLoopAll || 0));
for (const l of leaks) console.log('AUDIT_LEAK=pid=' + l.pid + ' remote=' + l.remote + ' name=' + l.name + ' state=' + (l.state || '?'));
if (VERBOSE && j.others && j.others.length) console.log('AUDIT_OTHERS_SAMPLE=' + j.others.join(' '));
if (VERBOSE) console.log('AUDIT_STATES=' + (j.byState || '') + ' | listenGw=' + (j.listenGw || 0) + ' listenLp=' + (j.listenLp || 0));
console.log('AUDIT_SCAN=' + scan + ' onepass conns=' + (j.connsScanned || 0) + ' used=' + (j.connsUsed || 0));
console.log('AUDIT_TW=chain_timewait=' + (j.twChain || 0) + ' nonloop=' + (j.twNon || 0) + ' (informational)');
console.log('AUDIT_MS=' + ms);
// netstat 用不了（一行都解析不出来）时按"审计失败"处理：宁可报不干净，也不静默放过。
const scanBad = scan === 'netstat_empty';
console.log(!scanBad && leaks.length === 0 ? 'AUDIT_OK' : 'AUDIT_LEAK');
process.exit(!scanBad && leaks.length === 0 ? 0 : 1);
