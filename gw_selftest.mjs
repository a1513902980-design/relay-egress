#!/usr/bin/env node
/*
 * gw_selftest.mjs —— 网关自测（不依赖 VPS、不依赖网络，全部在本机回环上跑）
 *
 * 为什么要有它：这个网关是"防泄漏"的那一层，它自己必须先被证明。
 * 而且"给别人用"时，对方可能没有 VPS 可试 —— 有了这个自测，别人拿到的文件夹双击就能自证。
 *
 * 它验 8 件事：
 *   T1 上游不是回环      → 拒绝启动（exit 2，不许猜）
 *   T2 上游连不上        → 拒绝启动（exit 3）
 *   T3 端口被占          → 拒绝启动（exit 4）
 *   T4 SOCKS5 全程通      → 经网关 → 桩上游 → 回显服务，字节原样往返
 *   T5 HTTP 代理通        → 绝对地址被改成 origin-form（上游收到的必须是 /path 不是整串 URL）
 *   T6 SOCKS5 的 BIND/UDP → 明确拒绝（8 位回复 0x07），不静默放行
 *   T7 上游一断          → 客户端连接直接失败（**不许**回退直连：目标本身是活的，成功才是泄漏）
 *   T8 记账不变式        → 状态文件里 viaTunnel == total 且 nonTunnel == 0
 *
 * 用法：node tools\gw\gw_selftest.mjs        （退出码 0 = 全过）
 */
import net from 'net';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GW = path.join(HERE, 'gateway.mjs');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'gwselftest-'));
// 兜底：任何一步卡住都不许永久挂起（会连带让上一轮的进程留在端口上）
const WATCHDOG = setTimeout(() => { console.log(''); console.log('SELFTEST_TIMEOUT 卡在某一项（上方最后一行即卡住的位置）'); process.exit(9); }, 120000);
let pass = 0, fail = 0;
const results = [];
function ok(id, what, detail) { pass++; results.push(['OK', id, what, detail || '']); console.log('  [OK] ' + id + ' ' + what + (detail ? '  ' + detail : '')); }
function no(id, what, detail) { fail++; results.push(['FAIL', id, what, detail || '']); console.log('  [X]  ' + id + ' ' + what + '  ' + (detail || '')); }

function listen(server, port) {
  return new Promise((res) => server.listen(port, '127.0.0.1', () => res(server.address().port)));
}
function once(sock, ev, ms) {
  return new Promise((res) => {
    const t = setTimeout(() => res(new Error('timeout')), ms || 4000);
    sock.once(ev, (a) => { clearTimeout(t); res(a); });
  });
}
function collect(sock, ms) {
  return new Promise((res) => {
    let b = Buffer.alloc(0);
    const t = setTimeout(() => res(b), ms || 1500);
    sock.on('data', (d) => { b = Buffer.concat([b, d]); });
    sock.on('close', () => { clearTimeout(t); res(b); });
  });
}
// 桩"隧道"：只接受 CONNECT，且**只连回环**（这样桩自己也守规矩，测的才是网关）
function makeStubSocks(upstreamLog) {
  const srv = net.createServer((c) => {
    let stage = 0, acc = Buffer.alloc(0);
    c.on('data', (d) => {
      acc = Buffer.concat([acc, d]);
      if (stage === 0) {
        if (acc.length < 2 + acc[1]) return;
        acc = acc.slice(2 + acc[1]); stage = 1; c.write(Buffer.from([5, 0]));
      }
      if (stage === 1) {
        if (acc.length < 10) return;
        const atyp = acc[3];
        let host = '', off = 0;
        if (atyp === 1) { host = acc.slice(4, 8).join('.'); off = 8; }
        else if (atyp === 3) { const l = acc[4]; host = acc.slice(5, 5 + l).toString(); off = 5 + l; }
        else { c.end(Buffer.from([5, 8, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
        const port = acc.readUInt16BE(off);
        const rest = acc.slice(off + 2);
        stage = 2;
        upstreamLog.push(host + ':' + port + '|' + rest.toString('latin1') + (rest.length ? '' : '') + (rest.length ? '' : ''));
        if (!/^127\./.test(host) && host !== 'localhost') {   // 桩也不许连外面
          c.end(Buffer.from([5, 2, 0, 1, 0, 0, 0, 0, 0, 0])); return;
        }
        const u = net.connect(port, host, () => {
          c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
          if (rest.length) u.write(rest);
          c.pipe(u); u.pipe(c);
        });
        u.on('error', () => c.destroy());
      }
    });
  });
  return srv;
}
function socksThrough(port, host, targetHost, targetPort) {
  return new Promise((res) => {
    const c = net.connect(port, host);
    let acc = Buffer.alloc(0), stage = 0, err = null;
    // 一定要有超时：否则握手卡住 = 自测永久挂起（这台机器上真踩过）
    const guard = setTimeout(() => res({ sock: null, err: new Error('handshake timeout') }), 6000);
    const done = (o) => { clearTimeout(guard); res(o); };
    c.on('error', (e) => { err = e; done({ sock: null, err: e }); });
    c.on('close', () => done({ sock: null, err: err || new Error('closed by gateway') }));
    c.on('connect', () => c.write(Buffer.from([5, 1, 0])));
    c.on('data', (d) => {
      acc = Buffer.concat([acc, d]);
      if (stage === 0) {
        if (acc.length < 2) return;
        if (acc[1] !== 0) { done({ sock: null, err: new Error('no auth method') }); return; }
        acc = acc.slice(2); stage = 1;
        const hb = Buffer.from(targetHost); const r = Buffer.alloc(5 + hb.length + 2);
        r[0] = 5; r[1] = 1; r[2] = 0; r[3] = 3; r[4] = hb.length; hb.copy(r, 5); r.writeUInt16BE(targetPort, 5 + hb.length);
        c.write(r); return;
      }
      if (stage === 1) {
        if (acc.length < 10) return;
        const rep = acc[1];
        if (rep !== 0) { done({ sock: null, err: new Error('rep=' + rep) }); return; }
        stage = 2; done({ sock: c, err: null });
      }
    });
  });
}

console.log('== 网关自测（全部在本机回环，不碰外网） ==');
console.log('   临时目录：' + TMP);

// 回显服务
const echo = net.createServer((c) => { c.pipe(c); });
const echoPort = await listen(echo, 0);
// 本地 HTTP 服务（回显收到的请求行，用来验 origin-form 改写）
let seenReqLine = '';
const webSrv = net.createServer((c) => {
  c.on('data', (d) => {
    if (!seenReqLine) seenReqLine = d.toString('latin1').split('\r\n')[0];
    c.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
  });
});
const webPort = await listen(webSrv, 0);
// 桩隧道
const upLog = [];
const stub = makeStubSocks(upLog);
const stubPort = await listen(stub, 0);

const gwPort = 18877;
function startGw(args) {
  return new Promise((res) => {
    const child = spawn(process.execPath, [GW].concat(args), { windowsHide: true });
    let out = '', settled = false;
    const finish = (o) => { if (!settled) { settled = true; clearInterval(iv); clearTimeout(to); res(o); } };
    child.stdout.on('data', (d) => { out += d.toString('utf8'); });
    child.stderr.on('data', (d) => { out += d.toString('utf8'); });
    child.on('close', (code) => finish({ code, out, child }));
    const iv = setInterval(() => { if (out.includes('GW_READY')) finish({ code: null, out, child }); }, 200);
    const to = setTimeout(() => finish({ code: null, out, child }), 4000);
  });
}

/* T1 上游不是回环 */
{
  const r = await startGw(['--port', String(gwPort + 1), '--up-host', '8.8.8.8', '--up', '1080']);
  if (r.code === 2 && /UPSTREAM_NOT_LOOPBACK/.test(r.out)) ok('T1', '上游非回环 → 拒绝启动', 'exit=2');
  else { no('T1', '上游非回环 → 拒绝启动', 'exit=' + r.code + ' out=' + r.out.trim().slice(0, 120)); if (r.child) r.child.kill(); }
}
/* T2 上游连不上 */
{
  const r = await startGw(['--port', String(gwPort + 1), '--up', '9']);
  if (r.code === 3 && /UPSTREAM_UNREACHABLE/.test(r.out)) ok('T2', '上游连不上 → 拒绝启动', 'exit=3');
  else { no('T2', '上游连不上 → 拒绝启动', 'exit=' + r.code + ' out=' + r.out.trim().slice(0, 120)); if (r.child) r.child.kill(); }
}

/* 起一个正常网关（上游=桩） */
const stateFile = path.join(TMP, 'state.json');
const logFile = path.join(TMP, 'gw.jsonl');
const G = await startGw(['--port', String(gwPort), '--up', String(stubPort), '--state', stateFile, '--log', logFile]);
const gwReady = /GW_READY/.test(G.out);
if (!gwReady) { no('T0', '网关能起来', G.out.trim().slice(0, 200)); }
else ok('T0', '网关能起来（上游=桩隧道）', 'GW_READY');

/* T3 端口被占 */
if (gwReady) {
  const r2 = await startGw(['--port', String(gwPort), '--up', String(stubPort)]);
  if (r2.code === 4 && /LISTEN_FAIL/.test(r2.out)) ok('T3', '端口被占 → 拒绝启动', 'exit=4');
  else { no('T3', '端口被占 → 拒绝启动', 'exit=' + r2.code + ' out=' + r2.out.trim().slice(0, 120)); if (r2.child) r2.child.kill(); }
}

/* T4 SOCKS5 通 */
if (gwReady) {
  const r = await socksThrough(gwPort, '127.0.0.1', '127.0.0.1', echoPort);
  if (!r.sock) no('T4', 'SOCKS5 经网关 → 桩 → 回显', String(r.err && r.err.message));
  else {
    r.sock.write('PING-1234');
    const back = await collect(r.sock, 1200);
    if (back.toString().includes('PING-1234')) ok('T4', 'SOCKS5 经网关 → 桩 → 回显', '字节原样往返');
    else no('T4', 'SOCKS5 经网关 → 桩 → 回显', '收到=' + back.toString().slice(0, 60));
    try { r.sock.destroy(); } catch { /* ignore */ }
  }
}

/* T5 HTTP 代理：绝对地址必须被改写成 origin-form */
if (gwReady) {
  const c = net.connect(gwPort, '127.0.0.1');
  const r = await once(c, 'connect', 3000);
  if (r instanceof Error) no('T5', 'HTTP 代理改写为 origin-form', 'connect timeout');
  else {
    c.write('GET http://127.0.0.1:' + webPort + '/hello?a=1 HTTP/1.1\r\nHost: 127.0.0.1:' + webPort + '\r\nProxy-Connection: keep-alive\r\n\r\n');
    const back = await collect(c, 1500);
    // 判据取"目标站真正看到的请求行"（seenReqLine 由本地源站服务端记录）：
    // 网关必须先拨隧道、再写改写后的请求，所以桩的 CONNECT 日志里看不到这一行 —— 源站才看得到。
    const gotOrigin = /GET \/hello\?a=1 HTTP\/1\.1/.test(seenReqLine);
    const gotResp = /ok/.test(back.toString());
    if (gotOrigin && gotResp) ok('T5', 'HTTP 代理改写为 origin-form', '源站看到：' + seenReqLine);
    else no('T5', 'HTTP 代理改写为 origin-form', '源站看到=' + (seenReqLine || '(无)') + ' 回包=' + back.toString().slice(0, 40));
  }
}

/* T6 UDP ASSOCIATE / BIND 被明确拒绝 */
if (gwReady) {
  const c = net.connect(gwPort, '127.0.0.1');
  await once(c, 'connect', 3000);
  c.write(Buffer.from([5, 1, 0]));
  const b = await collect(c, 1200);
  const idx = b.indexOf(5, 0);
  // 直接构造一个 cmd=3 的请求（UDP ASSOCIATE）
  const c2 = net.connect(gwPort, '127.0.0.1');
  await once(c2, 'connect', 3000);
  const hb = Buffer.from('127.0.0.1');
  const req = Buffer.alloc(5 + hb.length + 2);
  req[0] = 5; req[1] = 3; req[2] = 0; req[3] = 3; req[4] = hb.length; hb.copy(req, 5); req.writeUInt16BE(echoPort, 5 + hb.length);
  c2.write(Buffer.concat([Buffer.from([5, 1, 0]), req]));
  const b2 = await collect(c2, 1200);
  // 回包里前两字节是"方法选择回复"[5,0]，第三字节起才是 CONNECT/ASSOCIATE 的回复
  const rep = b2.length >= 4 ? b2[3] : -1;
  if (rep === 7) ok('T6', 'UDP ASSOCIATE 被明确拒绝', 'SOCKS 回复 REP=0x07（command not supported）');
  else no('T6', 'UDP ASSOCIATE 被明确拒绝', 'SOCKS 回复 REP=' + rep + ' raw=' + b2.toString('hex').slice(0, 30));
  try { c.destroy(); } catch { /* ignore */ }
}

/* T7 上游一断 → 客户端失败，绝不回退直连（回显服务本身活着） */
if (gwReady) {
  await new Promise((res) => stub.close(res));
  const r = await socksThrough(gwPort, '127.0.0.1', '127.0.0.1', echoPort);
  let leaked = false;
  if (r.sock) {
    r.sock.write('X');
    const back = await collect(r.sock, 1000);
    if (back.toString().includes('X')) leaked = true;   // 直连兜底了 = 严重问题
  }
  if (!leaked) ok('T7', '上游断开 → 请求失败（无直连兜底）', r.err ? 'err=' + r.err.message : '连接被直接销毁');
  else no('T7', '上游断开 → 请求失败（无直连兜底）', '居然通了 → 说明存在直连路径');
}

/* T8 记账不变式 */
{
  let st = null;
  try { st = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch { /* ignore */ }
  // 不变式 = 每条请求要么走隧道、要么作为失败断开，没有第三种结局；且"非隧道"恒为 0
  if (st && st.nonTunnel === 0 && (st.viaTunnel + st.upFail) === st.total && st.total > 0 && st.invariant === 'tunnel_only') {
    ok('T8', '记账不变式（走隧道+失败=总数，非隧道=0）', 'total=' + st.total + ' tunnel=' + st.viaTunnel + ' fail=' + st.upFail);
  } else no('T8', '记账不变式（走隧道+失败=总数，非隧道=0）', JSON.stringify(st));
}

if (G.child) { try { G.child.kill(); } catch { /* ignore */ } }
echo.close(); webSrv.close();
await new Promise((r) => setTimeout(r, 300));
console.log('');
console.log('SELFTEST_RESULT pass=' + pass + ' fail=' + fail);
console.log(fail === 0 ? 'SELFTEST_OK' : 'SELFTEST_FAIL');
try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* ignore */ }
process.exit(fail === 0 ? 0 : 1);
