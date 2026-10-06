#!/usr/bin/env node
/*
 * gateway.mjs —— C 方案的「唯一出网口」网关（本机回环上的一个小转发器）
 *
 * 它解决的是什么：
 *   以前"出口必须是 VPS"是靠**事后检查**（自检 + 每 45 秒复核）来保证的：发现不对再停。
 *   检查与下一次请求之间仍有一小段窗口，理论上能漏出去一次。
 *   这个网关把"出网"这件事从别人手里收回来：它自己就是唯一拨号出去的那一段，
 *   而它的代码里**只有一条上游** = 127.0.0.1:<隧道端口>，不存在拨非回环地址的语句。
 *   ⇒ 出口泄漏不再是"被检查出来的错误"，而是**写不出来的行为**：隧道断了就是请求失败。
 *
 * 链路（C 方案）：
 *   本机浏览器 → whistle 127.0.0.1:8899（只解密/只看，不做出口决策）
 *              → 本网关 127.0.0.1:8877（唯一出网口，只许拨 127.0.0.1:1080）
 *              → SSH 隧道 127.0.0.1:1080 → VPS → 目标站
 *
 * 对外只提供两件事：
 *   1) SOCKS5 服务（给 whistle 用：规则 * socks://127.0.0.1:8877）
 *   2) HTTP 代理服务（给 curl / 浏览器直连用：-x http://127.0.0.1:8877）
 *      HTTP 侧是"尽力而为"：一次请求一条上游连接，带 Connection: close；
 *      浏览器那条路走的是 whistle + SOCKS，不经过这里的 HTTP 解析器。
 *
 * 用法：
 *   node gateway.mjs [--port 8877] [--up 1080] [--up-host 127.0.0.1]
 *                    [--log <jsonl>] [--state <json>] [--pid <file>] [--idle-ms 0]
 *   node gateway.mjs --stop --pid <file>        停掉在跑的网关
 *   node gateway.mjs --check                    只做启动自检，不起监听（给脚本判断用）
 *
 * 退出码：0 正常 ｜ 2 上游不是回环（拒绝启动）｜ 3 上游连不上（拒绝启动）｜ 4 端口被占
 * 启动成功会输出一行：GW_READY listen=127.0.0.1:8877 up=127.0.0.1:1080 pid=...
 * 失败会输出一行：GW_FAIL reason=CODE（脚本一律按失败处理，不许猜）
 *
 * 设计红线（改这个文件的人请一并守住）：
 *   · 任何"连出去"的动作只能经过 dialUpstream()，且它内部再验一次回环；不许出现 net.connect(目标站)
 *   · 上游断开 = 直接销毁客户端连接，**绝不回退直连**（代码里没有这条路径）
 *   · 监听只绑 127.0.0.1；不解析 UDP（SOCKS5 的 UDP ASSOCIATE 一律拒绝）
 */
import net from 'net';
import fs from 'fs';
import path from 'path';

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  const v = i !== -1 ? process.argv[i + 1] : undefined;
  return v !== undefined && !String(v).startsWith('--') ? String(v) : def;
}
function intArg(name, def) {
  const v = parseInt(arg(name, String(def)), 10);
  return Number.isFinite(v) ? v : def;
}

const LISTEN_HOST = '127.0.0.1';          // 硬编码：只绑回环
const PORT = intArg('port', 8877);
const UP_HOST = arg('up-host', '127.0.0.1');
const UP_PORT = intArg('up', 1080);
const LOG = arg('log', '');
const STATE = arg('state', '');
const PIDF = arg('pid', '');
const IDLE_MS = intArg('idle-ms', 0);
const DEBUG = process.argv.includes('--debug');
const HANDSHAKE_MS = 12000;

/* ---------- 回环判定（唯一的"能去哪"判据） ---------- */
export function isLoopback(h) {
  let s = String(h == null ? '' : h).trim().toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (s === 'localhost' || s === '::1' || s === '0:0:0:0:0:0:0:1') return true;
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const a = [+m[1], +m[2], +m[3], +m[4]];
  if (a.some((x) => x < 0 || x > 255)) return false;
  return a[0] === 127;                     // 127.0.0.0/8 全部算本机
}

/* ---------- 记账 ---------- */
const T0 = Date.now();
let nTotal = 0, nTunnel = 0, nUpFail = 0, nHttp = 0, nRejected = 0;
let last = null;
function logLine(s) {
  const line = new Date().toISOString() + ' ' + s;
  process.stdout.write(line + '\n');
  if (LOG) { try { fs.appendFileSync(LOG, line + '\n', 'utf8'); } catch { /* ignore */ } }
}
function logJson(o) {
  if (!LOG) return;
  try { fs.appendFileSync(LOG, JSON.stringify(o) + '\n', 'utf8'); } catch { /* ignore */ }
}
function writeState(extra) {
  if (!STATE) return;
  const o = Object.assign({
    ts: Date.now(), pid: process.pid, listen: LISTEN_HOST + ':' + PORT,
    up: UP_HOST + ':' + UP_PORT, upLoopback: isLoopback(UP_HOST),
    total: nTotal, viaTunnel: nTunnel, nonTunnel: 0, upFail: nUpFail,
    http: nHttp, rejected: nRejected, uptimeMs: Date.now() - T0, last,
    invariant: invariantOk() ? 'tunnel_only' : 'BROKEN',
  }, extra || {});
  try { fs.mkdirSync(path.dirname(STATE), { recursive: true }); fs.writeFileSync(STATE, JSON.stringify(o), 'utf8'); }
  catch { /* ignore */ }
}
// 不变式（结构决定，不是统计口径）：
//   ① nonTunnel 恒为 0 —— 因为本文件只有 dialUpstream() 一个出网动作，而它只拨 UP_HOST=回环
//   ② 每条请求要么交给隧道、要么作为失败断开，没有第三种结局
function invariantOk() { return (nTunnel + nUpFail) === nTotal; }

/* ---------- 唯一的出网动作 ---------- */
function dialUpstream(target, cb) {
  // 再验一次：这不是防御性装饰，而是让"拨别的地方"在这个文件里根本没有可能发生
  if (!isLoopback(UP_HOST)) { cb(new Error('UPSTREAM_NOT_LOOPBACK')); return; }
  const s = net.connect({ host: UP_HOST, port: UP_PORT });
  s.setNoDelay(true);
  const to = setTimeout(() => { cleanup(); cb(new Error('UPSTREAM_TIMEOUT')); s.destroy(); }, HANDSHAKE_MS);
  function cleanup() { clearTimeout(to); s.removeListener('error', onErr); }
  function onErr(e) { cleanup(); cb(e); }
  s.once('error', onErr);
  s.once('connect', () => {
    socksConnectVia(s, target.host, target.port, (err) => {
      if (err) { cleanup(); try { s.destroy(); } catch { /* ignore */ } return cb(err); }
      cleanup();
      cb(null, s);
    });
  });
}

/* SOCKS5 客户端：让隧道替我们连目标（域名原样交给对端解析，本机不做 DNS） */
function socksConnectVia(s, host, port, cb) {
  let phase = 0, acc = Buffer.alloc(0);
  function onData(d) {
    acc = Buffer.concat([acc, d]);
    if (phase === 0) {
      // 注意：这里读的是**服务端的方法选择回复** = [VER, METHOD] 两个字节（不是客户端的问候语 [VER,NMETHOD,...]）
      if (acc.length < 2) return;
      if (acc[0] !== 0x05) return done(new Error('SOCKS_BAD_VERSION'));
      if (acc[1] !== 0x00) return done(new Error('SOCKS_METHOD_REJECTED_' + acc[1]));
      acc = acc.slice(2);
      phase = 1;
    }
    if (phase === 1) {
      if (acc.length < 4) return;
      const rep = acc[1], atyp = acc[3];
      let need;
      if (atyp === 0x01) need = 10;
      else if (atyp === 0x04) need = 22;
      else if (atyp === 0x03) { if (acc.length < 5) return; need = 5 + acc[4] + 2; }
      else return done(new Error('SOCKS_BAD_ATYP'));
      if (acc.length < need) return;
      if (rep !== 0x00) return done(new Error('SOCKS_REP_' + rep));
      return done(null);
    }
  }
  function done(err) { s.removeListener('data', onData); cb(err); }
  s.on('data', onData);
  // 问候 + 请求一起发（不等待往返）
  const hb = Buffer.from(host, 'utf8');
  const req = Buffer.alloc(4 + 1 + hb.length + 2);
  req.writeUInt8(0x05, 0); req.writeUInt8(0x01, 1); req.writeUInt8(0x00, 2); req.writeUInt8(0x03, 3);
  req.writeUInt8(hb.length, 4); hb.copy(req, 5);
  req.writeUInt16BE(port, 5 + hb.length);
  s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), req]));
}

/* ---------- 双向搬运 ---------- */
function bridge(client, up, meta) {
  const t = Date.now();
  let cx = 0, ux = 0, done = false;
  nTunnel++;                                   // 一进来就计数：这条连接已经确定交给隧道了
  client.on('data', (d) => { cx += d.length; });
  up.on('data', (d) => { ux += d.length; });
  client.pipe(up);
  up.pipe(client);
  const bye = (who) => {
    if (done) return;                          // 关闭事件会来好几次，只记一次（否则不变式对不上）
    done = true;
    logJson(Object.assign({ ts: Date.now(), who, ms: Date.now() - t, cliBytes: cx, upBytes: ux, viaTunnel: true }, meta));
    last = { ts: Date.now(), target: meta.target, up: meta.up, ok: true, ms: Date.now() - t, who };
    writeState();
    try { client.destroy(); } catch { /* ignore */ }
    try { up.destroy(); } catch { /* ignore */ }
  };
  client.on('error', () => bye('client_err'));
  up.on('error', () => bye('up_err'));
  client.on('close', () => bye('client_close'));
  up.on('close', () => bye('up_close'));
}
function upFail(client, meta, err) {
  nTotal++; nUpFail++;
  const reason = (err && err.message) || 'UPSTREAM_ERROR';
  logJson(Object.assign({ ts: Date.now(), ok: false, reason, viaTunnel: false, fallback: 'none' }, meta));
  last = { ts: Date.now(), target: meta.target, up: meta.up, ok: false, reason, ms: 0 };
  logLine('GW_UP_FAIL target=' + meta.target + ' reason=' + reason + ' action=client_connection_reset_no_fallback');
  writeState();
  try { client.destroy(); } catch { /* ignore */ }   // 直接断开，绝不直连兜底
}

/* ---------- SOCKS5 服务端 ---------- */
function handleSocks(client, first) {
  let acc = first, stage = 0;
  const meta = { kind: 'socks', client: client.remoteAddress + ':' + client.remotePort, target: '-', up: UP_HOST + ':' + UP_PORT };
  function onData(d) {
    acc = Buffer.concat([acc, d]);
    if (stage === 0) {
      if (acc.length < 2) return;
      if (acc[0] !== 0x05) { nRejected++; client.destroy(); return; }
      const nm = acc[1];
      if (acc.length < 2 + nm) return;
      const methods = acc.slice(2, 2 + nm);
      if (!methods.includes(0x00)) { nRejected++; client.end(Buffer.from([0x05, 0xff])); return; }
      acc = acc.slice(2 + nm);
      stage = 1;
      client.write(Buffer.from([0x05, 0x00]));
    }
    if (stage === 1) {
      if (acc.length < 4) return;
      const cmd = acc[1], atyp = acc[3];
      let host = '', need = 0, off = 4;
      if (atyp === 0x01) {
        if (acc.length < 10) return;
        host = acc.slice(4, 8).join('.'); need = 10; off = 8;
      } else if (atyp === 0x04) {
        if (acc.length < 22) return;
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(acc.readUInt16BE(4 + i).toString(16));
        host = parts.join(':'); need = 22; off = 20;
      } else if (atyp === 0x03) {
        if (acc.length < 5) return;
        const ln = acc[4];
        if (acc.length < 5 + ln + 2) return;
        host = acc.slice(5, 5 + ln).toString('utf8'); need = 5 + ln + 2; off = 5 + ln;
      } else { nRejected++; client.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); return; }
      const port = acc.readUInt16BE(off);
      const rest = acc.slice(need);
      client.removeListener('data', onData);
      if (cmd !== 0x01) {   // 只支持 CONNECT：UDP ASSOCIATE / BIND 一律拒绝
        nRejected++;
        logLine('GW_REJECT cmd=' + cmd + ' (only CONNECT is served; no UDP path exists here)');
        client.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        return;
      }
      meta.target = host + ':' + port;
      if (!host) { client.destroy(); return; }
      dialUpstream({ host, port }, (err, up) => {
        if (err) { upFail(client, meta, err); return; }
        nTotal++;
        client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        if (rest.length) up.write(rest);
        bridge(client, up, meta);
      });
    }
  }
  client.on('data', onData);
  onData(Buffer.alloc(0));   // 关键：首块已经攒在 acc 里，必须立刻喂一次，否则"客户端等回复、我们等下一次数据"= 死锁
}

/* ---------- HTTP 代理（尽力而为：一次请求一条上游连接） ---------- */
function handleHttp(client, first) {
  let acc = first;
  const meta = { kind: 'http', client: client.remoteAddress + ':' + client.remotePort, target: '-', up: UP_HOST + ':' + UP_PORT };
  function onData(d) {
    acc = Buffer.concat([acc, d]);
    const end = acc.indexOf('\r\n\r\n');
    if (end === -1) {
      if (acc.length > 65536) { nRejected++; client.destroy(); }
      return;
    }
    const head = acc.slice(0, end).toString('latin1');
    let body = acc.slice(end + 4);
    const lines = head.split('\r\n');
    const m = lines[0].match(/^([A-Za-z]+)\s+(\S+)\s+HTTP\/(\d\.\d)$/);
    if (!m) { nRejected++; client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); return; }
    const method = m[1].toUpperCase();
    const url = m[2];
    const headers = {};
    for (let i = 1; i < lines.length; i++) {
      const k = lines[i].indexOf(':');
      if (k > 0) headers[lines[i].slice(0, k).trim().toLowerCase()] = lines[i].slice(k + 1).trim();
    }
    let host = '', port = 0, origin = url;
    if (method === 'CONNECT') {
      const hm = url.match(/^(.*?):(\d+)$/);
      if (!hm) { nRejected++; client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); return; }
      host = hm[1]; port = parseInt(hm[2], 10);
    } else {
      if (/^https?:\/\//i.test(url)) {
        let u;
        try { u = new URL(url); } catch { nRejected++; client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); return; }
        host = u.hostname; port = u.port ? parseInt(u.port, 10) : (u.protocol === 'https:' ? 443 : 80);
        origin = u.pathname + (u.search || '');
      } else {
        const h = (headers['host'] || '').split(':');
        host = h[0]; port = h[1] ? parseInt(h[1], 10) : 80;
      }
    }
    if (!host) { nRejected++; client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); return; }
    client.removeListener('data', onData);
    meta.target = host + ':' + port;
    dialUpstream({ host, port }, (err, up) => {
      if (err) { upFail(client, meta, err); return; }
      nTotal++; nHttp++;
      if (method === 'CONNECT') {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      } else {
        const keep = ['host', 'user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type',
          'content-length', 'authorization', 'cookie', 'referer', 'origin', 'range', 'if-none-match', 'if-modified-since'];
        const keepHead = ['Host: ' + (headers['host'] || host)];
        for (const k of keep) {
          if (k === 'host') continue;
          if (headers[k] !== undefined) keepHead.push(k.replace(/(^|-)([a-z])/g, (s, a, b) => a + b.toUpperCase()) + ': ' + headers[k]);
        }
        keepHead.push('Connection: close');       // 一次请求一条连接：不给"半条连接被复用"留歧义
        up.write(method + ' ' + origin + ' HTTP/1.1\r\n' + keepHead.join('\r\n') + '\r\n\r\n');
      }
      if (body.length) up.write(body);
      bridge(client, up, meta);
    });
  }
  client.on('data', onData);
  onData(Buffer.alloc(0));   // 同上：首块立刻处理
}

/* ---------- 启动 ---------- */
function fail(code, reason) { logLine('GW_FAIL reason=' + reason); process.exit(code); }

if (process.argv.includes('--stop')) {
  let pid = 0;
  try { pid = parseInt(fs.readFileSync(PIDF, 'utf8').trim(), 10) || 0; } catch { /* none */ }
  if (!pid) { logLine('GW_STOP=nothing_to_stop'); process.exit(0); }
  try { process.kill(pid); logLine('GW_STOP=ok pid=' + pid); } catch (e) { logLine('GW_STOP=fail pid=' + pid + ' err=' + e.code); }
  try { fs.unlinkSync(PIDF); } catch { /* ignore */ }
  process.exit(0);
}

if (!isLoopback(UP_HOST)) fail(2, 'UPSTREAM_NOT_LOOPBACK');
if (!(UP_PORT > 0 && UP_PORT < 65536)) fail(2, 'UPSTREAM_PORT_BAD');

// 启动自检：上游必须真的能 TCP 连上，否则拒绝启动（fail-closed）
function preflight(cb) {
  const s = net.connect({ host: UP_HOST, port: UP_PORT });
  const to = setTimeout(() => { s.destroy(); cb(new Error('UPSTREAM_TIMEOUT')); }, 6000);
  s.once('connect', () => { clearTimeout(to); s.destroy(); cb(null); });
  s.once('error', (e) => { clearTimeout(to); cb(e); });
}

if (process.argv.includes('--check')) {
  preflight((err) => {
    if (err) { logLine('GW_CHECK=up_unreachable err=' + err.message); process.exit(3); }
    logLine('GW_CHECK=ok up=' + UP_HOST + ':' + UP_PORT);
    process.exit(0);
  });
} else {
  preflight((err) => {
    if (err) fail(3, 'UPSTREAM_UNREACHABLE');
    const server = net.createServer((client) => {
      client.setNoDelay(true);
      if (DEBUG) logLine('GW_CONN from=' + client.remoteAddress + ':' + client.remotePort + ' pid=' + process.pid);
      const onFirst = (d) => {
        client.removeListener('data', onFirst);
        if (DEBUG) logLine('GW_FIRST len=' + d.length + ' b0=0x' + d[0].toString(16));
        if (d[0] === 0x05) handleSocks(client, d);
        else handleHttp(client, d);
      };
      client.on('data', onFirst);
      client.on('error', () => { /* ignore */ });
      if (IDLE_MS > 0) client.setTimeout(IDLE_MS, () => client.destroy());
    });
    server.on('error', (e) => fail(4, 'LISTEN_FAIL ' + e.code));
    server.listen(PORT, LISTEN_HOST, () => {
      if (PIDF) { try { fs.mkdirSync(path.dirname(PIDF), { recursive: true }); fs.writeFileSync(PIDF, String(process.pid), 'utf8'); } catch { /* ignore */ } }
      writeState();
      logLine('GW_READY listen=' + LISTEN_HOST + ':' + PORT + ' up=' + UP_HOST + ':' + UP_PORT + ' pid=' + process.pid +
              ' invariant=' + (invariantOk() ? 'tunnel_only' : 'BROKEN'));
      setInterval(() => { writeState(); }, 5000).unref?.();
    });
    const bye = () => {
      writeState({ stopped: true, invariant: invariantOk() });
      logLine('GW_STOP invariant=' + (invariantOk() ? 'tunnel_only' : 'BROKEN') + ' total=' + nTotal + ' upFail=' + nUpFail);
      process.exit(0);
    };
    process.on('SIGINT', bye);
    process.on('SIGTERM', bye);
  });
}
