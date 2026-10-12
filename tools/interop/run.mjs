// Drives the browser interop test: starts rtc-interop (zig build interop), starts headless
// Chrome with fake media devices, opens the test page over the DevTools protocol, waits for
// the page's getStats() summary, and prints both sides' results.
//
//   node tools/interop/run.mjs [answer|offer] [gcm|cm]
//
// No npm packages: Node 22's built-in fetch and WebSocket only.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const mode = process.argv[2] || 'answer';
const profile = process.argv[3] || 'gcm';
const chrome = process.env.CHROME || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '..');
const exe = path.join(root, 'zig-out', 'bin', process.platform === 'win32' ? 'rtc-interop.exe' : 'rtc-interop');
const httpPort = 8765 + (mode === 'offer' ? 1 : 0) + (profile === 'cm' ? 2 : 0);
const cdpPort = 9333;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Chrome does not gather loopback candidates, so both sides use a LAN address.
function lanIp() {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list || []) if (a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.')) return a.address;
  }
  throw new Error('no LAN IPv4 address');
}

const ip = process.env.LAN_IP || lanIp();
const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rtc-interop-'));
console.log(`mode=${mode} profile=${profile} ip=${ip} logs=${logDir}`);

const zig = spawn(exe, [mode, ip, String(httpPort), profile], { stdio: ['ignore', 'pipe', 'pipe'] });
const zigLog = fs.createWriteStream(path.join(logDir, 'zig.log'));
zig.stdout.pipe(zigLog);
zig.stderr.on('data', (d) => { zigLog.write(d); if (process.env.VERBOSE) process.stderr.write(d); });

let browser;
async function cleanup() {
  try { browser?.kill(); } catch {}
  try { zig.kill(); } catch {}
}

async function main() {
  for (let i = 0; ; i++) {
    try { await fetch(`http://127.0.0.1:${httpPort}/status`); break; } catch { if (i > 50) throw new Error('rtc-interop did not start'); await sleep(100); }
  }
  const profileDir = path.join(logDir, 'chrome-profile');
  browser = spawn(chrome, [
    '--headless=new', `--remote-debugging-port=${cdpPort}`, `--user-data-dir=${profileDir}`,
    '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream',
    '--autoplay-policy=no-user-gesture-required', '--no-first-run', '--no-default-browser-check',
    '--enable-logging=stderr', '--v=0',
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  const chromeLog = fs.createWriteStream(path.join(logDir, 'chrome.log'));
  browser.stderr.pipe(chromeLog);

  let version;
  for (let i = 0; ; i++) {
    try { version = await (await fetch(`http://127.0.0.1:${cdpPort}/json/version`)).json(); break; } catch { if (i > 100) throw new Error('chrome did not start'); await sleep(100); }
  }
  console.log(`browser: ${version.Browser}`);
  const target = await (await fetch(`http://127.0.0.1:${cdpPort}/json/new?http://127.0.0.1:${httpPort}/?mode=${mode}`, { method: 'PUT' })).json();
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  };
  const call = (method, params = {}) => new Promise((resolve) => { const n = ++id; pending.set(n, resolve); ws.send(JSON.stringify({ id: n, method, params })); });
  const evaluate = async (expr) => (await call('Runtime.evaluate', { expression: expr, returnByValue: true })).result?.result?.value;

  let result = null;
  for (let i = 0; i < 60; i++) {
    await sleep(1000);
    const text = await evaluate('JSON.stringify(window.result)');
    result = text ? JSON.parse(text) : null;
    if (result?.done) break;
  }
  const status = await (await fetch(`http://127.0.0.1:${httpPort}/status`)).json();
  console.log('\n=== browser (getStats) ===');
  console.log(JSON.stringify(result, null, 2));
  console.log('\n=== reseal-rtc ===');
  console.log(JSON.stringify(status, null, 2));

  const b = result || {};
  const checks = {
    ice_connected: ['connected', 'completed'].includes(b.ice) && status.ice === 'connected',
    dtls_connected: b.transport?.dtlsState === 'connected' && status.connection === 'connected',
    browser_decrypted_audio: (b.audio_in?.packetsReceived || 0) > 50,
    browser_decoded_video: (b.video_in?.framesDecoded || 0) > 5,
    zig_decrypted_audio: status.audio_frames > 50,
    zig_received_video_frames: status.video_frames > 5,
    zig_srtp_errors_zero: status.srtp_errors === 0,
  };
  console.log('\n=== checks ===');
  for (const [k, v] of Object.entries(checks)) console.log(`${v ? 'PASS' : 'FAIL'} ${k}`);
  ws.close();
  return Object.values(checks).every(Boolean);
}

main().then(async (ok) => { await cleanup(); process.exit(ok ? 0 : 1); }, async (e) => { console.error(e); await cleanup(); process.exit(2); });
