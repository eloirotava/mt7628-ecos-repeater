const fs = require('fs'), vm = require('vm'), assert = require('assert');
const page = fs.readFileSync(process.argv[2], 'utf8');
const code = page.slice(page.lastIndexOf('<script>') + 8, page.lastIndexOf('</script>'));
const ids = [...page.matchAll(/id="([^"]+)"/g)].map(m => m[1]);

/* Real driver output, trimmed: hex UTF-8 SSID, hidden network, duplicate SSID, WPA3. */
const survey = [
  'Ch  SSID                                                             BSSID               Security               Siganl(%)W-Mode  ExtCH  NT WPS DPID',
  '1   Vizinha                                                          c8:5d:38:96:5d:94   WPA2PSK/AES            13       11b/g/n NONE   In YES     ',
  '1   CasaTania_2g                                                     e8:20:e2:0d:be:3d   WPA1PSKWPA2PSK/TKIPAES 23       11b/g/n NONE   In YES     ',
  '1   #CLARO-WIFI                                                      ea:20:e2:0d:bf:3e   NONE                   24       11b/g/n NONE   In  NO     ',
  '2   0x53616CC3A36F2033C2B0                                           80:3f:5d:32:ff:de   WPA1PSKWPA2PSK/TKIPAES 5        11b/g/n ABOVE  In YES     ',
  '4                                                                    4e:06:17:cf:d0:19   WPA2PSK/AES            37       11b/g/n NONE   In  NO     ',
  '6   ALMEIDA                                                          b0:fc:88:fd:c9:2b   WPA2PSK/AES            76       11b/g/n NONE   In YES     ',
  '10  #CLARO-WIFI                                                      da:33:b7:53:ef:f2   NONE                   5        11b/g/n NONE   In  NO     ',
  '11  Corp                                                             08:c7:f5:06:71:cb   WPA3SAE/AES            40       11b/g/n NONE   In YES     ',
].join('\n');

function element(id) {
  const el = {id, value: '', textContent: '', hidden: false, disabled: false, checked: false, className: '', style: {}, tabIndex: -1,
    children: [], listeners: {}, focused: false,
    appendChild(c) { this.children.push(c); return c; },
    addEventListener(name, fn) { this.listeners[name] = fn; },
    focus() { this.focused = true; }};
  Object.defineProperty(el, 'textContent', {get() { return el._text || ''; }, set(v) { el._text = String(v); if (v === '') el.children = []; }});
  return el;
}

function fixture(state, opts = {}) {
  const els = {};
  ids.forEach(id => els[id] = element(id));
  els['wifi-state'].textContent = JSON.stringify(state);
  const radios = {ap: element('mode-ap'), repeater: element('mode-repeater')};
  radios.ap.value = 'ap'; radios.repeater.value = 'repeater';
  els['wifi-form'].querySelector = sel => {
    if (sel === 'input[name=MODE]:checked') return radios.ap.checked ? radios.ap : radios.repeater;
    const m = /value=(\w+)/.exec(sel); return radios[m[1]];
  };
  els['wifi-form'].querySelectorAll = () => [els.apply];
  els['scan-table'].tBodies = [element('tbody')];
  const calls = [];
  let current = Object.assign({}, state);
  const context = {TextEncoder, TextDecoder, URLSearchParams, Uint8Array, AbortSignal, console, Promise, Object, Math, Date, JSON,
    setTimeout(fn) { fn(); }, setInterval() {},
    window: {confirm() { return opts.confirm !== false; }},
    document: {hidden: false, getElementById(id) { return els[id]; }, createElement(tag) { return element(tag); }, createTextNode(t) { return {textContent: t}; }},
    async fetch(url, options = {}) {
      calls.push({url, options});
      if (url.startsWith('/wifi_scan.html')) return {async json() { return {error: '', raw: survey}; }};
      if (options.method === 'POST') {
        if (url === '/wifi_apply.html') current = Object.assign({}, current, {revision: current.revision + 1, busy: 0, error: 0, saved: 1});
        return {async text() { return opts.reply || 'OK\n'; }};
      }
      return {async json() { return current; }};
    }};
  vm.runInNewContext(code, context);
  return {els, radios, calls, posts: () => calls.filter(c => c.options.method === 'POST')};
}
const base = {busy: 0, revision: 3, error: 0, saved: 1, mode: 'ap', ssid: 'Extender-A03E9C1D0E54', uplink: 'ECOSAPClient', channel: 6,
  security: 'WPA2PSK', device_security: 'open', admin_user: 'admin', admin_password_set: 0, telnet: 0, chip: 'MT7628KN', version: '1.0', build: 1700000000, uptime: 3700};
const submit = f => f.els['wifi-form'].listeners.submit({preventDefault() {}});

(async () => {
  /* Initial render */
  let f = fixture(base);
  assert(f.radios.ap.checked && f.els['uplink-fields'].hidden);
  assert.strictEqual(f.els.uplink.value, '', 'driver placeholder uplink is hidden');
  assert(f.els['device-password-field'].hidden, 'open network hides password');
  assert(!f.els['admin-banner'].hidden && f.els['current-field'].hidden);
  assert(f.els['st-telnet'].textContent.startsWith('Disabled'));
  assert.strictEqual(f.els['st-uptime'].textContent, '1 h 1 min');

  /* Open AP apply: always saves, sends open security and no password */
  await submit(f);
  let p = f.posts()[0].options.body;
  assert.strictEqual(f.posts()[0].url, '/wifi_apply.html');
  assert.strictEqual(p.get('SAVE'), '1'); assert.strictEqual(p.get('DEVICE_SECURITY'), 'open'); assert.strictEqual(p.get('PASSWORD'), '');
  assert(f.els['wifi-msg'].textContent.startsWith('Saved and applied'));

  /* Switching an open network to WPA2 requires a password */
  f = fixture(base); f.els['device-security'].value = 'wpa2'; f.els['wifi-form'].listeners.change();
  assert(!f.els['device-password-field'].hidden);
  await submit(f); assert.strictEqual(f.posts().length, 0); assert(f.els['wifi-msg'].textContent.includes('8–63'));
  f.els.password.value = 'short'; await submit(f); assert.strictEqual(f.posts().length, 0);
  f.els.password.value = 'device-pass-1'; await submit(f); assert.strictEqual(f.posts()[0].options.body.get('PASSWORD'), 'device-pass-1');
  assert.strictEqual(f.els.password.value, '', 'password field cleared');

  /* WPA2 network: empty password keeps the current one */
  f = fixture(Object.assign({}, base, {device_security: 'wpa2'}));
  await submit(f); p = f.posts()[0].options.body;
  assert.strictEqual(p.get('DEVICE_SECURITY'), 'wpa2'); assert.strictEqual(p.get('PASSWORD'), '');

  /* UTF-8 length check */
  f = fixture(base); f.els.ssid.value = 'é'.repeat(17); await submit(f); assert.strictEqual(f.posts().length, 0);

  /* Repeater: scan, parse and choose */
  f = fixture(base); f.radios.ap.checked = false; f.radios.repeater.checked = true; f.els['wifi-form'].listeners.change();
  assert(!f.els['uplink-fields'].hidden && f.els.channel.disabled);
  await f.els.scan.listeners.click.call(f.els.scan);
  const rows = f.els['scan-table'].tBodies[0].children;
  const names = rows.map(r => r.children[0].textContent);
  assert.deepStrictEqual(names, ['ALMEIDA', 'Corp', '#CLARO-WIFI', 'CasaTania_2g', 'Vizinha', 'Salão 3°']);
  assert(!names.includes(''), 'hidden networks skipped');
  assert.strictEqual(rows[2].children[2].textContent, '1', 'duplicate SSID keeps the strongest entry');
  assert.strictEqual(rows[1].children[3].textContent, 'WPA3SAE/AES');
  rows[3].listeners.click();
  assert.strictEqual(f.els.uplink.value, 'CasaTania_2g'); assert.strictEqual(f.els['uplink-security'].value, 'mixed'); assert.strictEqual(f.els.channel.value, '1');
  assert(f.els['uplink-password'].focused);
  rows[1].listeners.click(); assert(f.els['scan-msg'].className.includes('bad'), 'WPA3 is unsupported');
  rows[2].listeners.click(); assert.strictEqual(f.els['uplink-security'].value, 'open'); assert(f.els['uplink-password'].disabled);

  /* Repeater apply: new uplink needs its password */
  rows[0].listeners.click();
  await submit(f); assert.strictEqual(f.posts().length, 0); assert(f.els['wifi-msg'].textContent.includes('uplink password'));
  f.els['uplink-password'].value = 'uplink-pass-1'; await submit(f);
  p = f.posts()[0].options.body;
  assert.strictEqual(p.get('MODE'), 'repeater'); assert.strictEqual(p.get('UPLINK_SSID'), 'ALMEIDA'); assert.strictEqual(p.get('UPLINK_SECURITY'), 'wpa2');
  assert.strictEqual(p.get('UPLINK_PASSWORD'), 'uplink-pass-1'); assert.strictEqual(p.get('CHANNEL'), '6');

  /* Same uplink: empty password keeps the stored one */
  f = fixture(Object.assign({}, base, {mode: 'repeater', uplink: 'Home', uplink_status: 'disconnected'}));
  assert(f.els['st-uplink'].className === 'bad' && f.els['st-uplink'].textContent.includes('not connected'));
  await submit(f); assert.strictEqual(f.posts().length, 1); assert.strictEqual(f.posts()[0].options.body.get('UPLINK_PASSWORD'), '');
  f = fixture(Object.assign({}, base, {mode: 'repeater', uplink: 'Home', uplink_status: 'connected'}));
  assert.strictEqual(f.els['st-uplink'].className, 'ok');

  /* Administration */
  f = fixture(base); const admin = f.els['admin-form'].listeners.submit;
  f.els['admin-user'].value = 'ad min'; await admin({preventDefault() {}}); assert.strictEqual(f.posts().length, 0);
  f.els['admin-user'].value = 'admin'; f.els['admin-password'].value = 'admin-pass-1'; f.els['admin-confirm'].value = 'other-pass-1';
  await admin({preventDefault() {}}); assert(f.els['admin-msg'].textContent.includes('do not match'));
  f.els['admin-confirm'].value = 'admin-pass-1'; await admin({preventDefault() {}});
  p = f.posts()[0]; assert.strictEqual(p.url, '/admin_apply.html');
  assert.strictEqual(p.options.body.get('USER'), 'admin'); assert.strictEqual(p.options.body.get('PASSWORD'), 'admin-pass-1');
  assert(f.els['admin-msg'].textContent.includes('sign in')); assert.strictEqual(f.els['admin-password'].value, '');
  f = fixture(base, {reply: 'ERROR: current password is incorrect'});
  f.els['admin-user'].value = 'admin'; f.els['admin-password'].value = 'admin-pass-1'; f.els['admin-confirm'].value = 'admin-pass-1';
  await f.els['admin-form'].listeners.submit({preventDefault() {}}); assert.strictEqual(f.els['admin-msg'].textContent, 'current password is incorrect');

  /* WireGuard */
  const WGK = 'YrZ7dX/8XFcP54QatyBWLDXipzhGnLWtvf1iPwG9bCA=';
  const withWg = w => Object.assign({}, base, {admin_password_set: 1, wireguard: Object.assign({enabled: 0, address: '', peer_public_key: '', endpoint: '', port: 51820, keepalive: 25, preshared_key_set: 0, public_key: 'cfMO=', state: 'off', status: 'Disabled', handshake_age: -1, rx_bytes: 0, tx_bytes: 0}, w)});
  f = fixture(withWg({}));
  assert.strictEqual(f.els['st-wg'].textContent, 'Off'); assert.strictEqual(f.els['wg-public'].textContent, 'cfMO='); assert.strictEqual(f.els['wg-port'].value, '51820'); assert.strictEqual(f.els['wg-keepalive'].value, '25');
  const wgSubmit = f.els['wg-form'].listeners.submit;
  f.els['wg-enabled'].checked = true; await wgSubmit({preventDefault() {}}); assert.strictEqual(f.posts().length, 0); assert(f.els['wg-msg'].textContent.includes('tunnel address'));
  f.els['wg-address'].value = '10.8.0.30'; f.els['wg-peer'].value = WGK; f.els['wg-endpoint'].value = 'br.example';
  await wgSubmit({preventDefault() {}}); assert.strictEqual(f.posts().length, 0); assert(f.els['wg-msg'].textContent.includes('IPv4/prefix'));
  f.els['wg-address'].value = '10.8.0.30/24'; f.els['wg-peer'].value = 'short'; await wgSubmit({preventDefault() {}}); assert.strictEqual(f.posts().length, 0);
  f.els['wg-peer'].value = WGK; await wgSubmit({preventDefault() {}});
  p = f.posts()[0]; assert.strictEqual(p.url, '/wg_apply.html');
  assert.strictEqual(p.options.body.get('ADDRESS'), '10.8.0.30/24'); assert.strictEqual(p.options.body.get('PEER_PUBLIC_KEY'), WGK); assert.strictEqual(p.options.body.get('PRESHARED_KEY'), ''); assert.strictEqual(p.options.body.get('KEEPALIVE'), '25');
  f = fixture(withWg({preshared_key_set: 1, enabled: 1, address: '10.8.0.30/24', peer_public_key: WGK, endpoint: 'br.example'}));
  assert(f.els['wg-psk-hint'].textContent.includes('keep'));
  await f.els['wg-form'].listeners.submit({preventDefault() {}}); assert.strictEqual(f.posts()[0].options.body.get('PRESHARED_KEY'), 'keep');
  f = fixture(Object.assign(withWg({}), {admin_password_set: 0}));
  f.els['wg-enabled'].checked = true; f.els['wg-address'].value = '10.8.0.30/24'; f.els['wg-peer'].value = WGK; f.els['wg-endpoint'].value = 'br.example';
  await f.els['wg-form'].listeners.submit({preventDefault() {}}); assert.strictEqual(f.posts().length, 0); assert(f.els['wg-msg'].textContent.includes('admin password'));
  f = fixture(withWg({enabled: 1, state: 'connected', status: 'Connected to 164.163.10.88:51820', handshake_age: 12, rx_bytes: 2048, tx_bytes: 512}));
  assert.strictEqual(f.els['st-wg'].className, 'ok'); assert(f.els['st-wg'].textContent.includes('handshake 12 s ago')); assert(f.els['st-wg'].textContent.includes('2.0 KB'));

  /* System actions need confirmation */
  f = fixture(base, {confirm: false}); await f.els.factory.listeners.click(); assert.strictEqual(f.posts().length, 0);
  f = fixture(base); await f.els.factory.listeners.click(); assert.strictEqual(f.posts()[0].options.body.get('ACTION'), 'factory');
  f = fixture(base); await f.els.reboot.listeners.click(); assert.strictEqual(f.posts()[0].options.body.get('ACTION'), 'reboot');

  console.log('PASS: status rendering, scan parsing and selection, Wi-Fi, admin and WireGuard validation, POST fields, system actions');
})().catch(e => { console.error(e); process.exitCode = 1; });
