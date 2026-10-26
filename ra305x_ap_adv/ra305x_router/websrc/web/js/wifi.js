(function () {
  'use strict';
  var form = document.getElementById('wifi-form');
  var state = JSON.parse(document.getElementById('wifi-state').textContent);
  var channel = document.getElementById('channel');
  var status = document.getElementById('status');
  var button = document.getElementById('apply');
  var temporary = document.getElementById('temporary');
  for (var n = 1; n <= 13; n++) {
    var option = document.createElement('option');
    option.value = String(n); option.textContent = 'Channel ' + n; channel.appendChild(option);
  }
  function repeater() { return form.elements.MODE.value === 'repeater'; }
  function modeChanged() {
    var rep = repeater();
    document.getElementById('uplink-fields').hidden = !rep;
    document.getElementById('uplink').required = rep;
    document.getElementById('uplink-password').required = rep && document.getElementById('security').value !== 'open';
    document.getElementById('uplink-password').disabled = !rep || document.getElementById('security').value === 'open';
    document.getElementById('channel-note').textContent = rep ? 'Must match the channel of your existing Wi-Fi network.' : 'Choose a channel for your access point.';
  }
  form.elements.MODE.value = state.mode;
  document.getElementById('ssid').value = state.ssid;
  document.getElementById('uplink').value = state.uplink;
  channel.value = String(state.channel >= 1 && state.channel <= 13 ? state.channel : 6);
  document.getElementById('security').value = state.security === 'OPEN' ? 'open' : state.security === 'WPAPSKWPA2PSK' ? 'mixed' : 'wpa2';
  form.addEventListener('change', modeChanged);
  modeChanged();
  function asciiKey(value) { return /^[\x20-\x7e]{8,63}$/.test(value); }
  function ssidOK(value) { return value.length > 0 && new TextEncoder().encode(value).length <= 32 && !/[\x00-\x1f\x7f]/.test(value); }
  function delay(ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }
  async function poll(expected) {
    for (var i = 0; i < 25; i++) {
      await delay(2000);
      try {
        var response = await fetch('/wifi_state.html?t=' + Date.now(), {cache:'no-store', signal:AbortSignal.timeout(3500)});
        var current = await response.json();
        if (!current.busy && current.error) return false;
        if (!current.busy && current.revision >= expected.revision && current.mode === expected.mode && current.ssid === expected.ssid && current.channel === expected.channel && (!expected.save || current.saved) && (expected.mode !== 'repeater' || current.uplink === expected.uplink)) { state = current; return true; }
      } catch (_) { /* Wi-Fi may briefly disconnect while applying. */ }
    }
    return false;
  }
  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    var rep = repeater();
    var save = !event.submitter || event.submitter.value !== '0';
    var ssid = document.getElementById('ssid').value;
    var uplink = document.getElementById('uplink').value;
    if (!ssidOK(ssid) || (rep && !ssidOK(uplink))) { status.textContent = 'Network names must contain 1–32 UTF-8 bytes, without control characters.'; return; }
    if (!asciiKey(document.getElementById('password').value) || (rep && document.getElementById('security').value !== 'open' && !asciiKey(document.getElementById('uplink-password').value))) { status.textContent = 'Passwords must contain 8–63 ASCII characters.'; return; }
    if (!window.confirm(rep ? 'Apply Repeater mode? Disconnect the Ethernet uplink first. Your Wi-Fi connection may drop; reconnect to the network you configured.' : 'Apply Access Point mode? The Wi-Fi uplink will stop. Keep the Ethernet cable connected.')) return;
    button.disabled = true; temporary.disabled = true;
    status.textContent = 'Applying settings… If disconnected, reconnect to your configured Wi-Fi network.';
    var expected = {save:save, revision:state.revision + 1, mode:rep ? 'repeater' : 'ap', ssid:ssid, uplink:uplink, channel:Number(channel.value)};
    try {
      var data = new URLSearchParams(new FormData(form));
      data.set("SAVE", save ? "1" : "0");
      var response = await fetch('/wifi_apply.html', {method:'POST', body:data, signal:AbortSignal.timeout(8000)});
      var text = (await response.text()).trim();
      if (text !== 'OK') throw new Error(text || 'The device did not accept these settings.');
    } catch (error) {
      if (error.name !== 'TimeoutError' && error.name !== 'TypeError') { status.textContent = error.message; button.disabled = false; temporary.disabled = false; return; }
    }
    var ok = await poll(expected);
    document.getElementById('password').value = '';
    document.getElementById('uplink-password').value = '';
    status.textContent = ok ? (save ? 'Settings saved. They will survive restart.' : 'Settings applied for this session. They will be lost after restart.') : 'Connection not confirmed. Reconnect to the configured Wi-Fi and reopen this address. A power cycle restores the installed firmware.';
    button.disabled = false; temporary.disabled = false;
  });
}());
