const fs = require('fs'), vm = require('vm'), assert = require('assert');
const code = fs.readFileSync(process.argv[2], 'utf8');
function fixture(mode) {
  const ids = {}, events = {}, calls = [];
  ['wifi-form','wifi-state','channel','status','apply','temporary','uplink-fields','uplink','uplink-password','security','channel-note','ssid','password'].forEach(id => ids[id] = {value:'',textContent:'',hidden:false,required:false,disabled:false,appendChild(){},addEventListener(name, fn){events[name] = fn;}});
  ids['wifi-state'].textContent = JSON.stringify({mode,ssid:'Test AP',uplink:'Source',channel:6,security:'WPA2PSK',revision:0,busy:0});
  ids['wifi-form'].elements = {MODE:{value:mode}};
  let applied;
  const context = {TextEncoder,URLSearchParams,AbortSignal,console,Promise,setTimeout(fn){fn();},window:{confirm(){return true;}},document:{getElementById(id){return ids[id];},createElement(){return {};}},FormData:class {
    constructor(){this.items=[['MODE',ids['wifi-form'].elements.MODE.value],['SSID',ids.ssid.value],['PASSWORD',ids.password.value],['CHANNEL',ids.channel.value],['UPLINK_SSID',ids.uplink.value],['UPLINK_SECURITY',ids.security.value]];if(!ids['uplink-password'].disabled)this.items.push(['UPLINK_PASSWORD',ids['uplink-password'].value]);}
    [Symbol.iterator](){return this.items[Symbol.iterator]();}
  },async fetch(url, options){
    calls.push({url,options});
    if(options.method === 'POST'){
      const p=options.body;applied={revision:1,busy:0,saved:p.get('SAVE')==='1'?1:0,mode:p.get('MODE'),ssid:p.get('SSID'),uplink:p.get('UPLINK_SSID'),channel:Number(p.get('CHANNEL'))};
      return {async text(){return 'OK\n';}};
    }
    return {async json(){return applied;}};
  }};
  vm.runInNewContext(code,context);
  return {ids,events,calls};
}
(async()=>{
 let f=fixture('ap');assert(f.ids['uplink-fields'].hidden);assert(!f.ids.uplink.required);assert(f.ids['uplink-password'].disabled);
 f.ids.password.value='short';await f.events.submit({preventDefault(){},submitter:{value:"0"}});assert(f.calls.length===0);assert(f.ids.status.textContent.includes('8–63'));
 f.ids.password.value='test-pass-123';await f.events.submit({preventDefault(){},submitter:{value:"0"}});assert(f.calls.length===2);assert(f.calls[0].url==='/wifi_apply.html');assert(f.calls[0].options.body.get('MODE')==='ap');assert(f.ids.status.textContent.startsWith('Settings applied'));assert(f.ids.password.value==='');assert(!f.ids.apply.disabled);
 f=fixture('ap');f.ids.password.value='test-pass-123';await f.events.submit({preventDefault(){},submitter:{value:'1'}});assert(f.calls[0].options.body.get('SAVE')==='1');assert(f.ids.status.textContent.startsWith('Settings saved'));
 f=fixture('repeater');assert(!f.ids['uplink-fields'].hidden);assert(f.ids.uplink.required);assert(f.ids['uplink-password'].required);
 f.ids.password.value='test-pass-123';f.ids['uplink-password'].value='uplink-pass-123';await f.events.submit({preventDefault(){},submitter:{value:"0"}});assert(f.calls[0].options.body.get('MODE')==='repeater');assert(f.calls[0].options.body.get('UPLINK_PASSWORD')==='uplink-pass-123');assert(f.ids.status.textContent.startsWith('Settings applied'));
 f=fixture('repeater');f.ids.security.value='open';f.events.change();assert(f.ids['uplink-password'].disabled);assert(!f.ids['uplink-password'].required);
 f.ids.ssid.value='é'.repeat(17);f.ids.password.value='test-pass-123';await f.events.submit({preventDefault(){},submitter:{value:"0"}});assert(f.calls.length===0);assert(f.ids.status.textContent.includes('UTF-8'));
 console.log('PASS: UI mode switching, password and UTF-8 validation, POST fields, apply polling and feedback');
})().catch(e=>{console.error(e);process.exitCode=1;});
