#!/usr/bin/env python3
"""Validate Wi-Fi API behavior and browser form logic without hardware."""
from pathlib import Path
from html.parser import HTMLParser
import re
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[1]
web = repo / 'ra305x_ap_adv/ra305x_router/websrc/web'
source = (repo / 'ra305x_ap_adv/ra305x_router/websrc/cgi/cgi_v2/cgi_api.c').read_bytes().decode('latin1')
start = source.index('/* English AP/repeater UI.')
end = source.index('\nstatic int wifi_ui_restart(void)\n{', start)
implementation = source[start:end]
admin_start = source.index('/* Printable ASCII, no spaces or colons')
admin_end = source.index('/* Site survey as JSON', admin_start)
implementation += '\n' + source[admin_start:admin_end]
constants = sorted(set(re.findall(r'\bCFG_[A-Za-z0-9_]+', implementation)) - {'CFG_get_str', 'CFG_set_str', 'CFG_commit', 'CFG_NO_EVENT', 'CFG_save_user', 'CFG_telnet_allowed'})
defines = '#define CFG_NO_EVENT 999\n' + ''.join(f'#define {name} {i+1}\n' for i, name in enumerate(constants))
harness = (repo / 'tools/wifi_ui_test.c').read_text()
harness = defines + harness.replace('/* IMPLEMENTATION */', implementation)
with tempfile.TemporaryDirectory(prefix='tomada-wifi-tests-') as temp:
    cfile = Path(temp) / 'test.c'
    binary = Path(temp) / 'test'
    cfile.write_text(harness)
    subprocess.run(['gcc', '-std=gnu99', '-Werror=implicit-function-declaration', str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
subprocess.run(['node', str(repo / 'tools/wifi_ui_test.js'), str(web / 'index.html')], check=True)

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.modes = set()
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        if tag == 'input' and attrs.get('name') == 'UPLINK':
            self.modes.add(attrs.get('value'))

page = (web / 'index.html').read_text()
parser = FormParser()
parser.feed(page)
script = page[page.rindex('<script>'):]
js_ids = {i for i in re.findall(r"\$\('([^']+)'\)", script) if not i.endswith('-') and not re.match(r'net\d-', i)}  # netN-* are built by the script
assert js_ids <= parser.ids, js_ids - parser.ids
assert parser.modes == {'cable', 'wifi'}
assert 'lang="en"' in page and not re.search('[\u3400-\u9fff]', page)
assert 'href="/llms.txt"' in page and (web / 'llms.txt').is_file() and not (web / 'agent_api.txt').exists()
assert '<title>MT7628KN Wi-Fi Extender</title>' in page and 'Smart Plug' not in page
assert 'agent_api' not in page, 'the page announces only /llms.txt'
prof = (repo / 'ra305x_ap_adv/ra305x_router/cfg/cfg_prof.c').read_bytes().decode('latin1')
reset = prof[prof.index('void CFG_reset_default()'):]
reset = reset[:reset.index('\n}\n')]
assert '_KEY' not in reset, 'factory reset must erase the WireGuard device key, not carry it over'
llms = (web / 'llms.txt').read_text()
assert '## API reference' in llms and 'agent_api' not in llms, 'one file for agents: guide and API reference'
assert page.count('<%') == 1, 'only the state CGI tag may appear; webcomp parses <%'
for endpoint in ('wifi_state', 'wifi_apply', 'wifi_scan', 'admin_apply', 'system_apply', 'wg_apply', 'startup_apply', 'networks_apply', 'firmware_apply', 'setup_apply', 'config_backup', 'config_restore'):
    assert (web / f'{endpoint}.html').is_file(), endpoint
assert not (web / 'factorySetting.html').exists()
assert 'WG_KEY' not in source, 'the web interface must never read the WireGuard device private key'
assert not (web / 'ntun_apply.html').exists()
cfg = (repo / 'ra305x_ap_adv/ra305x_router/webpages/web.cfg').read_text()
assert 'llms.txt' in cfg and 'agent_api' not in cfg
print('PASS: HTML form wiring, English interface and local agent instructions')

# Exercise the actual installer against a NOR flash model, including failures.
flash_source = (repo / 'ra305x_ap_adv/ra305x_router/cli/ramboot.c').read_text()
start = flash_source.index('/* Explicit network installation;')
end = flash_source.index('static void rb_worker(', start)
fragment = '\n'.join(line for line in flash_source[start:end].splitlines() if not line.startswith('#include'))
policy = (repo / 'ra305x_ap_adv/ra305x_router/include/flash_policy.h').read_text()
scaffold = (repo / 'tools/flash_policy_test.c').read_text()
with tempfile.TemporaryDirectory(prefix='tomada-flash-tests-') as temp:
    cfile = Path(temp) / 'test.c'
    binary = Path(temp) / 'test'
    cfile.write_text(scaffold.replace('/* IMPLEMENTATION */', policy + '\n' + fragment))
    subprocess.run(['gcc', '-std=gnu99', '-Werror=implicit-function-declaration', str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# Reproduce the cold-boot regression with a legacy static-IP profile.
lan_source = (repo / 'ra305x_ap_adv/ra305x_router/init/lan_start.c').read_bytes().decode('latin1')
start = lan_source.index('static int lan_ip_mode(int ipmode)')
end = lan_source.index('\n}', start) + 2
fragment = lan_source[start:end]
harness = '#include <assert.h>\n#define CFG_SYS_OPMODE 1\n#define CFG_WLN_ApCliEnable 2\nstatic int test_opmode, test_apcli;\nstatic int CFG_get(int id,int *out){*out=id==CFG_SYS_OPMODE?test_opmode:test_apcli;return 0;}\n' + fragment + '\nint main(void){test_apcli=0;test_opmode=2;assert(lan_ip_mode(1)==0);test_opmode=3;assert(lan_ip_mode(1)==0);assert(lan_ip_mode(0)==0);test_opmode=1;assert(lan_ip_mode(1)==1);test_apcli=1;test_opmode=2;assert(lan_ip_mode(1)==1);assert(lan_ip_mode(0)==0);test_opmode=3;assert(lan_ip_mode(1)==0);return 0;}\n'
with tempfile.TemporaryDirectory(prefix='tomada-dhcp-tests-') as temp:
    cfile=Path(temp)/'test.c';binary=Path(temp)/'test'
    cfile.write_text(harness)
    subprocess.run(['gcc',str(cfile),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
print('PASS: bridged AP/repeater cold boot uses DHCP despite a legacy static-IP setting; WISP router keeps a static LAN')

# WireGuard protocol core (wg/wg_proto.c): keyed BLAKE2s KAT and TAI64N.
# Interop with a real wg0: wg_host_test <priv> <pub> <ip> <port> <tunnel-src> <ping-dst>
router = repo / 'ra305x_ap_adv/ra305x_router'
with tempfile.TemporaryDirectory(prefix='tomada-wg-tests-') as temp:
    binary = Path(temp) / 'wg_host_test'
    sources = [repo / 'tools/wg_host_test.c', router / 'wg/wg_proto.c'] + [router / 'crypto' / f for f in ('blake2s.c', 'c25519.c', 'aead.c', 'sha2.c')]
    subprocess.run(['gcc', '-O2', '-std=gnu99', '-Wall', f'-I{router}/crypto', f'-I{router}/wg', '-o', str(binary)] + [str(f) for f in sources], check=True)
    subprocess.run([str(binary), '--selftest'], check=True)

# mDNS responder parsing and answers (init/mdns.c)
with tempfile.TemporaryDirectory(prefix='tomada-mdns-tests-') as temp:
    binary = Path(temp) / 'mdns_test'
    subprocess.run(['gcc', '-std=gnu99', '-Wall', '-DMDNS_HOST_TEST', f'-I{router}/init', '-o', str(binary), str(repo / 'tools/mdns_test.c')], check=True)
    subprocess.run([str(binary)], check=True)

# Startup script executor (cli/cmd_boot.c) with a fake command tree
with tempfile.TemporaryDirectory(prefix='tomada-boot-tests-') as temp:
    binary = Path(temp) / 'cli_boot_test'
    subprocess.run(['gcc', '-std=gnu99', '-Wall', '-DCLI_BOOT_HOST_TEST', f'-I{router}/cli', '-o', str(binary), str(repo / 'tools/cli_boot_test.c')], check=True)
    subprocess.run([str(binary)], check=True, stdout=subprocess.PIPE)
    print('PASS: startup script command-tree walk, results and isolation from the config')

# Routed networks and isolation rules (init/net_extra.c)
with tempfile.TemporaryDirectory(prefix='tomada-net-tests-') as temp:
    binary = Path(temp) / 'net_extra_test'
    subprocess.run(['gcc', '-std=gnu99', '-DNET_EXTRA_HOST_TEST', f'-I{router}/init', f'-I{router}/include', '-o', str(binary), str(repo / 'tools/net_extra_test.c')], check=True)
    subprocess.run([str(binary)], check=True, stdout=subprocess.PIPE)
    print('PASS: routed networks, address parsing and isolation rules (reach list, Internet, device access, via WireGuard, network 1 in bridge setups)')
