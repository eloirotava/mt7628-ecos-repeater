# mt7628-ecos-repeater

Alternative eCos firmware for a generic MT7628KN Wi-Fi plug repeater
(board HX7628_L2, 8 MB RAM, 2 MB SPI flash, U-Boot 1.1.3 with menu 1-9).
Based on the MediaTek/Ralink eCos SDK published as `icplus/mtk7628_eCos`.

## What changed from the SDK
- Builds on a current Ubuntu runner (GitHub Actions, see `.github/workflows/build.yml`).
- Console at 57600 baud, correct UART TX address for MT7628.
- Telnet CLI (port 23) accepts LF, CR, CR+LF and CR+NUL as Enter.
- LAN uses DHCP in AP / repeater modes; DHCP retries until a lease arrives.
- **Rescue address**: `192.168.11.1/24` is always added to the LAN. If no DHCP
  lease arrives in ~2 minutes it becomes the primary address, so a PC with a
  static `192.168.11.x` on the cable can always reach the device.
- **Reset button** (GPIO45, active low): short press reboots; hold > 3.2 s and
  release restores factory defaults *and saves them to flash*.
- Factory defaults: bridged AP, DHCP client, no DHCP server, WPA2 (`88888888`).
- English web UI for AP / repeater setup, `/llms.txt`.
- `ramboot` CLI command: download a uImage by TFTP and boot it from RAM, or
  install it to the firmware partition only (`ramboot install <tftp-ip> <file> CONFIRM-FLASH`).
  U-Boot, its environment, the config sector and the Wi-Fi calibration are never touched.
- Hardware watchdog kept alive; a test image that hangs falls back to the flash image.

## Build
Push to any branch; the artifact `firmware` holds `eCos_runner.img` (uImage, load/entry 0x80500000).

## Test without flashing
From a running build: `python3 tools/ramboot_client.py <device-ip> <tftp-ip> eCos_runner.img --boot`.
Always test in RAM before installing.

## Default credentials
Web and telnet: `admin` / `admin`. Change them.

No warranty. Keep a full flash backup before installing anything.
