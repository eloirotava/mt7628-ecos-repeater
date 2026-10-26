#!/usr/bin/env python3
"""Hardware smoke test: Telnet login and CLI commands with common Enter encodings."""
import argparse
import socket
import time


def expect(sock, marker, timeout=4):
    deadline = time.monotonic() + timeout
    data = bytearray()
    sock.settimeout(0.25)
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            raise RuntimeError('connection closed while waiting for %r: %r' % (marker, bytes(data)))
        data.extend(chunk)
        if marker in data:
            return bytes(data)
    raise RuntimeError('timeout waiting for %r: %r' % (marker, bytes(data)))


def test_session(host, user, password, ending):
    with socket.create_connection((host, 23), timeout=5) as sock:
        expect(sock, b'Login as:')
        for command, marker in ((user, b'Password:'), (password, b'CMD>'),
                                ('help', b'CMD>'), ('cfg', b'CFG>'),
                                ('get SYS_OPMODE', b'CFG>'), ('up', b'CMD>')):
            sock.sendall(command.encode() + ending)
            response = expect(sock, marker)
            if command == 'help' and not all(word in response for word in (b'cfg', b'net', b'os')):
                raise RuntimeError('help output incomplete: %r' % response)
            if command == 'get SYS_OPMODE' and b'SYS_OPMODE=' not in response:
                raise RuntimeError('configuration query failed: %r' % response)
        sock.sendall(b'exit' + ending)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host')
    parser.add_argument('--user', default='admin')
    parser.add_argument('--password', default='admin')
    args = parser.parse_args()
    failures = 0
    for name, ending in (('LF', b'\n'), ('CR', b'\r'), ('CR+LF', b'\r\n'), ('CR+NUL', b'\r\x00')):
        try:
            test_session(args.host, args.user, args.password, ending)
            print('%s: PASS (login, help, cfg, get, up)' % name, flush=True)
        except (OSError, RuntimeError) as exc:
            failures += 1
            print('%s: FAIL: %s' % (name, exc), flush=True)
        time.sleep(0.5)
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
