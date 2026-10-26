#!/usr/bin/env python3
"""Exercise the installed telnet client through a PTY using normal Enter."""
import os
import pty
import select
import subprocess
import sys
import time

master, slave = pty.openpty()
client = subprocess.Popen(['telnet', sys.argv[1]], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
os.close(slave)


def expect(marker, timeout=8):
    end = time.monotonic() + timeout
    data = bytearray()
    while time.monotonic() < end:
        if not select.select([master], [], [], 0.2)[0]:
            continue
        chunk = os.read(master, 4096)
        if not chunk:
            break
        data.extend(chunk)
        if marker in data:
            return bytes(data)
    raise RuntimeError('expected %r, received %r' % (marker, bytes(data)))


try:
    expect(b'Login as:')
    os.write(master, b'admin\r')
    expect(b'Password:')
    os.write(master, b'admin\r')
    expect(b'CMD>')
    os.write(master, b'help\r')
    output = expect(b'CMD>')
    assert all(word in output for word in (b'cfg', b'net', b'os')), output
    os.write(master, b'cfg\r')
    expect(b'CFG>')
    os.write(master, b'get SYS_OPMODE\r')
    output = expect(b'CFG>')
    assert b'SYS_OPMODE=' in output, output
    os.write(master, b'up\r')
    expect(b'CMD>')
    os.write(master, b'exit\r')
    print('system telnet client + normal Enter: PASS (login, help, cfg, get, up)')
finally:
    client.terminate()
    try:
        client.wait(timeout=2)
    except subprocess.TimeoutExpired:
        client.kill()
        client.wait()
    os.close(master)
