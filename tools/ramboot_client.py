#!/usr/bin/env python3
"""Control the eCos RAM loader through Telnet; no serial or flash writes."""
import argparse
import re
import socket
import time


class Console:
    def __init__(self, host, user, password):
        self.sock = socket.create_connection((host, 23), timeout=3)
        self.buf = bytearray()
        try:
            self.expect(b'Login as:')
            self.sock.sendall(user.encode() + b'\r\n')
            self.expect(b'Password:')
            self.sock.sendall(password.encode() + b'\r\n')
            prompt = self.expect(b'>')
            for _ in range(8):
                if prompt.endswith(b'CMD>'):
                    break
                self.sock.sendall(b'up\r\n')
                prompt = self.expect(b'>')
            else:
                raise RuntimeError('cannot reach root console prompt')
        except BaseException:
            self.sock.close()
            raise

    def expect(self, marker, timeout=5):
        deadline = time.monotonic() + timeout
        self.sock.settimeout(0.3)
        while time.monotonic() < deadline:
            at = self.buf.find(marker)
            if at >= 0:
                end = at + len(marker)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                raise EOFError('console connection closed')
            self.buf.extend(data)
            if len(self.buf) > 65536:
                raise RuntimeError('console response exceeds limit')
        raise TimeoutError('expected %r; last output: %r' % (marker, bytes(self.buf[-500:])))

    def command(self, command):
        self.sock.sendall(command.encode() + b'\r\n')
        return self.expect(b'CMD>')

    def status(self):
        out = self.command('ramboot status')
        matches = re.findall(rb'ramboot v1: state=(\w+) busy=(\d+) received=(\d+) error=([^\r\n]*)', out)
        if not matches:
            raise RuntimeError('RAM loader status missing: %r' % out)
        state, busy, received, error = matches[-1]
        return state.decode(), int(busy), int(received), error.decode()

    def close(self):
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host')
    parser.add_argument('server')
    parser.add_argument('file')
    parser.add_argument('--boot', action='store_true')
    parser.add_argument('--expect-error')
    parser.add_argument('--user', default='admin')
    parser.add_argument('--password', default='admin')
    args = parser.parse_args()
    if any(c.isspace() for c in args.file) or len(args.file) >= 128:
        parser.error('TFTP filename must be shorter than 128 bytes and contain no whitespace')
    console = Console(args.host, args.user, args.password)
    try:
        mode = 'boot' if args.boot else 'check'
        response = console.command('ramboot %s %s %s' % (mode, args.server, args.file))
        if b'ramboot: queued' not in response:
            raise RuntimeError('command not queued: %r' % response)
        deadline = time.monotonic() + 55
        last = None
        while time.monotonic() < deadline:
            time.sleep(0.3)
            try:
                status = console.status()
            except (OSError, EOFError, TimeoutError):
                if args.boot:
                    break
                raise
            if status != last:
                print('state=%s busy=%d received=%d error=%s' % status, flush=True)
                last = status
            state, busy, received, error = status
            if state == 'failed' and not busy:
                if args.expect_error and args.expect_error in error:
                    print('PASS: invalid/unavailable image rejected; console responsive')
                    return 0
                raise RuntimeError(error)
            if not busy and state == 'checked':
                if args.expect_error:
                    raise RuntimeError('expected rejection but image validated')
                print('PASS: complete image validated, no execution or flash write')
                return 0
            if state == 'booting' and args.boot:
                break
        else:
            raise TimeoutError('RAM loader did not finish in time')
    finally:
        console.close()
    if not args.boot:
        raise RuntimeError('unexpected loader state')
    print('RAM handoff requested; waiting for the console to return', flush=True)
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        time.sleep(2)
        current = None
        try:
            current = Console(args.host, args.user, args.password)
            state, busy, received, error = current.status()
            if state == 'idle' and not busy and received == 0:
                print('PASS: fresh RAM-loader instance reachable over Telnet')
                return 0
        except (OSError, EOFError, TimeoutError, RuntimeError):
            pass
        finally:
            if current:
                current.close()
    raise TimeoutError('fresh console not confirmed; recovery required')


if __name__ == '__main__':
    raise SystemExit(main())
