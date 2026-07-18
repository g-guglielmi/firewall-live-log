"""One UDP syslog listener per device.

Each listener binds its device's port, parses every datagram with the
device's configured vendor (or auto-detect), and puts a normalized item
on the shared queue for the single writer thread to persist.  Queue items:

    ("ev", ts, device, vendor, src, dst, proto, dst_port, action, rule)
    ("un", ts, device, raw)          # unparseable line, kept for diagnosis

If the queue is full (writer overloaded) the datagram is dropped and the
shared drop counter is incremented — bounded memory beats unbounded lag.
"""

import queue
import socket
import sys
import time

import parsers

RECVBUF_REQUEST = 8 * 1024 * 1024


def run(stop_event, device, q, drops):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECVBUF_REQUEST)
    try:
        sock.bind(("0.0.0.0", device.port))
    except OSError as e:
        print(f"[listener {device.name}] cannot bind udp/{device.port}: {e}",
              file=sys.stderr)
        stop_event.set()
        return
    sock.settimeout(1.0)
    print(f"[listener {device.name}] udp/{device.port} vendor={device.vendor}")
    sys.stdout.flush()

    while not stop_event.is_set():
        try:
            data, _addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            if stop_event.is_set():
                break
            raise

        text = data.decode("utf-8", "replace")
        now = int(time.time())
        rec = parsers.parse(text, device.vendor)
        if rec is None:
            item = ("un", now, device.name, text)
        else:
            vendor, src, dst, proto, dport, action, rule = rec
            item = ("ev", now, device.name, vendor, src, dst, proto,
                    dport, action, rule)
        try:
            q.put_nowait(item)
        except queue.Full:
            with drops["lock"]:
                drops["n"] += 1

    sock.close()
    print(f"[listener {device.name}] stopped")
    sys.stdout.flush()
