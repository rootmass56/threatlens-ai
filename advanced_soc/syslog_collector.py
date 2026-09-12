"""Small UDP syslog edge collector that forwards durable envelopes to ThreatLens HTTP ingestion."""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime


def main() -> int:
    host=os.getenv("THREATLENS_SYSLOG_BIND","0.0.0.0")
    port=int(os.getenv("THREATLENS_SYSLOG_PORT","5514"))
    api=os.getenv("THREATLENS_SYSLOG_API_URL","http://api:10000/api/v1/ingest/realtime")
    key=os.getenv("THREATLENS_SYSLOG_INGEST_KEY","").strip()
    if not key:
        raise SystemExit("THREATLENS_SYSLOG_INGEST_KEY is required; create a syslog_rfc ingestion source first.")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(2.0)
    print(f"ThreatLens syslog collector listening UDP {host}:{port}",flush=True)
    while True:
        try:
            data,address=sock.recvfrom(65535)
        except TimeoutError:
            continue
        message=data.decode("utf-8",errors="replace").strip()
        if not message:
            continue
        event_id=f"{int(time.time()*1000)}-{address[0]}-{abs(hash(message)) & 0xffffffff:x}"
        payload={"records":[{"client_event_id":event_id,"payload":{"message":message,"source_ip":address[0],"received_at":datetime.now(UTC).isoformat(),"transport":"udp"}}],"analysis_name":"Realtime Syslog"}
        request=urllib.request.Request(api,data=json.dumps(payload).encode(),headers={"Content-Type":"application/json","X-ThreatLens-Ingest-Key":key},method="POST")
        try:
            with urllib.request.urlopen(request,timeout=30) as response:
                response.read()
        except (urllib.error.URLError,TimeoutError) as error:
            print(f"syslog forward failed: {error}",flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
