#!/usr/bin/env python3
"""
dns_client.py

A minimal DNS client that queries a DNS server's TXT record and prints results.
- Uses dnslib to construct and parse DNS messages.
- Shows the raw request/response bytes and decoded TXT strings.

Usage:
    python3 dns_client.py lesson1.example. --server 127.0.0.1 --port 53535
"""
import argparse
import socket
from dnslib import DNSRecord, QTYPE

def query_txt(server, port, qname, timeout=3.0):
    q = DNSRecord.question(qname, qtype="TXT")
    raw = q.pack()
    print(f"Packed DNS query ({len(raw)} bytes) -> {qname} (TXT)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(raw, (server, port))
        resp_raw, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    print(f"Received raw response ({len(resp_raw)} bytes)")
    resp = DNSRecord.parse(resp_raw)
    return resp

def pretty_print_txt_response(resp):
    # Print header info
    print("Response Header:", resp.header)
    if resp.header.rcode != 0:
        print("Non-success rcode:", resp.header.rcode)
    # Print answers
    if resp.rr:
        for rr in resp.rr:
            print(f"Answer: {rr.rname} TYPE={rr.rtype} TTL={rr.ttl}")
            # rr.rdata is a TXT object for TXT answers
            try:
                txt_parts = rr.rdata.strings  # list of bytes
                # decode for printing
                txt_decoded = [part.decode("utf-8", errors="replace") for part in txt_parts]
                print(" TXT parts:", txt_decoded)
            except Exception as e:
                print(" Could not decode TXT parts:", e)
    else:
        print("No answers in response")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Educational DNS TXT query client")
    p.add_argument("qname", help="Query name (e.g., lesson1.example.)")
    p.add_argument("--server", default="127.0.0.1", help="DNS server address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=53535, help="DNS server UDP port (default 53535)")
    args = p.parse_args()
    resp = query_txt(args.server, args.port, args.qname)
    pretty_print_txt_response(resp)
