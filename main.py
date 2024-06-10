import sys
import struct
import socket
from dataclasses import dataclass


@dataclass
class DNSHeader:
    xid: int  # Randomly chosen identifier
    flags: int  # Bit-mask to indicate request/response
    qdcount: int = 0  # Number of questions
    ancount: int = 0  # Number of answers
    nscount: int = 0  # Number of authority records
    arcount: int = 0  # Number of additional records

    def to_bytes(self):
        # https://www.ietf.org/rfc/rfc1035.txt
        return struct.pack('!HHHHHH', self.xid, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount)


@dataclass
class DNSQuestion:
    name: str
    dnstype: int = 1  # The QType (1 = A)
    dnsclass: int = 1  # The QCLASS (1 = IN)

    def to_bytes(self):
        parts = self.name.split('.')
        name_bytes = b''.join((len(part).to_bytes(
            1, byteorder='big') + part.encode('ascii')) for part in parts) + b'\x00'
        return name_bytes + struct.pack('!HH', self.dnstype, self.dnsclass)


def build_query(domain: str):
    header = DNSHeader(xid=12345, flags=0x0100, qdcount=1)
    question = DNSQuestion(name=domain)
    return header.to_bytes() + question.to_bytes()


def send_query(domain: str, server: str, port: int = 53):
    query = build_query(domain)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        print("query: ", query)
        sock.sendto(query, (server, port))
        response, _ = sock.recvfrom(512)

        print("resonse: ", response)
        return response
    finally:
        sock.close()


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]

    send_query(domain, '8.8.8.8', 53)


if __name__ == "__main__":
    main()
