import sys
import struct
import socket
from io import BytesIO
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
    qname: str
    qtype: int = 1  # The QType (1 = A)
    qclass: int = 1  # The QCLASS (1 = IN)

    def to_bytes(self):
        parts = self.qname.split('.')
        name_bytes = b''.join((len(part).to_bytes(
            1, byteorder='big') + part.encode('ascii')) for part in parts) + b'\x00'
        return name_bytes + struct.pack('!HH', self.qtype, self.qclass)


@dataclass
class DNSRecord:
    name: int
    type: int
    class_: int
    ttl: int
    length: int
    data: int


def parse_header(reader):
    header_fields = struct.unpack('!HHHHHH', reader.read(12))
    return DNSHeader(*header_fields)


def parse_domain_name(reader):
    labels = []
    while True:
        length_byte = reader.read(1)
        length = length_byte[0]
        if length == 0:
            break
        if length >= 192:  # 11000000
            # Handle compression
            pointer_byte = reader.read(1)
            pointer = struct.unpack('!H', length_byte + pointer_byte)[0]
            pointer &= 0x3FFF  # Remove the two most significant bits
            current_position = reader.tell()
            reader.seek(pointer)
            subdomain = parse_domain_name(reader)
            labels.append(subdomain)
            reader.seek(current_position)
            break
        labels.append(reader.read(length).decode('ascii'))
    return ".".join(labels)


def parse_question(reader):
    qname = parse_domain_name(reader)
    data = reader.read(4)
    qtype, qclass = struct.unpack("!HH", data)
    return DNSQuestion(qname, qtype, qclass)


def parse_questions(reader, cnt):
    questions = []
    for _ in range(cnt):
        questions.append(parse_question(reader))
    return questions


def parse_record(reader):
    name = parse_domain_name(reader)
    data = reader.read(10)
    type, class_, ttl, length = struct.unpack("!HHIH", data)
    if type == 1:
        data = socket.inet_ntoa(reader.read(length))
    else:
        data = parse_domain_name(reader)

    return DNSRecord(name, type, class_, ttl, length, data)


def parse_records(reader, cnt):
    records = []
    for _ in range(cnt):
        records.append(parse_record(reader))
    return records


def parse_response(bytes, ns):
    reader = BytesIO(bytes)
    header = parse_header(reader)
    questions = parse_questions(reader, header.qdcount)
    if ns:
        cnt = header.nscount
    else:
        cnt = header.ancount
    records = parse_records(reader, cnt)
    return header, questions, records


def build_query(domain: str):
    header = DNSHeader(xid=12345, flags=0x0100, qdcount=1)
    question = DNSQuestion(qname=domain)
    return header.to_bytes() + question.to_bytes()


def send_query(domain: str, server: str, port: int = 53, ns=False):
    query = build_query(domain)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        print("query to ", server)
        sock.sendto(query, (server, port))
        # DNS specification mandates a maximum of 512 bytes for all messages
        response, _ = sock.recvfrom(512)
        return parse_response(response, ns)
    finally:
        sock.close()


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]

    root_server = '198.41.0.4'
    _, _, ns_records = send_query(domain, root_server, 53, True)

    if len(ns_records) == 0:
        print("No records found in the root server.")
        return

    tld_server = None
    for r in ns_records:
        if r.type == 2:
            tld_server = r.data
            break

    if tld_server is None:
        print("No TLD name server found")
        return

    _, _, ns_records = send_query(domain, tld_server, 53, True)

    authority_server = None
    for r in ns_records:
        if r.type == 2:
            authority_server = r.data
            break

    if authority_server is None:
        print("No authority server found")
        return

    _, _, records = send_query(domain, authority_server, 53)
    for r in records:
        print(r)


if __name__ == "__main__":
    main()
