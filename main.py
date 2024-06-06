import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]

    print("domain: ", domain)
    print("ip: ", "192.168.0.1")


if __name__ == "__main__":
    main() 
