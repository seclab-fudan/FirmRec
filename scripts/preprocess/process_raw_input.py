#!python
import sys
import base64

# TODO: use pattern matching from VulnReportAnalyzer

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} INPUT")
        sys.exit(1)

    file_path = sys.argv[1]

    with open(file_path, "rb") as fp:
        data = fp.read()

        if data.split()[0] in ["GET", "POST"]:
            data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")

    print(repr(base64.b64encode(data)))


if __name__ == "__main__":
    main()
