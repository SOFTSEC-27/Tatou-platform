import os
import sys
import afl


def exercise(data):
    if data.startswith(b"A"):
        result = 10
        result += 1
        return result
    if data.startswith(b"B"):
        result = 20
        result *= 2
        return result
    return 0


def main():
    with open(sys.argv[1], "rb") as stream:
        data = stream.read(4096)
    exercise(data)


if __name__ == "__main__":
    afl.init()
    main()
    os._exit(0)
