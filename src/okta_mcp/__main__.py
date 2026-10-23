import sys

from okta_mcp import __version__


def main() -> int:
    print(f"okta-mcp {__version__}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
