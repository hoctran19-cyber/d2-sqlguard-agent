"""Chạy web app trên localhost: python -m sqlguard.web [--port 8000]."""

import argparse

import uvicorn


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    # Chỉ nghe trên 127.0.0.1: app có tài khoản demo, không được mở ra mạng ngoài.
    uvicorn.run("sqlguard.web.app:app", host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
