"""Serve the evaluation console on localhost: python -m evaluation.web [--port 8765]."""

import argparse

import uvicorn

from evaluation.web.app import app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    # Loopback only: the console can start experiments and must not be exposed to the network.
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
