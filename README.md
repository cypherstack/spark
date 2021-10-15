# Spark

This is a research implementation of the [Spark](https://eprint.iacr.org/2021/1173) transaction protocol.
Its purpose is to demonstrate algorithms and make it easy to iterate on features and ideas.

**This code is experimental and not intended for use in production.**
**It is not written with secure implementation in mind, has not been formally reviewed, and likely contains errors.**


## Requirements

This code requires an active [Python 3 release](https://devguide.python.org/#status-of-python-branches).

Install all required non-standard packages: `pip3 install -r requirements.txt`


## Testing

A test workflow in this repository runs against all active Python 3 release minor versions.

[![Test status](../../actions/workflows/test.yml/badge.svg)](../../actions/workflows/test.yml)

Run the test suite locally using either:
- `python3 -m unittest discover`
- `pytest`
