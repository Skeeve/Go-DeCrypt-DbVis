# decrypt-dbvis ~ Stephan Hradek

## Description

DbVisualizer uses PBEWithMD5AndDES with a static key to store passwords.

This is a quick hack to extract and decrypt credentials from DbVisualizer config files.

Tested against DbVisualizer Free 9.0.9 and 9.1.6, as well as Pro 24.1.4

This go programm was created using
[gerry/decrypt_dbvis.py](https://gist.github.com/gerry/c4602c23783d894b8d96) as
a guideline.

## Motivation

Since Mac OS no longer has Python installed.
Also I'm not a Python programmer and I'm currently learning Go, I devided to
convert
[gerry/decrypt_dbvis.py](https://gist.github.com/gerry/c4602c23783d894b8d96) to Go.

## Compilation using Go

If you have Go installed, check the `Dockerfile` to see the easy build steps.

## Compilation using Docker

If you do not have Go installed, but Docker, simply use

```shell
./build # to build for intel Mac
./build linux # to build for linux 64 Bit
```

Check the `build` script to see the other options.

## Installation

Simply move the compiled `decrypt-dbvis` to somewher in your $PATH.
