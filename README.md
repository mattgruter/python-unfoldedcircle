# python-unfoldedcircle

Python library to interact with Unfolde Circle Remote Two.

## Supported Devices

This tool and library has been tested with:

- Remote Two

It might work with other devices from Unfolded Circle. If you have a device which is not listed above, please submit an issue.

## Installation

The easiest way to install is by using `pip`:

```sh
pip install python-unfoldedcircle
```

## Device Discovery

Discover devices on your network by running:

```sh
unfoldedcircle discover
```

Note: Devices need to be on the same network as you are in order to be discovered through UPnP.

Example:

```sh
$ unfoldedcircle discover
Discovered devices:
- Remote Two Bob (http://192.168.1.20:80/api/)
- Remote Two Marley (http://192.168.1.30:80/api/)
```

You can set the endpoint with the `--endpoint` command line option or with the environment variable `UC_ENDPOINT`.

## Usage

Invoke with `--help` to get a list of available commands and options.

```sh
unfoldedcircle --help
```

### Authentication

Authentication is necessary to interact with a device. The `auth login` command sets up an API key to be used by this tool.

```sh
$ unfoldedcricle --endpoint http://192.168.1.20:80/api/ auth login
PIN: ***
Use this API key for 'Remote Two Bob': PhyrUcD.YzNkOTg5MTA5ZTFkNDMxMGIxODVkMTJiYmU3ODllMjcuMmFjZDk0YmU5N2RjNDM4ZWFhYzU3ZTY1MjQzY2EyNTk
```

Set the API key returned by the `login` command with the `--apikey` command line option or with the environment variable `UC_APIKEY`.
