import copy
import logging
import socket
import time

import click
import httpx
import zeroconf

ZEROCONF_TIMEOUT = 1
ZEROCONF_SERVICE_TYPE = "_uc-remote._tcp.local."


class Device:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def url(self, path=""):
        if self.port == "80":
            return f"http://{self.host}/api/{path}"
        else:
            return f"http://{self.host}:{self.port}/api/{path}"

    def info(self):
        with httpx.Client() as client:
            r = client.get(self.url("pub/version"))
            return r.json()


def discover_devices():
    class DeviceListener:
        def __init__(self):
            self.devices = []

        def add_service(self, zc, type, name):
            info = zc.get_service_info(type, name)
            host = socket.inet_ntoa(info.addresses[0])
            port = info.port
            self.devices.append(Device(host, port))

        def update_service(self, zc, type, name):
            pass

        def remove_service(self, zc, type, name):
            pass

    zc = zeroconf.Zeroconf()
    listener = DeviceListener()
    zeroconf.ServiceBrowser(zc, ZEROCONF_SERVICE_TYPE, listener)
    try:
        time.sleep(ZEROCONF_TIMEOUT)
    finally:
        zc.close()
    return copy.deepcopy(listener.devices)


def print_info(device):
    info = device.info()
    click.echo(f"Remote: '{info['device_name']}'")
    click.echo(f"  endpoint: {device.url()}")
    click.echo(f"  version: {info['os']}")
    click.echo(f"  api: {info['api']}")
    click.echo(f"  core: {info['core']}")


pass_device = click.make_pass_decorator(Device)


@click.group()
@click.option("--host", envvar="UC_HOST", required=False)
@click.option("--port", envvar="UC_PORT", required=False)
@click.option("-d", "--debug", default=False, count=True)
@click.pass_context
@click.version_option(package_name="python-unfoldedcircle")
def cli(ctx, host, port, debug):
    lvl = logging.INFO
    if debug:
        lvl = logging.DEBUG
        click.echo("Setting debug level to %s" % debug)
    logging.basicConfig(level=lvl)

    if ctx.invoked_subcommand == "discover":
        return

    logging.debug("Using host %s, port %s", host, port)
    ctx.obj = Device(host, port)


@cli.command()
@pass_device
def info(dev):
    print_info(dev)


@cli.command()
def discover():
    for d in discover_devices():
        print_info(d)


if __name__ == "__main__":
    cli()
