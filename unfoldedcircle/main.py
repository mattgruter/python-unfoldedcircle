import copy
import logging
import socket
import time
from urllib.parse import urlparse, urljoin

import click
import httpx
import zeroconf

ZEROCONF_TIMEOUT = 1
ZEROCONF_SERVICE_TYPE = "_uc-remote._tcp.local."


class DeviceList:
    def __init__(self, devices):
        self.devices = devices

    def __iter__(self):
        return self.devices.__iter__()

    def __len__(self):
        return len(self.devices)


class Device:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        p = urlparse(endpoint)
        self.host = p.hostname
        self.port = p.port
        self.__info = None

    def url(self, path=""):
        return urljoin(self.endpoint, path, allow_fragments=True)

    def info(self):
        if not self.__info:
            with httpx.Client() as client:
                r = client.get(self.url("pub/version"))
                return r.json()
        return self.__info


def discover_devices():
    class DeviceListener:
        def __init__(self):
            self.devices = []

        def add_service(self, zc, type, name):
            info = zc.get_service_info(type, name)
            host = socket.inet_ntoa(info.addresses[0])
            endpoint = f"http://{host}:{info.port}/api/"
            self.devices.append(Device(endpoint))

        def update_service(self, zc, type, name):
            pass

        def remove_service(self, zc, type, name):
            pass

    zc = zeroconf.Zeroconf(interfaces=zeroconf.InterfaceChoice.Default)
    listener = DeviceListener()
    zeroconf.ServiceBrowser(zc, ZEROCONF_SERVICE_TYPE, listener)
    try:
        time.sleep(ZEROCONF_TIMEOUT)
    finally:
        zc.close()
    return DeviceList(copy.deepcopy(listener.devices))


def print_info(device):
    info = device.info()
    click.echo(f"Remote: '{info['device_name']}'")
    click.echo(f"  endpoint: {device.url()}")
    click.echo(f"  version: {info['os']}")
    click.echo(f"  api: {info['api']}")
    click.echo(f"  core: {info['core']}")


pass_devices = click.make_pass_decorator(DeviceList)


@click.group()
@click.option("--endpoint", envvar="UC_ENDPOINT")
@click.option("-d", "--debug", default=False, count=True)
@click.option("--testing", envvar="UC_TESTING", hidden=True, is_flag=True)
@click.pass_context
@click.version_option(package_name="python-unfoldedcircle")
def cli(ctx, endpoint, debug, testing):
    ctx.obj = dict()

    if testing:
        click.echo("-- Testing mode --")
        if not endpoint:
            endpoint = "http://localhost:8080/api/"

    lvl = logging.WARN
    if debug:
        lvl = logging.DEBUG
        click.echo("Setting debug level to %s" % debug)
    logging.basicConfig(level=lvl)

    if not endpoint:
        logging.debug("Auto-discoverying devices")
        ctx.obj = discover_devices()
    else:
        logging.debug("Using endpoint %s", endpoint)
        ctx.obj = DeviceList([Device(endpoint)])


@cli.command(help="Print device information.")
@pass_devices
def info(devices):
    for d in devices:
        print_info(d)


@cli.command(help="Discover supported devices.")
@pass_devices
def discover(devices):
    if not devices:
        click.echo("No devices discovered.")
    else:
        click.echo("Discovered devices:")
        for d in devices:
            click.echo(f"- {d.info()['device_name']} ({d.host})")


if __name__ == "__main__":
    cli()
