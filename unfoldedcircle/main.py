import copy
import logging
import socket
import sys
import time
from urllib.parse import urljoin, urlparse

import click
import httpx
import zeroconf

ZEROCONF_TIMEOUT = 3
ZEROCONF_SERVICE_TYPE = "_uc-remote._tcp.local."


class DeviceList:
    def __init__(self, devices):
        self.devices = devices

    def __iter__(self):
        return self.devices.__iter__()

    def __len__(self):
        return len(self.devices)


class Device:
    def __init__(self, endpoint, username=None, password=None):
        self.endpoint = endpoint
        p = urlparse(endpoint)
        self.host = p.hostname
        self.port = p.port
        self.username = username
        self.password = password
        self.__info = None
        self.__logged_in = False
        self.__auth_cookie = {}

    def url(self, path=""):
        return urljoin(self.endpoint, path, allow_fragments=True)

    def client(self):
        client = httpx.Client()
        if self.__logged_in:
            client.cookies.update(self.__auth_cookie)
        return client

    def info(self):
        if not self.__info:
            with self.client() as client:
                r = client.get(self.url("pub/version"))
                return r.json()
        return self.__info

    def login(self):
        if self.__logged_in:
            return
        with httpx.Client() as client:
            body = {"username": self.username, "password": self.password}
            r = client.post(self.url("pub/login"), json=body)
            httpx.Response
        if r.is_error:
            click.echo(f"Error: {r.json()['message']}")
            sys.exit()
        logging.debug("Login successful")
        self.__auth_cookie = {"id": r.cookies["id"]}
        self.__logged_in = True

    def fetch_docks(self):
        self.login()
        with self.client() as client:
            r = client.get(self.url("docks"))
        return r.json()


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


pass_devices = click.make_pass_decorator(DeviceList)


@click.group()
@click.option("--endpoint", envvar="UC_ENDPOINT")
@click.option("-d", "--debug", default=False, count=True)
@click.option("--testing", envvar="UC_TESTING", hidden=True, is_flag=True)
@click.option("--username", default="web-configurator", hidden=True)
@click.option("--pin", default="1234", type=str)
@click.pass_context
@click.version_option(package_name="python-unfoldedcircle")
def cli(ctx, endpoint, debug, testing, username, pin):
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
        ctx.obj = DeviceList([Device(endpoint, username, password=pin)])


@cli.command(help="Print device information.")
@pass_devices
def info(devices):
    for d in devices:
        click.echo(f"Remote: '{d.info()['device_name']}'")
        click.echo(f"  endpoint: {d.url()}")
        click.echo(f"  version: {d.info()['os']}")
        click.echo(f"  api: {d.info()['api']}")
        click.echo(f"  core: {d.info()['core']}")


@cli.command(help="Discover supported devices.")
@pass_devices
def discover(devices):
    if not devices:
        click.echo("No devices discovered.")
    else:
        click.echo("Discovered devices:")
        for d in devices:
            click.echo(f"- {d.info()['device_name']} ({d.endpoint})")


@cli.command(help="List docks connected to a remote")
@pass_devices
def docks(devices):
    for d in devices:
        docks = d.fetch_docks()
        click.echo(f"Remote: '{d.info()['device_name']}'")
        for dock in docks:
            click.echo(f"- {dock['name']} ({dock['dock_id']})")


if __name__ == "__main__":
    cli()
