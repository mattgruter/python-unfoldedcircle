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


class DeviceList(list):
    def __init__(self, *args, **kwargs):
        super(DeviceList, self).__init__(args[0])


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

    def fetch_activities(self):
        self.login()
        with self.client() as client:
            r = client.get(self.url("activities"))
        return r.json()

    def fetch_remotes(self):
        self.login()
        with self.client() as client:
            r = client.get(self.url("remotes"))
            self.remotes = r.json()
            for remote in self.remotes:
                r = client.get(self.url(f"remotes/{remote['entity_id']}/ir"))
                if r:
                    remote["codeset"] = r.json()

        return self.remotes

    def fetch_emitters(self):
        self.login()
        with self.client() as client:
            r = client.get(self.url("ir/emitters"))
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
        if not docks:
            click.echo("No docks found")
            return
        click.echo(f"Docks connected to '{d.info()['device_name']}'")
        fields = {
            "id": "dock_id",
            "model": "model",
            "url": "resolved_ws_url",
            "active": "active",
        }
        for dock in docks:
            click.echo(f"- name: '{dock['name']}'")
            for field, k in fields.items():
                click.echo(f"    {field : <8}{dock[k]}")
            click.echo()


@cli.command(help="List activities")
@pass_devices
def activities(devices):
    for d in devices:
        activities = d.fetch_activities()
        if not activities:
            click.echo("No activities found")
            return
        click.echo(f"Activities configured on '{d.info()['device_name']}'")
        fields = {
            "id": "entity_id",
            "enabled": "enabled",
        }
        for a in activities:
            click.echo(f"- name: '{a['name']['en']}'")
            for field, k in fields.items():
                click.echo(f"    {field : <8}{a[k]}")
            click.echo()


@cli.command(help="List IR codesets")
@pass_devices
def ircodes(devices):
    for d in devices:
        remotes = d.fetch_remotes()
        if not remotes:
            click.echo("No IR codesets found")
            return
        click.echo(f"IR codesets configured on '{d.info()['device_name']}")
        for r in remotes:
            click.echo(f"- name: '{r['name']['en']}'")
            click.echo(f"    id      {r['entity_id']}")
            click.echo(f"    codeset {r['codeset']['id']}")
            for code in r["codeset"]["codes"]:
                click.echo(f"      - {code['cmd_id']}")


@cli.command(help="List IR emitters")
@pass_devices
def iremitters(devices):
    for d in devices:
        emitters = d.fetch_emitters()
        if not emitters:
            click.echo("No IR emitters found")
            return
        click.echo(f"IR emitters available on '{d.info()['device_name']}")
        fields = {
            "id": "device_id",
            "type": "type",
            "active": "active",
        }
        for e in emitters:
            click.echo(f"- name: '{e['name']}'")
            for field, k in fields.items():
                click.echo(f"    {field : <8}{e[k]}")
            click.echo()


if __name__ == "__main__":
    cli()
