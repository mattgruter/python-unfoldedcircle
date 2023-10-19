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


class NoDefaultEmitterError(Exception):
    "Raised when default IR emitter can't be inferred."
    pass


class EmitterNotFoundError(Exception):
    """Raised when IR emitter with a given name can't be found.

    Attributes:
        name -- name of emitter that wasn't found
        message -- explanation of the error
    """

    def __init__(self, name, message="Emitter not found on device"):
        self.name = name
        self.message = message
        super().__init__(self.message)


class IRCodesetNotFound(Exception):
    """Raised when IR codeset with a given name can't be found.

    Attributes:
        name -- IR target name that wasn't found
        message -- explanation of the error
    """

    def __init__(self, name, message="IR target name not found in codesets"):
        self.name = name
        self.message = message
        super().__init__(self.message)


class DeviceGroup(list):
    def __init__(self, *args, **kwargs):
        super(DeviceGroup, self).__init__(args[0])

    def send_ircmd(self, target, cmd, emitter_name=None):
        dev, emitter = self.find_emitter(emitter_name)
        dev2, codeset = self.find_codeset(target)
        assert dev == dev2
        logging.debug(
            "Sending '%s' to '%s' via emitter '%s' on device '%s'",
            cmd,
            target,
            emitter["name"],
            dev.name,
        )
        dev.send_ircode(emitter["device_id"], codeset, cmd)

    def find_emitter(self, emitter_name):
        if len(self) > 1 and not emitter_name:
            logging.info(
                "Unable to infer default emitter with more than 1 device."
            )
            raise NoDefaultEmitterError()
        for d in self:
            emitters = d.fetch_emitters()
            if not emitter_name:
                if len(emitters) == 1:
                    e = emitters[0]
                    logging.debug(
                        "Selecting default IR emitter '%s'", e["name"]
                    )
                    return d, e
                elif len(emitters) > 1:
                    raise NoDefaultEmitterError()

            for e in emitters:
                if emitter_name == e["name"]:
                    logging.debug(
                        "Found IR emitter '%s' connected to device '%s'",
                        emitter_name,
                        d.name,
                    )
                    return d, e
            logging.debug(
                "IR emitter '%s' not found in device '%s'",
                emitter_name,
                d.name,
            )
        else:
            msg = f"IR emitter '{emitter_name}' not found."
            raise EmitterNotFoundError(emitter_name, message=msg)

    def find_codeset(self, target):
        logging.debug("Searching for IR target '%s'", target)
        for d in self:
            remotes = d.fetch_remotes()
            for r in remotes:
                if target in r["name"].values():
                    logging.debug(
                        "Found IR target '%s' on device '%s'",
                        target,
                        d.info()["device_name"],
                    )
                    return d, r["codeset"]["id"]
        else:
            msg = f"IR target '{target}' not found."
            raise IRCodesetNotFound(target, message=msg)


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

    @property
    def name(self):
        return self.info()["device_name"]

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

    def send_ircode(self, emitter, codeset, command):
        self.login()
        with self.client() as client:
            body = {"codeset_id": codeset, "cmd_id": command}
            url = self.url(f"ir/emitters/{emitter}/send")
            r = client.put(url=url, json=body)
            if r.is_error:
                code = r.status_code
                err = r.json()
                click.echo(f"Error: {code} {err['code']}: {err['message']}")


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
    return DeviceGroup(copy.deepcopy(listener.devices))


pass_devices = click.make_pass_decorator(DeviceGroup)


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
        ctx.obj = DeviceGroup([Device(endpoint, username, password=pin)])


@cli.command()
@pass_devices
def info(devices):
    """Print device information."""

    for d in devices:
        click.echo(f"Remote: '{d.info()['device_name']}'")
        click.echo(f"  endpoint: {d.url()}")
        click.echo(f"  version: {d.info()['os']}")
        click.echo(f"  api: {d.info()['api']}")
        click.echo(f"  core: {d.info()['core']}")


@cli.command()
@pass_devices
def discover(devices):
    """Discover supported devices."""

    if not devices:
        click.echo("No devices discovered.")
        sys.exit(-1)
    else:
        click.echo("Discovered devices:")
        for d in devices:
            click.echo(f"- {d.info()['device_name']} ({d.endpoint})")


@cli.command()
@pass_devices
def docks(devices):
    """List docks connected to a remote."""

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


@cli.command()
@pass_devices
def activities(devices):
    """List activities."""

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


@cli.command()
@pass_devices
def ircodes(devices):
    """List IR codesets."""

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


@cli.command()
@pass_devices
def iremitters(devices):
    """List IR emitters."""

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


@cli.command()
@click.option(
    "--emitter",
    envvar="UC_EMITTER",
    help="The IR emitter to send the code from",
)
@click.argument("target")
@click.argument("command")
@pass_devices
def irsend(devices, emitter, target, command):
    """Send IR COMMAND to TARGET.

    TARGET is the name of the device to send the IR code to (e.g. "LG TV")

    COMMAND is the name of the IR command (e.g. "VOLUME_UP")

    Example: irsend "LG TV" VOLUME_DUP
    """

    try:
        devices.send_ircmd(target, command, emitter)
    except NoDefaultEmitterError:
        click.echo("No default emitter found. Use --emitter flag to set one.")
        sys.exit(-1)
    except EmitterNotFoundError as e:
        click.echo(e.message)
        sys.exit(-1)
    except IRCodesetNotFound as e:
        click.echo(e.message)
        sys.exit(-1)


if __name__ == "__main__":
    cli()
