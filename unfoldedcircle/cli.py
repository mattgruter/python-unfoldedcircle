import logging
import sys

import click

from unfoldedcircle.device import (
    AUTH_APIKEY_NAME,
    ApiKeyNotFound,
    AuthenticationError,
    CodesetNotFound,
    CommandNotFound,
    Device,
    DeviceGroup,
    EmitterNotFound,
    HTTPError,
    discover_devices,
)

VERSION = "0.0.1"


class Credentials:
    def __init__(self, keyfile):
        self.keyfile = keyfile
        self.apikeys = dict()

    def read_keyfile(self):
        apikeys = dict()
        try:
            with open(self.keyfile, "r") as f:
                for line in f:
                    endpoint, apikey = line.split(";")
                    apikey = apikey.strip()
                    apikeys[endpoint] = apikey
        except FileNotFoundError:
            apikeys = dict()
        self.apikeys = apikeys
        return apikeys

    def write_keyfile(self):
        with open(self.keyfile, "w") as f:
            for endpoint, key in self.apikeys.items():
                f.write(f"{endpoint};{key}\n")

    def add_endpoint(self, endpoint, key):
        self.read_keyfile()
        self.apikeys.update({endpoint: key})
        self.write_keyfile()

    def delete_endpoint(self, endpoint):
        self.read_keyfile()
        if endpoint in self.read_keyfile():
            del self.apikeys[endpoint]
            self.write_keyfile()


class AppContext:
    def __init__(self, credentials, devices):
        self.credentials = credentials
        self.devices = devices


pass_app_context = click.make_pass_decorator(AppContext)


def main():
    try:
        cli()
    except HTTPError as err:
        click.echo(f"HTTP Error: {err.message}")
        sys.exit(-1)
    except (AuthenticationError, ApiKeyNotFound) as err:
        click.echo(f"{err.message}")
        sys.exit(-1)
    except (EmitterNotFound, CodesetNotFound, CommandNotFound) as err:
        click.echo(f"{err.message}")
        sys.exit(-1)


@click.group()
@click.option("--endpoint", envvar="UC_ENDPOINT")
@click.option(
    "-k",
    "--keyfile",
    envvar="UC_KEYFILE",
    default="./.credentials",
    type=click.Path(),
)
@click.option("--apikey", envvar="UC_APIKEY", type=str)
@click.option("-d", "--debug", default=False, count=True)
@click.option("--testing", envvar="UC_TESTING", hidden=True, is_flag=True)
@click.version_option(
    package_name="python-unfoldedcircle",
    prog_name="unfoldedcircle",
)
@click.pass_context
def cli(ctx, endpoint, keyfile, apikey, debug, testing):
    lvl = logging.WARN
    if debug:
        lvl = logging.DEBUG
        click.echo("Setting debug level to %s" % debug)
    logging.basicConfig(level=lvl)

    # credentials
    credentials = Credentials(keyfile)
    if apikey:
        apikeys = {endpoint: apikey}
    if not apikey:
        apikeys = credentials.read_keyfile()

    # devices
    if testing:
        click.echo("-- Testing mode --")
        endpoint = "http://localhost:8080/api/"
    if not endpoint:
        logging.debug("Auto-discoverying devices")
        devices = discover_devices(apikeys)
    else:
        logging.debug("Using endpoint %s", endpoint)
        apikey = apikeys.get(endpoint)
        devices = DeviceGroup([Device(endpoint, apikey)])

    ctx.obj = AppContext(credentials, devices)


@cli.group()
@pass_app_context
def auth(app):
    """Authenticate with the device."""
    if len(app.devices) != 1:
        click.echo("Use --endpoint to specify 1 device, multiple discovered.")
        sys.exit(-1)


@auth.command("login")
@click.option("--pin", envvar="UC_PIN", type=str)
@pass_app_context
def auth_login(app, pin):
    """Create an API key for this library."""
    assert len(app.devices) == 1
    d = app.devices[0]
    d.apikey = None
    if not pin:
        d.pin = click.prompt("PIN", hide_input=True)
    key = d.add_apikey(AUTH_APIKEY_NAME, ["admin"])
    app.credentials.add_endpoint(d.endpoint, key)
    click.echo(f"New API key for '{d.endpoint}': {key}")


@auth.command("logout")
@click.option("--pin", envvar="UC_PIN", type=str)
@pass_app_context
def auth_logout(app, pin):
    """Delete this libraries API key."""
    assert len(app.devices) == 1
    d = app.devices[0]
    if not d.apikey:
        click.echo("Not logged in")
        sys.exit(-1)
    app.credentials.delete_endpoint(d.endpoint)
    if not d.apikey:
        if not pin:
            pin = click.prompt("PIN", hide_input=True)
        d.pin = pin
    d.del_apikey(AUTH_APIKEY_NAME)
    click.echo(f"API key for '{d.endpoint}' removed")


@auth.command("list")
@pass_app_context
def auth_listkeys(app):
    """List registered API keys."""
    assert len(app.devices) == 1
    d = app.devices[0]
    keys = d.get_apikeys()
    if not keys:
        click.echo("No API keys found")
        return
    click.echo(f"API keys configured on '{d.get_name()}'")
    fields = {
        "id": "key_id",
        "name": "name",
        "prefix": "prefix",
        "scopes": "scopes",
        "active": "active",
        "created": "creation_date",
    }
    for key in keys:
        click.echo(f"- name: '{key['name']}'")
        for field, k in fields.items():
            click.echo(f"    {field : <8}{key[k]}")
        click.echo()


@auth.command("add")
@click.argument("name")
@click.argument("scopes")
@pass_app_context
def auth_addkey(app, name, scopes):
    """Add an API key with NAME and SCOPES.

    NAME is the name of the API key to add.
    SCOPES is a comma seperated list of auth scopes.

    Example: auth add testkey ir,configuration
    """
    assert len(app.devices) == 1
    d = app.devices[0]
    d.add_apikey(name, scopes.split(","))


@auth.command("del")
@click.argument("apikey")
@pass_app_context
def auth_delkey(app, apikey):
    """Delete an API key APIKEY.

    APIKEY is the name of the API Key to delete.

    Example: auth del mykey
    """
    assert len(app.devices) == 1
    d = app.devices[0]
    d.del_apikey(apikey)


@cli.command()
@pass_app_context
def version(app):
    """Print device version."""

    for d in app.devices:
        ver = d.get_version()
        click.echo(f"Remote: '{d.get_name()}'")
        click.echo(f"  endpoint: {d.endpoint}")
        click.echo(f"  version: {ver['os']}")
        click.echo(f"  api: {ver['api']}")
        click.echo(f"  core: {ver['core']}")


@cli.command()
@pass_app_context
def info(app):
    """Print device information."""

    for d in app.devices:
        sysinfo = d.get_sysinfo()
        click.echo(f"Remote: '{d.get_name()}'")
        click.echo(f"  endpoint: {d.endpoint}")
        click.echo(f"  model: {sysinfo['model_name']}")
        click.echo(f"  model number: {sysinfo['model_number']}")
        click.echo(f"  serial number: {sysinfo['serial_number']}")


@cli.command()
@pass_app_context
def discover(app):
    """Discover supported devices."""

    if not app.devices:
        click.echo("No devices discovered.")
        sys.exit(-1)
    else:
        click.echo("Discovered devices:")
        for d in app.devices:
            click.echo(f"- {d.get_name()} ({d.endpoint})")


@cli.command()
@pass_app_context
def docks(app):
    """List docks connected to a remote."""

    for d in app.devices:
        docks = d.get_docks()
        if not docks:
            click.echo("No docks found")
            return
        click.echo(f"Docks connected to '{d.get_name()}'")
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
@pass_app_context
def activities(app):
    """List activities."""

    for d in app.devices:
        activities = d.get_activities()
        if not activities:
            click.echo("No activities found")
            return
        click.echo(f"Activities configured on '{d.get_name()}'")
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
@pass_app_context
def ircodes(app):
    """List IR codesets."""

    for d in app.devices:
        remotes = d.get_remotes()
        if not remotes:
            click.echo("No IR codesets found")
            return
        click.echo(f"IR codesets configured on '{d.get_name()}")
        for r in remotes:
            click.echo(f"- name: '{r['name']['en']}'")
            click.echo(f"    id      {r['entity_id']}")
            click.echo(f"    codeset {r['codeset']['id']}")
            for code in r["codeset"]["codes"]:
                click.echo(f"      - {code['cmd_id']}")


@cli.command()
@pass_app_context
def iremitters(app):
    """List IR emitters."""

    for d in app.devices:
        emitters = d.get_emitters()
        if not emitters:
            click.echo("No IR emitters found")
            return
        click.echo(f"IR emitters available on '{d.get_name()}")
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
@click.argument("command")
@click.argument("target")
@pass_app_context
def irsend(app, emitter, command, target):
    """Send IR COMMAND to TARGET.

    COMMAND is the name of the IR command (e.g. "VOLUME_UP")

    TARGET is the name of the device to send the IR code to (e.g. "LG TV")

    Example: irsend "LG TV" VOLUME_DUP
    """

    app.devices.send_ircmd(command, target, emitter)
