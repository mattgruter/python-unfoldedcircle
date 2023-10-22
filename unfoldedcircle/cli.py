import logging
import sys

import click

from unfoldedcircle.device import (
    Device,
    DeviceGroup,
    discover_devices,
    HTTPError,
    AuthenticationError,
    NoDefaultEmitter,
    EmitterNotFound,
    CodesetNotFound,
    CommandNotFound,
    ApiKeyNotFound,
    AUTH_APIKEY_NAME,
)

VERSION = "0.0.1"

pass_devices = click.make_pass_decorator(DeviceGroup)


def main():
    try:
        cli()
    except HTTPError as err:
        click.echo(f"HTTP Error: {err.message}")
        sys.exit(-1)
    except (AuthenticationError, ApiKeyNotFound) as err:
        click.echo(f"{err.message}")
        sys.exit(-1)
    except NoDefaultEmitter:
        click.echo("No default emitter found. Use --emitter flag to set one.")
        sys.exit(-1)
    except (EmitterNotFound, CodesetNotFound, CommandNotFound) as err:
        click.echo(f"{err.message}")
        sys.exit(-1)


@click.group()
@click.option("--endpoint", envvar="UC_ENDPOINT")
@click.option("-d", "--debug", default=False, count=True)
@click.option("--testing", envvar="UC_TESTING", hidden=True, is_flag=True)
@click.option("--apikey", envvar="UC_APIKEY", type=str)
@click.version_option(
    package_name="python-unfoldedcircle",
    prog_name="unfoldedcircle",
)
@click.pass_context
def cli(ctx, endpoint, debug, testing, apikey):
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
        ctx.obj = DeviceGroup([Device(endpoint, apikey)])


@cli.group()
@pass_devices
def auth(devices):
    """Authenticate with the device."""
    if len(devices) != 1:
        click.echo("Use --endpoint to specify 1 device, multiple discovered.")
        sys.exit(-1)


@auth.command()
@click.option("--pin", envvar="UC_PIN", type=str)
@pass_devices
def auth_login(devices, pin):
    """Create an API key for this library."""
    assert len(devices) == 1
    d = devices[0]
    if d.apikey:
        click.echo("API key already configured.")
        sys.exit(-1)
    if not pin:
        d.pin = click.prompt("PIN", hide_input=True)
    key = d.add_apikey(AUTH_APIKEY_NAME, ["admin"])
    click.echo(f"Use this API key for {d.name}: {key['api_key']}")


@auth.command()
@click.option("--pin", envvar="UC_PIN", type=str)
@pass_devices
def auth_logout(devices, pin):
    """Delete this libraries API key."""
    assert len(devices) == 1
    d = devices[0]
    if not d.apikey:
        if not pin:
            pin = click.prompt("PIN", hide_input=True)
        d.pin = pin
    d.del_apikey(AUTH_APIKEY_NAME)


@auth.command("list")
@pass_devices
def auth_listkeys(devices):
    """List registered API keys."""
    assert len(devices) == 1
    d = devices[0]
    keys = d.fetch_apikeys()
    if not keys:
        click.echo("No API keys found")
        return
    click.echo(f"API keys configured on '{d.info()['device_name']}'")
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
@pass_devices
def auth_addkey(devices, name, scopes):
    """Add an API key with NAME and SCOPES.

    NAME is the name of the API key to add.
    SCOPES is a comma seperated list of auth scopes.

    Example: auth add testkey ir,configuration
    """
    assert len(devices) == 1
    d = devices[0]
    d.add_apikey(name, scopes.split(","))


@auth.command("del")
@click.argument("apikey")
@pass_devices
def auth_delkey(devices, apikey):
    """Delete an API key APIKEY.

    APIKEY is the name of the device to send the IR code to (e.g. "LG TV")

    Example: auth del "1fbcbbd5-06ff-48b4-a7a8-a09c13d07458"
    """
    assert len(devices) == 1
    d = devices[0]
    d.del_apikey(apikey)


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

    devices.send_ircmd(target, command, emitter)
