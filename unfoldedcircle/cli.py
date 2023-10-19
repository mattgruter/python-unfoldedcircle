import logging
import sys

import click

from device import (
    Device,
    DeviceGroup,
    discover_devices,
    HTTPError,
    LoginError,
    NoDefaultEmitter,
    EmitterNotFound,
    CodesetNotFound,
    CommandNotFound,
)

VERSION = "0.0.1"

pass_devices = click.make_pass_decorator(DeviceGroup)


def main():
    try:
        cli()
    except (HTTPError, LoginError) as err:
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
@click.option("--username", default="web-configurator", hidden=True)
@click.option("--pin", default="1234", type=str)
@click.pass_context
@click.version_option(version=VERSION, prog_name="unfoldedcircle")
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

    devices.send_ircmd(target, command, emitter)
