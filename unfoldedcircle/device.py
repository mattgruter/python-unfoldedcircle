import copy
import logging
import socket
import time
from urllib.parse import urljoin, urlparse

import httpx
import zeroconf

ZEROCONF_TIMEOUT = 3
ZEROCONF_SERVICE_TYPE = "_uc-remote._tcp.local."


class HTTPError(Exception):
    """Raised when an HTTP operation fails.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class LoginError(Exception):
    """Raised when HTTP login fails.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class NoDefaultEmitter(Exception):
    """Raised when default IR emitter can't be inferred."""

    pass


class EmitterNotFound(Exception):
    """Raised when IR emitter with a given name can't be found.

    Attributes:
        name -- name of emitter that wasn't found
        message -- explanation of the error
    """

    def __init__(self, name, message="Emitter not found on device"):
        self.name = name
        self.message = message
        super().__init__(self.message)


class CodesetNotFound(Exception):
    """Raised when IR codeset with a given name can't be found.

    Attributes:
        name -- IR target name that wasn't found
        message -- explanation of the error
    """

    def __init__(self, name, message="IR target name not found in codesets"):
        self.name = name
        self.message = message
        super().__init__(self.message)


class CommandNotFound(Exception):
    """Raised when IR comman with a given name can't be found.

    Attributes:
        name -- IR command name that wasn't found
        message -- explanation of the error
    """

    def __init__(self, name, message="IR command not found in codesets"):
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
            raise NoDefaultEmitter()
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
                    raise NoDefaultEmitter()

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
            raise EmitterNotFound(emitter_name, message=msg)

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
            raise CodesetNotFound(target, message=msg)


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
            msg = f"{r.json()['message']}"
            raise LoginError(msg)
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
                if r.status_code == 404:
                    msg = f"IR command '{command}' not found."
                    raise CommandNotFound(command, message=msg)
                err = r.json()
                msg = f"{r.status_code} {err['code']}: {err['message']}"
                raise HTTPError(msg)


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
