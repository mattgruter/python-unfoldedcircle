import copy
import logging
import socket
import time
from urllib.parse import urljoin, urlparse

import httpx
import zeroconf

ZEROCONF_TIMEOUT = 3
ZEROCONF_SERVICE_TYPE = "_uc-remote._tcp.local."

AUTH_APIKEY_NAME = "python-unfoldedcircle"
AUTH_USERNAME = "web-configurator"


class HTTPError(Exception):
    """Raised when an HTTP operation fails.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message
        super().__init__(self.message)


class AuthenticationError(Exception):
    """Raised when HTTP login fails.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


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
    """Raised when IR command with a given name can't be found.

    Attributes:
        name -- IR command name that wasn't found
        message -- explanation of the error
    """

    def __init__(self, name, message="IR command not found in codesets"):
        self.name = name
        self.message = message
        super().__init__(self.message)


class ApiKeyNotFound(Exception):
    """Raised when API Key with given name can't be found.

    Attributes:
        name -- Name of the API Key
        message -- explanation of the error
    """

    def __init__(self, name, message="API key name not found"):
        self.name = name
        self.message = message
        super().__init__(self.message)


class DeviceGroup(list):
    def __init__(self, *args):
        super(DeviceGroup, self).__init__(args[0])

    def send_ircmd(self, command, target, emitter=None):
        for d in self:
            try:
                d.send_ircmd(command, target, emitter)
            except EmitterNotFound:
                pass  # try next device
            else:
                return
        else:  # raise EmitterNotFound if no device has it
            msg = f"IR emitter '{emitter}' not found."
            raise EmitterNotFound(emitter, message=msg)


class Device:
    def __init__(self, endpoint, apikey=None, pin=None):
        self.endpoint = endpoint
        p = urlparse(endpoint)
        self.host = p.hostname
        self.port = p.port
        self.apikey = apikey
        self.pin = pin
        self._name = None
        self._fw_version = None
        self._model_name = None
        self._model_number = None
        self._serial_number = None
        self._version = None
        self._sysinfo = None

    @property
    def name(self):
        return self._name or "N/A"

    @property
    def fw_version(self):
        return self._fw_version or "N/A"

    @property
    def model_name(self):
        return self._model_name or "N/A"

    @property
    def model_number(self):
        return self._model_number or "N/A"

    @property
    def serial_number(self):
        return self._serial_number or "N/A"

    def url(self, path=""):
        return urljoin(self.endpoint, path, allow_fragments=True)

    def raise_if_error(self, r):
        if r.is_error:
            msg = f"{r.status_code} {r.json()['code']}: {r.json()['message']}"
            raise HTTPError(r.status_code, msg)

    def login(self, username, pin):
        with httpx.Client() as client:
            body = {"username": username, "password": pin}
            r = client.post(self.url("pub/login"), json=body)
        if r.is_error:
            raise AuthenticationError(f"{r.json()['message']}")
        logging.debug("Login successful")
        return {"id": r.cookies["id"]}

    def client(self):
        if self.apikey:
            logging.debug("Setting bearer token to API key.")
            client = httpx.Client(auth=ApiKeyAuth(self.apikey))
        else:
            client = httpx.Client()
            if self.pin:
                logging.debug("Logging in with provided PIN")
                auth_cookie = self.login(AUTH_USERNAME, self.pin)
                client.cookies.update(auth_cookie)
        return client

    def get_name(self):
        if not self._name:
            self.get_version()
        return self._name

    def get_version(self):
        if not self._version:
            with self.client() as client:
                r = client.get(self.url("pub/version"))
            self.raise_if_error(r)
            self._version = r.json()
            self._name = r.json().get("device_name")
            self._fw_version = r.json().get("os")
        return self._version

    def get_sysinfo(self):
        if not self._sysinfo:
            with self.client() as client:
                r = client.get(self.url("system"))
            self.raise_if_error(r)
            self._sysinfo = r.json()
            self._model_name = r.json().get("model_name")
            self._model_number = r.json().get("model_number")
            self._serial_number = r.json().get("serial_number")
        return self._sysinfo

    def get_apikeys(self):
        with self.client() as client:
            r = client.get(self.url("auth/api_keys"))
        self.raise_if_error(r)
        return r.json()

    def add_apikey(self, key_name, scopes):
        logging.debug(f"Creating API key '{key_name}' with scopes {scopes}")
        body = {"name": key_name, "scopes": scopes}
        with self.client() as client:
            r = client.post(self.url("auth/api_keys"), json=body)
        self.raise_if_error(r)
        return r.json()["api_key"]

    def del_apikey(self, key_name):
        logging.debug(f"Deleting API key '{key_name}'")
        with self.client() as client:
            keys = self.get_apikeys()
            for k in keys:
                if k["name"] == key_name:
                    key_id = k["key_id"]
                    break
            else:
                msg = f"API Key '{key_name}' not found."
                raise ApiKeyNotFound(key_name, message=msg)
            r = client.delete(self.url(f"auth/api_keys/{key_id}"))
        self.raise_if_error(r)

    def get_docks(self):
        with self.client() as client:
            r = client.get(self.url("docks"))
        self.raise_if_error(r)
        return r.json()

    def get_activities(self):
        with self.client() as client:
            r = client.get(self.url("activities"))
        self.raise_if_error(r)
        return r.json()

    def get_remotes(self):
        with self.client() as client:
            r = client.get(self.url("remotes"))
            self.raise_if_error(r)
            self.remotes = r.json()
            for remote in self.remotes:
                r = client.get(self.url(f"remotes/{remote['entity_id']}/ir"))
                self.raise_if_error(r)
                if r:
                    remote["codeset"] = r.json()
        return self.remotes

    def get_emitters(self):
        with self.client() as client:
            r = client.get(self.url("ir/emitters"))
        self.raise_if_error(r)
        return r.json()

    def send_ircode(self, command, target, emitter_name=None):
        """Send IR command to supplied target (i.e. remote name).

        The command is sent via all emitters attached to the device unless
        an emitter is supplied (by name).
        Example: device.send_ircode("VOLUME_UP", "LG TV", "dock1")

        Raises
          - 'CommandNotFound' if the supplied IR command is not recognized.
          - 'CodesetNotFound' if the supplied target is not recognized.
          - 'EmitterNotFound' if a supplied emitter is not recognized.
        """
        with self.client() as client:
            codeset_id = self.find_codeset(target)
            body = {"codeset_id": codeset_id, "cmd_id": command}
            if emitter_name:
                emitter_ids = [self.find_emitter(emitter_name)]
            else:
                emitter_ids = [e["id"] for e in self.get_emitters()]
            for emitter_id in emitter_ids:
                logging.debug("Sending %s on emitter %s", command, emitter_id)
                url = self.url(f"ir/emitters/{emitter_id}/send")
                r = client.put(url=url, json=body)
                if r.is_error and r.status_code == 404:
                    msg = f"IR command '{command}' not found."
                    raise CommandNotFound(command, message=msg)
                else:
                    self.raise_if_error(r)

    def find_codeset(self, target):
        logging.debug(
            "Searching for IR target '%s' on device '%s'", target, self.name
        )
        for r in self.get_remotes():
            if target in r["name"].values():
                logging.debug(
                    "Found IR target '%s' on device '%s': codeset=%s",
                    target,
                    self.name,
                    r["codeset"]["id"],
                )
                return r["codeset"]["id"]
        else:
            msg = f"IR target '{target}' not found."
            raise CodesetNotFound(target, message=msg)

    def find_emitter(self, emitter_name):
        emitters = self.get_emitters()
        for e in emitters:
            if emitter_name == e["name"]:
                logging.debug(
                    "Found IR emitter '%s' with ID '%s' on device '%s'",
                    emitter_name,
                    e["id"],
                    self.get_name(),
                )
                return e["id"]
        else:
            logging.debug(
                "IR emitter '%s' not found on device '%s'",
                emitter_name,
                self.get_name(),
            )
            msg = f"IR emitter '{emitter_name}' not found."
            raise EmitterNotFound(emitter_name, message=msg)


class ApiKeyAuth(httpx.Auth):
    def __init__(self, apikey):
        self.apikey = apikey

    def auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self.apikey}"
        yield request


def discover_devices(apikeys=dict()):
    class DeviceListener:
        def __init__(self):
            self.apikeys = apikeys
            self.devices = []

        def add_service(self, zc, type, name):
            info = zc.get_service_info(type, name)
            host = socket.inet_ntoa(info.addresses[0])
            endpoint = f"http://{host}:{info.port}/api/"
            apikey = apikeys.get(endpoint)
            self.devices.append(Device(endpoint, apikey))

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
