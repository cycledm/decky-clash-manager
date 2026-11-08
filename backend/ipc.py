# SPDX-License-Identifier: GPL-3.0-or-later
"""Small bounded RPC protocol for inherited local socket pairs."""

import json
import socket
import threading

MAX_MESSAGE = 256 * 1024


class OperationError(Exception):
    """A fixed, displayable failure message that contains no user data."""


class Channel:
    def __init__(self, connection):
        self.connection = connection
        self.reader = connection.makefile("rb")
        self.lock = threading.Lock()

    def receive(self):
        line = self.reader.readline(MAX_MESSAGE + 1)
        if not line:
            raise EOFError
        if len(line) > MAX_MESSAGE or not line.endswith(b"\n"):
            raise ValueError("Invalid IPC frame")
        return json.loads(line)

    def send(self, value):
        data = json.dumps(value, ensure_ascii=True, allow_nan=False).encode() + b"\n"
        if len(data) > MAX_MESSAGE:
            raise ValueError("IPC frame is too large")
        self.connection.sendall(data)

    def request(self, method, *args):
        with self.lock:
            self.send([method, list(args)])
            response = self.receive()
        if "error" in response:
            raise OperationError(response["error"])
        return response["result"]

    def close(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.reader.close()
        self.connection.close()


def serve(channel, methods, known_errors=(OperationError,)):
    try:
        while True:
            request = channel.receive()
            try:
                method, args = request
                result = methods[method](*args)
                response = {"result": result}
            except known_errors as error:
                response = {"error": str(error)}
            except Exception:
                response = {"error": "The operation failed internally."}
            channel.send(response)
    except (OSError, EOFError, ValueError):
        pass
    finally:
        channel.close()
