import socket
import asyncio
import struct
import json


class Socket:
    def __init__(self):
        # AF_INET - тип адресов, SOCK_STREAM - TCP/IP
        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        self.main_loop = asyncio.new_event_loop()

    async def key_exchange(self, public_key):
        await self.main_loop.sock_sendall(self.socket, public_key)
        public_key_rec = await self.main_loop.sock_recv(self.socket, 4096)
        return public_key_rec

    async def send_data(self, **kwargs):
        where = kwargs['where']
        del kwargs['where']

        data = self._encode_data(kwargs)
        meta_data = struct.pack(">I", len(data))
        await self.main_loop.sock_sendall(where, meta_data + data)

    def _encode_data(self, data):
        return json.dumps(data).encode("utf-8")

    def _decode_data(self, data: bytes):
        return json.loads(data).decode("utf-8")

    async def _recv_message(self, listened_socket: socket.socket, message_len):
        message = bytearray()

        while len(message) < message_len:
            packet = await self.main_loop.sock_recv(listened_socket, message_len - len(message))
            if packet is None:
                return None
            # расширят сообщение на пакеты
            message.extend(packet)
        return message

    async def listen_socket(self, listened_socket):
        meta_data = self.main_loop._recv_message(listened_socket, 4)
        # тк tuple, формирует по 4 байта
        meta_data = struct.unpack(">I", meta_data)[0]
        data = await self._recv_message(listened_socket, meta_data)
        return self._decode_data(data)

    async def main(self):
        raise NotImplementedError()

    def start(self):
        self.main_loop.run_until_complete(self.main())

    def set_up(self):
        raise NotImplementedError()
