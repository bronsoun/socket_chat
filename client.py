from socket_class import Socket
import asyncio
from datetime import datetime
from os import system
from encryption import DiffieHellman, AESCipher


class Client(Socket):
    def __init__(self):
        super(Client, self).__init__()
        self.client_key = DiffieHellman()
        self.client_pub_key = str(self.client_key.gen_public_key())
        print('----------BEGIN CLIENT PUBLIC KEY----------\n', self.client_pub_key,
              '\n----------END CLIENT PUBLIC KEY----------\n')
        self.client_pvt_key = None
        self.messages = ""

    def set_up(self):
        try:
            self.socket.connect(("127.0.0.1", 2323))
            pub_key = self.client_pub_key
            # ClientHello
            """settings_str = 'TLS_AES_128_SHA256'
            self.socket.send(settings_str.encode('utf-8'))"""
            self.socket.send(pub_key.encode('utf-8'))
            # ServerHello получение ответа сервера в котором содержится его публичный ключ
            server_recv = self.socket.recv(1024)
            # публичный ключ сервера
            server_pub_key = int(server_recv.decode('utf-8'))
            self.server_pub_key = server_pub_key
            print('----------BEGIN SERVER PUBLIC KEY----------\n', server_pub_key,
                  '\n----------END SERVER PUBLIC KEY----------\n')
            # генерация общего ключа
            self.client_pvt_key = self.client_key.gen_shared_key(server_pub_key)
            print('----------BEGIN CLIENT SHARED KEY----------\n', self.client_pvt_key,
                  '\n----------END CLIENT SHARED KEY----------\n')
            # создание шифра по ключу
            self.aes = AESCipher(self.client_pvt_key)
            self.socket.setblocking(False)
        except ConnectionRefusedError:
            print('Сервер недоступен')
            exit(0)

    async def listen_socket(self, listened_socket=None):
        while True:
            data = await self.main_loop.sock_recv(self.socket, 4096)
            key = data.decode('utf-8').partition(':')[2]
            print(key)
            if key != self.client_pub_key:
                self.aes = AESCipher(key)
                # self.encryptor.decrypt(data.decode("utf-8"))
                decrypted_message = self.aes.decrypt(data.decode('utf-8').partition(':')[0])
                print('data', decrypted_message)
            else:
                self.aes = AESCipher(self.client_pvt_key)
                decrypted_message = self.aes.decrypt(data.decode('utf-8').partition(':')[0])
                print('data', decrypted_message)
            if decrypted_message == '':
                self.messages += f"{datetime.now().date()}: {data}\n"
            else:
                self.messages += f"{datetime.now().date()}: {decrypted_message}\n"
            system("clear")
            print(self.messages)

    async def send_data(self, data=None):
        while True:
            # await ждет выполнения функции
            data = await self.main_loop.run_in_executor(None, input, ">")
            # self.encryptor.encrypt(data)
            encrypted_data = self.aes.encrypt(data)
            await self.main_loop.sock_sendall(self.socket, encrypted_data)

    async def main(self):
        await asyncio.gather(
            self.main_loop.create_task(self.listen_socket()),
            self.main_loop.create_task(self.send_data())
        )


if __name__ == '__main__':
    client = Client()
    client.set_up()
    client.start()
