from socket_class import Socket
from encryption import DiffieHellman, AESCipher


class Server(Socket):
    def __init__(self):
        # вызов __init__ родителя
        super(Server, self).__init__()
        self.users = []
        self.server_key = DiffieHellman()
        self.server_pub_key = str(self.server_key.gen_public_key())
        print("Сервер запущен\n\n")
        print('----------BEGIN SERVER PUBLIC KEY----------\n', self.server_pub_key,
              '\n----------END SERVER PUBLIC KEY----------\n')
        self.client_names = {}
        self.client_keys = {}
        self.client_pub_keys = {}

    def set_up(self):
        self.socket.bind(("127.0.0.1", 2323))
        self.socket.listen(5)
        self.socket.setblocking(False)

    async def send_data(self, data=None):
        for user in self.users:
            for key in self.client_keys:
                if key == user:
                    self.aes = AESCipher(self.client_keys[key])
                    send_data = self.aes.encrypt(data).decode('utf-8')+':'+self.client_keys[key]
                    await self.main_loop.sock_sendall(user, send_data.encode('utf-8'))

    async def listen_socket(self, listened_socket=None):
        if not listened_socket:
            return
        while True:
            try:
                data = await self.main_loop.sock_recv(listened_socket, 4096)
                self.aes = AESCipher(self.client_keys[listened_socket])
                print('----------BEGIN CLIENT SHARED KEY----------\n', self.client_keys[listened_socket],
                      '\n----------END CLIENT SHARED KEY----------\n')
                print('MESSAGE:', data.decode('utf-8'), '\nDECRYPT MESSAGE:', self.aes.decrypt(data))
                print('\n----------------------------------------------------'
                      '----------------------------------------------------------\n')
                # формируем сообщение, состоящее из сообщения и
                # конкатенированного общего ключа пользователя, отправившего сообщение
                # в общий чат, но это некорректно тк теряется преимущество перед RSA
                data = self.aes.decrypt(data) # str
                #data = data.decode('utf-8')+':'+self.client_keys[listened_socket]
                await self.send_data(data)

            except ConnectionResetError:
                return


    async def accept_socket(self):
        while True:
            # принимает входящее сообщения асинхронно
            user_socket, address = await self.main_loop.sock_accept(self.socket)
            print('\n-------------------------------------------\n')
            print(f"Пользователь: {address[0]} подключился\n")
            print('-------------------------------------------\n')
            server_pub_key = self.server_pub_key
            client_recv = await self.main_loop.sock_recv(user_socket, 1024)
            user_socket.send(server_pub_key.encode('utf-8'))
            print('----------BEGIN CLIENT PUBLIC KEY----------\n', client_recv.decode('utf-8'),
                  '\n----------END CLIENT PUBLIC KEY----------\n')
            client_pub_key = int(client_recv.decode('utf-8'))
            # генерация общего ключа на сервере
            self.client_pvt_key = self.server_key.gen_shared_key(client_pub_key)
            self.client_keys[user_socket] = self.client_pvt_key
            self.client_pub_keys[user_socket] = client_recv.decode('utf-8')
            self.users.append(user_socket)
            self.main_loop.create_task(self.listen_socket(user_socket))

    async def main(self):
        # выполняет accept_socket на каждой итерации цикла
        await self.main_loop.create_task(self.accept_socket())


if __name__ == '__main__':
    server = Server()
    server.set_up()
    server.start()
