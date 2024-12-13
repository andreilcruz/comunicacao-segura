import socket
import ssl

# Configurações do servidor
HOST = 'localhost'
PORT = 5000

# Configuração SSL
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(cafile='cert.pem')

# Criar o socket com SSL
cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cliente_ssl = context.wrap_socket(cliente, server_hostname=HOST)

try:
    # Conectar ao servidor
    cliente_ssl.connect((HOST, PORT))
    print(cliente_ssl.recv(1024).decode().strip())  # Mensagem inicial do servidor

    # Enviar credenciais para autenticação
    usuario = input("Digite seu usuário: ")
    cliente_ssl.sendall(usuario.encode())
    print(cliente_ssl.recv(1024).decode().strip())
    senha = input("Digite sua senha: ")
    cliente_ssl.sendall(senha.encode())

    # Receber resposta de autenticação
    resposta = cliente_ssl.recv(1024).decode().strip()
    print(f"\n{resposta}\n")

    # Verificar se a autenticação falhou
    if 'Falha' in resposta:
        print("A autenticação falhou. Encerrando a conexão.\n")
        cliente_ssl.close()
        exit()

    # Comunicação com o servidor após autenticação bem-sucedida
    print("Digite suas mensagens abaixo. Use 'sair' para encerrar a conexão.\n")
    while True:
        mensagem = input('Você (cliente): ')
        if mensagem.lower() == 'sair':
            print('\nEncerrando conexão.')
            break
        cliente_ssl.sendall(mensagem.encode())
        resposta_servidor = cliente_ssl.recv(1024).decode().strip()
        print(f"\nServidor: {resposta_servidor}\n")

except Exception as e:
    print(f"\nErro: {e}\n")
finally:
    cliente_ssl.close()
    print("\nConexão encerrada.")
