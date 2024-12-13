import socket
import threading
import logging
import psutil
import time
import csv
from datetime import datetime, timedelta
import ssl

# Configuração dos logs
logging.basicConfig(
    filename='servidor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

# Nome do arquivo de relatório
RELATORIO_CSV = 'relatorio_servidor.csv'

# Credenciais para autenticação
CREDENCIAIS_VALIDAS = {'usuario': 'senha123'}

# Inicializar o arquivo de relatório
def inicializar_relatorio():
    with open(RELATORIO_CSV, mode='w', newline='', encoding='utf-8') as arquivo:
        escritor = csv.writer(arquivo)
        escritor.writerow(['Timestamp', 'Uso de CPU (%)', 'Uso de Memória (%)', 'Clientes Ativos', 'Última Mensagem'])

# Registrar dados no relatório
def registrar_no_relatorio(cpu, memoria, clientes_ativos, ultima_mensagem="Nenhuma mensagem"):
    """Registra dados no arquivo de relatório CSV com melhor formatação."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if not ultima_mensagem:
        ultima_mensagem = "Nenhuma mensagem"
    with open(RELATORIO_CSV, mode='a', newline='', encoding='utf-8') as arquivo:
        escritor = csv.writer(arquivo, delimiter=';', quoting=csv.QUOTE_MINIMAL)  # Separador ponto e vírgula
        escritor.writerow([timestamp, f"{cpu:.1f}%", f"{memoria:.1f}%", clientes_ativos, ultima_mensagem])


def autenticar_cliente(conn):
    """Autentica o cliente enviando credenciais."""
    conn.sendall(b'Usuario: ')
    usuario = conn.recv(1024).decode().strip()
    conn.sendall(b'Senha: ')
    senha = conn.recv(1024).decode().strip()
    if CREDENCIAIS_VALIDAS.get(usuario) == senha:
        conn.sendall('Autenticado com sucesso!\n'.encode('utf-8'))
        logging.info(f'Cliente {usuario} autenticado.')
        return True
    else:
        conn.sendall('Falha na autenticação.\n'.encode('utf-8'))
        logging.warning(f'Tentativa de autenticação falhou para {usuario}.')
        return False

def handle_client(conn, addr):
    logging.info(f'Conexão estabelecida com {addr}')
    if not autenticar_cliente(conn):
        conn.close()
        return
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                logging.info(f'Conexão encerrada pelo cliente {addr}')
                break
            mensagem_cliente = data.decode()
            logging.info(f'Mensagem recebida de {addr}: {mensagem_cliente}')
            registrar_no_relatorio(psutil.cpu_percent(), psutil.virtual_memory().percent, threading.active_count() - 1, mensagem_cliente)
            mensagem_servidor = input('Você (servidor): ')
            conn.sendall(mensagem_servidor.encode())
            logging.info(f'Mensagem enviada para {addr}: {mensagem_servidor}')
    except ConnectionResetError:
        logging.error(f'Conexão com {addr} foi encerrada abruptamente.')
    except Exception as e:
        logging.error(f'Erro inesperado com {addr}: {e}')
    finally:
        conn.close()
        logging.info(f'Conexão fechada com {addr}')

def monitorar_recursos(intervalo=30):
    """Monitorar e registrar recursos do sistema periodicamente."""
    while True:
        uso_cpu = psutil.cpu_percent(interval=None)
        uso_memoria = psutil.virtual_memory().percent
        clientes_ativos = threading.active_count() - 1
        registrar_no_relatorio(uso_cpu, uso_memoria, clientes_ativos)
        time.sleep(intervalo)

HOST = ''  # Escuta em todas as interfaces de rede disponíveis
PORT = 5000  # Porta para escutar as conexões

servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
servidor.bind((HOST, PORT))
servidor.listen()
logging.info(f'Servidor iniciado e escutando na porta {PORT}...')

# Configurar SSL
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
servidor_ssl = context.wrap_socket(servidor, server_side=True)

# Inicializa o arquivo de relatório
inicializar_relatorio()

# Inicia a thread para monitorar recursos
thread_monitoramento = threading.Thread(target=monitorar_recursos, daemon=True)
thread_monitoramento.start()

try:
    while True:
        conn, addr = servidor_ssl.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        logging.info(f'Clientes ativos: {threading.active_count() - 1}')
except KeyboardInterrupt:
    logging.info('Servidor interrompido pelo usuário.')
finally:
    servidor_ssl.close()
    logging.info('Servidor encerrado.')
