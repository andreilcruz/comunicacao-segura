from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID
from cryptography import x509
from datetime import datetime, timedelta

def gerar_certificados():
    # Gerar a chave privada
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Salvar a chave privada no arquivo 'key.pem'
    with open("key.pem", "wb") as key_file:
        key_file.write(chave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Configurar os detalhes do certificado
    nome = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "São Paulo"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Sua Cidade"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sua Organização"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    # Gerar o certificado
    certificado = (
        x509.CertificateBuilder()
        .subject_name(nome)
        .issuer_name(nome)
        .public_key(chave_privada.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(chave_privada, hashes.SHA256())
    )

    # Salvar o certificado no arquivo 'cert.pem'
    with open("cert.pem", "wb") as cert_file:
        cert_file.write(certificado.public_bytes(serialization.Encoding.PEM))

    print("Certificados gerados com sucesso: 'key.pem' e 'cert.pem'")

# Chamar a função para gerar os certificados
gerar_certificados()
