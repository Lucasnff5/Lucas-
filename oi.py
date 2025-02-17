import os
import random
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import shutil

# Função para gerar a chave a partir da senha
def gerar_chave(senha):
    chave = hashlib.sha256(senha.encode()).digest()
    return chave

# Função para gerar um código de recuperação aleatório
def gerar_codigo_recuperacao():
    return random.randint(10000, 99999)  # Código de 5 dígitos

# Função para gerar senhas aleatórias para as 5 partes
def gerar_senhas_partes():
    return [str(random.randint(100000, 999999)) for _ in range(5)]

# Função para incluir o script no arquivo (com proteção contra manipulação)
def obter_script():
    return '''import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# Função para gerar a chave a partir da senha
def gerar_chave(senha):
    chave = hashlib.sha256(senha.encode()).digest()
    return chave
'''  # Exemplo, você pode adicionar o script completo aqui

# Função para criptografar o arquivo
def criptografar_arquivo(caminho_arquivo, senha):
    if not os.path.isfile(caminho_arquivo):
        print(f"Arquivo não encontrado: {caminho_arquivo}")
        return  # Não criptografar se o arquivo não existir

    chave = gerar_chave(senha)

    # Gerar um código de recuperação
    codigo_recuperacao = gerar_codigo_recuperacao()

    # Criar um IV (vetor de inicialização) aleatório
    iv = os.urandom(16)

    # Obter o script a ser inserido no arquivo
    script_embutido = obter_script()

    # Abrir o arquivo e ler seu conteúdo
    with open(caminho_arquivo, 'rb') as f:
        conteudo_arquivo = f.read()

    # Criação do objeto de criptografia AES em modo CBC
    cipher = AES.new(chave, AES.MODE_CBC, iv)

    # Adicionar padding (preenchimento) ao conteúdo
    conteudo_arquivo_padded = pad(conteudo_arquivo, AES.block_size)

    # Criptografar o conteúdo
    conteudo_arquivo_criptografado = cipher.encrypt(conteudo_arquivo_padded)

    # Calcular o comprimento total dos dados criptografados
    tamanho_criptografado = len(conteudo_arquivo_criptografado)

    # Estrutura do cabeçalho: IV + Código de recuperação + Script embutido
    cabecalho = iv + struct.pack('!I', codigo_recuperacao)  # Código de recuperação como inteiro

    # Sobrescrever o arquivo original com o cabeçalho, o script e o conteúdo criptografado
    with open(caminho_arquivo, 'wb') as f:
        f.write(cabecalho)  # Escrever cabeçalho
        f.write(script_embutido.encode())  # Incluir o script embutido
        f.write(conteudo_arquivo_criptografado)  # Escrever conteúdo criptografado

    print(f"Arquivo criptografado com sucesso: {caminho_arquivo}")
    print(f"Código de recuperação gerado: {codigo_recuperacao}")

# Função para quebrar o arquivo criptografado em 5 partes e criptografar com senhas diferentes
def quebrar_arquivo(caminho_arquivo):
    # Cria 5 partes do arquivo
    with open(caminho_arquivo, 'rb') as f:
        conteudo = f.read()

    tamanho_parte = len(conteudo) // 5
    partes = []
    senhas_partes = gerar_senhas_partes()

    for i in range(5):
        parte_nome = f"{caminho_arquivo}_parte_{i+1}.bin"
        partes.append(parte_nome)
        
        # Criptografar cada parte com uma senha diferente
        chave_parte = gerar_chave(senhas_partes[i])
        iv_parte = os.urandom(16)
        cipher = AES.new(chave_parte, AES.MODE_CBC, iv_parte)
        parte_conteudo_criptografado = cipher.encrypt(pad(conteudo[i * tamanho_parte : (i + 1) * tamanho_parte], AES.block_size))
        
        with open(parte_nome, 'wb') as parte_f:
            parte_f.write(iv_parte)
            parte_f.write(parte_conteudo_criptografado)

    # Cria o arquivo de aviso
    with open("avisovocefalhou.txt", 'w') as aviso_f:
        aviso_f.write("Este arquivo foi quebrado em 5 partes e o original não existe mais. Caso a tentativa de script ou ferramentas de hacker tenha sido usada para pegar as informações, sinto muito, mas não deu certo, pois a segurança de 5 pontas é invencível.")

    print("Arquivo quebrado em 5 partes e aviso gerado.")

    # Apagar o arquivo original após a quebra em partes
    os.remove(caminho_arquivo)
    print(f"Arquivo original '{caminho_arquivo}' removido.")

# Função para descriptografar o arquivo
def descriptografar_arquivo(caminho_arquivo, senha, codigo_recuperacao):
    if not os.path.isfile(caminho_arquivo):
        print(f"Arquivo não encontrado: {caminho_arquivo}")
        return  # Não descriptografar se o arquivo não existir

    chave = gerar_chave(senha)

    # Abrir o arquivo criptografado e ler seu conteúdo
    with open(caminho_arquivo, 'rb') as f:
        iv = f.read(16)  # O primeiro bloco é o IV
        codigo_armazenado_bytes = f.read(4)  # O código de recuperação ocupa 4 bytes
        script_embutido = b"".join([f.read(1) for _ in range(100)])  # Pegando o script embutido (tamanho arbitrário)
        conteudo_arquivo_criptografado = f.read()

        # Verificar se o código de recuperação está no formato esperado
        if len(codigo_armazenado_bytes) != 4:
            print("Erro: Código de recuperação não encontrado no arquivo ou está mal formatado.")
            return

        # O código de recuperação foi armazenado como um inteiro
        codigo_armazenado = struct.unpack('!I', codigo_armazenado_bytes)[0]

    # Verificar se o código fornecido é o mesmo do arquivo
    if codigo_recuperacao != codigo_armazenado:
        print("Código de recuperação incorreto! Iniciando a segurança de 5 partes.")
        quebrar_arquivo(caminho_arquivo)  # Chama a função para quebrar o arquivo
        return

    # Criação do objeto de criptografia AES em modo CBC
    cipher = AES.new(chave, AES.MODE_CBC, iv)

    # Descriptografar o conteúdo
    conteudo_arquivo_descriptografado = unpad(cipher.decrypt(conteudo_arquivo_criptografado), AES.block_size)

    # Sobrescrever o arquivo criptografado com o conteúdo descriptografado
    with open(caminho_arquivo, 'wb') as f:
        f.write(conteudo_arquivo_descriptografado)

    print(f"Arquivo descriptografado com sucesso: {caminho_arquivo}")

# Função principal para escolher criptografar ou descriptografar
def menu():
    senha = input("Digite a senha para criptografar ou descriptografar arquivos: ")

    # Opções
    print("\nEscolha uma opção:")
    print("1. Criptografar um arquivo")
    print("2. Descriptografar um arquivo")
    opcao = input("Digite a opção desejada (1 ou 2): ")

    if opcao == '1':
        # Criptografar
        arquivo = input("Digite o nome e o caminho do arquivo a ser criptografado (ex: E:\\meuarquivo.txt): ")
        criptografar_arquivo(arquivo, senha)

    elif opcao == '2':
        # Descriptografar
        arquivo = input("Digite o nome e o caminho do arquivo criptografado (ex: E:\\meuarquivo.txt): ")
        codigo_recuperacao = int(input("Digite o código de recuperação: "))
        descriptografar_arquivo(arquivo, senha, codigo_recuperacao)

    else:
        print("Opção inválida. Tente novamente.")

# Chamar a função do menu
if __name__ == "__main__":
    print("\nScript criado por Lucas Matheus")  # Adicionando o crédito ao criador
    menu()
