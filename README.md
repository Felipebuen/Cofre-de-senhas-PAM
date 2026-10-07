# Cofre de Senhas PAM

Aplicação web local para armazenar e organizar credenciais. O projeto combina uma API Flask com uma interface responsiva e um arquivo JSON para persistência dos dados cifrados.

## Funcionalidades

- Criar perfis independentes, cada um protegido por sua própria senha mestra.
- Armazenar, pesquisar, editar e remover credenciais dentro do perfil autenticado.
- Gerar senhas aleatórias e avaliar a força de senhas.
- Exibir estatísticas por perfil e permitir trocar a senha mestra desse perfil.
- Usar a interface em computadores e celulares.
- Migrar automaticamente o formato antigo de perfil único para o formato com perfis quando o cofre legado é aberto.

## Requisitos

- Python 3.10 ou superior.
- pip.

As dependências estão listadas em `requirements(1).txt`. O pacote `argon2-cffi` habilita Argon2id; quando indisponível, o projeto usa PBKDF2-HMAC-SHA256.

## Instalação e execução

No PowerShell, na pasta do projeto:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r "requirements(1).txt"
python app.py
```

Abra `http://127.0.0.1:5000` no navegador. O servidor está vinculado a `127.0.0.1` e não deve ser tratado como uma instalação pronta para acesso pela rede ou produção.

## Primeiro acesso e perfis

No primeiro acesso, crie o cofre informando o nome do primeiro perfil e uma senha mestra com pelo menos 8 caracteres. Depois de entrar, a área **Configurações** permite criar outros perfis. Cada perfil recebe seu próprio salt, verificador, chave derivada e lista de credenciais. A senha mestra de um perfil não abre os demais.

Para entrar, selecione o perfil e informe a senha mestra correspondente. Trocar a senha mestra em Configurações re-cifra as credenciais apenas do perfil atual.

O cadastro de novos perfis requer que alguém já autenticado autorize a operação. Os perfis não têm papéis administrativos diferentes: qualquer pessoa autenticada pode criar outro perfil.

## Como os dados são protegidos

- Os campos sensíveis de cada credencial são cifrados com AES-256-GCM.
- A chave de 256 bits é derivada da senha mestra com Argon2id (3 iterações, 64 MiB, paralelismo 2) ou, como fallback, PBKDF2-HMAC-SHA256 (600.000 iterações).
- Cada perfil usa um salt aleatório de 256 bits. Cada credencial recebe um nonce aleatório próprio para AES-GCM.
- O arquivo `data/vault.json` armazena salts, verificadores e credenciais cifradas; ele não armazena as senhas mestras nem as chaves derivadas.
- O formato antigo de perfil único é migrado para o perfil `Principal` sem decifrar/re-cifrar as credenciais existentes.

**Metadados visíveis:** títulos e categorias das credenciais ficam em texto claro para permitir listagem e busca. Nomes de perfis também ficam visíveis. Usuários com acesso ao arquivo podem ver esses metadados, mesmo sem conseguir decifrar as senhas e os demais campos protegidos.

## Arquivos principais

- `app.py`: servidor Flask e endpoints REST.
- `backend/crypto.py`: derivação de chaves, cifragem, geração e avaliação de senhas.
- `backend/vault.py`: persistência, autenticação de perfis e operações de credenciais.
- `frontend/templates/index.html`: interface web responsiva.
- `data/vault.json`: armazenamento local criado pelo aplicativo.

## Cuidados

- Faça cópias de segurança de `data/vault.json` com o servidor parado e mantenha-as em local protegido. Perder a senha mestra significa perder o acesso às credenciais daquele perfil.
- Não compartilhe o arquivo do cofre nem backups sem protegê-los. Os metadados descritos acima continuam legíveis.
- O Flask usa a chave de sessão gerada em memória a cada inicialização. Reiniciar o servidor invalida as sessões existentes, mas não altera as credenciais persistidas.
- O servidor de desenvolvimento do Flask não é apropriado para exposição pública. Uma implantação compartilhada exige, no mínimo, configuração de segredo persistente, HTTPS, controles contra tentativas repetidas, proteção CSRF e um servidor de produção.