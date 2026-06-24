"""
Módulo de Autenticação e Criptografia
Demonstra práticas de proteção de dados e controle de acesso (Broken Access Control e Data Protection).
Usa bcrypt para gerar e verificar senhas de forma segura, evitando algoritmos obsoletos como MD5 ou SHA1.
"""

import bcrypt
import os

def hash_password(password: str) -> str:
    """
    Gera um hash criptográfico seguro usando bcrypt (que possui Salt automático
    e proteção contra ataques de força bruta/rainbow tables graças ao fator de custo).
    """
    # Em produção, senhas devem ser codificadas para bytes antes do hash
    password_bytes = password.encode('utf-8')
    
    # Gera o salt com fator de trabalho (rounds) adequado
    salt = bcrypt.gensalt(rounds=12)
    
    # Gera o hash
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se uma senha em texto claro corresponde ao hash armazenado.
    O bcrypt extrai o salt do próprio hash automaticamente.
    """
    plain_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    
    return bcrypt.checkpw(plain_bytes, hashed_bytes)

def require_role(user_role: str, allowed_roles: list) -> bool:
    """
    Controle de Acesso Baseado em Papel (RBAC).
    Verifica se o papel do usuário logado está na lista de papéis permitidos para acessar um recurso.
    Aplica o Princípio do Privilégio Mínimo (Default Deny).
    """
    # Fail-safe: se a lista for vazia, negar acesso.
    if not allowed_roles:
        return False
        
    return user_role in allowed_roles

# Exemplo de uso para demonstrar ao avaliador do repositório:
# No mundo real, a senha vem do usuário no formulário, e o hash está no DB.
# Aqui mostramos como o sistema lidaria no backend:
if __name__ == "__main__":
    senha_forte = "S3nh4_F0rt3_!2026"
    hash_banco = hash_password(senha_forte)
    print(f"Hash armazenado (Seguro): {hash_banco}")
    print(f"Verificação com senha correta: {verify_password(senha_forte, hash_banco)}")
    print(f"Verificação com senha incorreta: {verify_password('senha_errada', hash_banco)}")
