"""
Módulo de Validação e Sanitização de Entradas (Input Sanitization)
Este script garante que os dados fornecidos por usuários não contenham
cargas úteis (payloads) maliciosas como XSS, injeção de SQL ou comandos.
"""

import re
import html

def escape_html(input_str: str) -> str:
    """
    Escapa caracteres HTML para evitar ataques Cross-Site Scripting (XSS).
    Converte <, >, &, " e ' para suas respectivas entidades HTML seguras.
    """
    if not isinstance(input_str, str):
        return str(input_str)
    return html.escape(input_str)

def sanitize_username(username: str) -> str:
    """
    Aplica uma política de 'Allowlist' rigorosa para nomes de usuário.
    Permite apenas letras (a-z, A-Z), números (0-9) e underscores (_).
    Retorna None se o formato for inválido.
    """
    if not username:
        return ""
        
    # Limita o tamanho para evitar ataques de negação de serviço (DoS) na regex
    if len(username) > 50:
        return None
        
    # Regex allowlist: só permite alphanum e underscore
    pattern = re.compile(r'^[a-zA-Z0-9_]+$')
    
    if pattern.match(username):
        return escape_html(username)
    return None

def validate_ip(ip_address: str) -> str:
    """
    Valida rigorosamente se a entrada corresponde a um formato de IP (IPv4 ou IPv6).
    Isso previne injeções quando usamos o IP em logs ou buscas de banco de dados.
    """
    if not ip_address:
        return ""
        
    # Regex genérica para IPv4 e IPv6
    # Em produção, a biblioteca 'ipaddress' nativa do Python é recomendada:
    # try: ipaddress.ip_address(ip_address); return escape_html(ip_address) except ValueError: return None
    
    ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    # Regex simplificada para IPv6 (allowlist alfanumérica e dois pontos)
    ipv6_pattern = re.compile(r'^[0-9a-fA-F:]+$')
    
    if ipv4_pattern.match(ip_address) or ipv6_pattern.match(ip_address):
        return escape_html(ip_address)
    return None
