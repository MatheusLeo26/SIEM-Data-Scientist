"""
Módulo de Segurança e Hardening (Boas Práticas de Cibersegurança)
Este script demonstra a implementação de boas práticas de segurança recomendadas,
como configuração de cookies HTTP-Only, cabeçalhos de segurança (CORS/CSP) e 
higienização de dados em Local/Session Storage para aplicações web Python.
"""

import os
from http import cookies

def get_security_headers():
    """
    Retorna os cabeçalhos de segurança recomendados (CORS e CSP)
    para mitigação de ataques XSS, Clickjacking e vazamento de dados.
    """
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://img.icons8.com; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests;"
    )
    
    headers = {
        # Content Security Policy (CSP)
        "Content-Security-Policy": csp_policy,
        # Impedir Sniffing de tipo MIME
        "X-Content-Type-Options": "nosniff",
        # Proteção contra Clickjacking (Frame Busting)
        "X-Frame-Options": "DENY",
        # Proteção contra ataques de cross-site scripting (XSS)
        "X-XSS-Protection": "1; mode=block",
        # Forçar comunicação por canais seguros (HTTPS)
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        # Controle de Referenciador para evitar vazamento de caminhos internos
        "Referrer-Policy": "no-referrer-when-downgrade",
        # Cabeçalhos CORS básicos (restritos em produção)
        "Access-Control-Allow-Origin": os.getenv("ALLOWED_ORIGINS", "https://seu-dominio-producao.vercel.app"),
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    }
    return headers

def create_secure_session_cookie(token_name, token_value, max_age_seconds=3600):
    """
    Gera a string de configuração para um cookie de sessão altamente seguro.
    - HttpOnly: Impede que scripts do lado do cliente (como JS) acessem o cookie (Mitiga XSS).
    - Secure: Garante que o cookie só seja transmitido em conexões HTTPS criptografadas.
    - SameSite=Strict: Protege contra ataques CSRF (Cross-Site Request Forgery).
    """
    cookie = cookies.SimpleCookie()
    cookie[token_name] = token_value
    cookie[token_name]["httponly"] = True
    cookie[token_name]["secure"] = True
    cookie[token_name]["samesite"] = "Strict"
    cookie[token_name]["path"] = "/"
    cookie[token_name]["max-age"] = max_age_seconds
    
    return cookie.output()

def get_session_storage_cleanup_script():
    """
    Retorna uma string contendo um script JavaScript para garantir
    a higienização automática do localStorage/sessionStorage no fechamento da aba.
    """
    js_script = """
    <script>
        // Garante que dados sensíveis não permaneçam no localStorage
        localStorage.clear();
        
        // Configura evento para limpar sessionStorage no descarregamento da aba (unload/close)
        window.addEventListener('beforeunload', function() {
            sessionStorage.clear();
            localStorage.clear();
        });
    </script>
    """
    return js_script
