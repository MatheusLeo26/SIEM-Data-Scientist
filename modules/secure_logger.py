"""
Módulo de Monitoramento e Logs Seguros (Logging & Monitoring)
Centraliza o registro de auditoria, garantindo que exceções técnicas e ações do
usuário sejam salvas no servidor, mas ocultando proativamente dados sensíveis
como senhas e tokens (Data Masking).
"""

import logging
import re
import sys
import os

class SensitiveDataFilter(logging.Filter):
    """
    Filtro de log que intercepta as mensagens antes de serem gravadas
    e aplica expressões regulares para mascarar dados sensíveis.
    """
    def filter(self, record):
        # Expressões regulares para encontrar padrões sensíveis
        patterns_to_mask = {
            r'(?i)(senha|password|passwd)[\s:=]+[\'"]?([^\s\'",\]\}]+)[\'"]?': r'\1=***MASCARADO***',
            r'(?i)(token|bearer)[\s:=]+[\'"]?([a-zA-Z0-9\-\._~+]+)[\'"]?': r'\1=***MASCARADO***',
            # Simulação de máscara para cartões de crédito (Regex simples)
            r'(?i)(cartao|card)[\s:=]+[\'"]?\d{13,19}[\'"]?': r'\1=***MASCARADO***'
        }
        
        # Mascara a mensagem do log
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern, replacement in patterns_to_mask.items():
                msg = re.sub(pattern, replacement, msg)
            record.msg = msg
            
        # Também mascara os argumentos (args), se existirem e forem strings
        if record.args:
            new_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    for pattern, replacement in patterns_to_mask.items():
                        arg = re.sub(pattern, replacement, arg)
                new_args.append(arg)
            record.args = tuple(new_args)
            
        return True

def setup_secure_logger(name="siem_logger", log_file="server_audit.log"):
    """
    Configura e retorna uma instância do logger.
    - Grava em arquivo (para auditoria futura).
    - Usa o filtro SensitiveDataFilter.
    - Formato inclui Timestamp, Nível e Mensagem.
    """
    logger = logging.getLogger(name)
    
    # Se o logger já tiver handlers (ex: em hot reload do Streamlit), não duplica
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Formato de log seguro e rastreável
        formatter = logging.Formatter(
            '%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler para escrever no arquivo local
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        
        # Handler para saída no console (apenas para ambiente de dev)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        
        # Adiciona o filtro de proteção contra vazamentos
        sensitive_filter = SensitiveDataFilter()
        file_handler.addFilter(sensitive_filter)
        stream_handler.addFilter(sensitive_filter)
        
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)
        
    return logger

# Instância global para ser importada
secure_log = setup_secure_logger()
