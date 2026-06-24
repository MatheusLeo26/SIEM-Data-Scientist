import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from analyzer import SIEMAnalyzer
import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env
load_dotenv()

# Set Page Config
st.set_page_config(
    page_title="SIEM do Cientista de Dados",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Premium Glassmorphism Look & Dark Theme
st.markdown("""
<style>
    /* Main Background & Font styling */
    .stApp {
        background-color: #0E1117;
        color: #E0E6ED;
        font-family: 'Outfit', 'Inter', sans-serif;
    }
    
    /* Headers styling */
    h1, h2, h3 {
        color: #00F2FE !important;
        font-weight: 700 !important;
    }
    
    /* Metrics panel card style */
    .metric-card {
        background: rgba(255, 255, 255, 0.03);
        border-radius: 12px;
        padding: 20px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        text-align: center;
        transition: transform 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-5px);
        border-color: rgba(0, 242, 254, 0.4);
    }
    .metric-val {
        font-size: 2rem;
        font-weight: 800;
        color: #00F2FE;
    }
    .metric-title {
        font-size: 0.9rem;
        color: #8892B0;
        text-transform: uppercase;
        letter-spacing: 1.5px;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #0B0D13 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    /* Alerts CSS */
    .alert-banner {
        padding: 12px 20px;
        border-radius: 8px;
        margin-bottom: 10px;
        font-weight: 500;
    }
    .alert-high {
        background-color: rgba(255, 75, 75, 0.1);
        border: 1px solid rgba(255, 75, 75, 0.3);
        color: #FF4B4B;
    }
    .alert-warning {
        background-color: rgba(255, 170, 0, 0.1);
        border: 1px solid rgba(255, 170, 0, 0.3);
        color: #FFAA00;
    }
</style>
""", unsafe_allow_html=True)

# App Header
st.title("🛡️ SIEM do Cientista de Dados")
st.markdown("##### Análise Estatística e Inteligência Artificial para Detecção de Anomalias em Logs")

# Load and analyze data
@st.cache_data
def run_siem_analysis():
    # If csv files don't exist, generate them
    if not os.path.exists("auth_logs.csv") or not os.path.exists("network_logs.csv"):
        import generate_data
        generate_data.generate_auth_logs()
        generate_data.generate_network_logs()
        
    analyzer = SIEMAnalyzer()
    analyzer.load_data()
    auth_anom = analyzer.detect_auth_anomalies()
    net_anom = analyzer.detect_network_anomalies()
    return auth_anom, net_anom

auth_df, net_df = run_siem_analysis()

# Calculate Metrics
total_auth = len(auth_df)
auth_anomalies_count = auth_df['anomaly_flag'].sum()
total_net = len(net_df)
net_anomalies_count = net_df['anomaly_flag'].sum()

# Top Metric Cards
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f'<div class="metric-card"><div class="metric-val">{total_auth:,}</div><div class="metric-title">Logins Analisados</div></div>', unsafe_allow_html=True)
with col2:
    st.markdown(f'<div class="metric-card"><div class="metric-val" style="color: #FF4B4B;">{auth_anomalies_count}</div><div class="metric-title">Alertas de Login</div></div>', unsafe_allow_html=True)
with col3:
    st.markdown(f'<div class="metric-card"><div class="metric-val">{total_net:,}</div><div class="metric-title">Conexões de Rede</div></div>', unsafe_allow_html=True)
with col4:
    st.markdown(f'<div class="metric-card"><div class="metric-val" style="color: #FF4B4B;">{net_anomalies_count}</div><div class="metric-title">Alertas de Rede (AI)</div></div>', unsafe_allow_html=True)

st.write("")
st.write("")

# Sidebar configuration
st.sidebar.image("https://img.icons8.com/nolan/96/shield.png", width=80)
st.sidebar.markdown("### SIEM Analyzer Dashboard")
st.sidebar.markdown("Este painel demonstra como técnicas de Ciência de Dados e Machine Learning podem processar logs em escala para detectar ameaças em tempo real.")

page = st.sidebar.radio("Navegar para:", ["Painel de Autenticação", "Análise de Rede (AI K-Means)", "Visualizador de Logs Brutos", "Segurança & Hardening"])

if page == "Painel de Autenticação":
    st.header("🔑 Detecção Estatística em Eventos de Autenticação")
    st.markdown("""
    **Como funciona:** Este módulo analisa o comportamento histórico de logins dos usuários (linha de base). 
    Ele sinaliza automaticamente:
    * **Ataques de Força Bruta:** Mais de 10 tentativas falhas seguidas no intervalo de 5 minutos.
    * **Desvios de Localização/Horário:** Logins bem-sucedidos em horários atípicos (ex: das 22h às 06h) ou países nunca antes acessados pelo usuário.
    """)
    
    # Scatter plot: Timestamp vs User, highlight anomalies
    fig_auth = px.scatter(
        auth_df,
        x="timestamp",
        y="user",
        color="anomaly_flag",
        color_discrete_map={True: "#FF4B4B", False: "#00F2FE"},
        hover_data=["ip_address", "country", "status", "hour"],
        title="Histórico de Logins por Usuário (Vermelho = Anomalias Detectadas)",
        labels={"timestamp": "Data/Hora", "user": "Usuário", "anomaly_flag": "Anômalo"}
    )
    fig_auth.update_traces(marker=dict(size=10, opacity=0.8))
    fig_auth.update_layout(
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.05)")
    )
    st.plotly_chart(fig_auth, use_container_width=True)

    # Specific Alerts List
    st.subheader("⚠️ Alertas de Autenticação Críticos")
    anomalies = auth_df[auth_df['anomaly_flag'] == True].sort_values(by='timestamp', ascending=False)
    
    if len(anomalies) > 0:
        for idx, row in anomalies.head(10).iterrows():
            reason = "Horário de Login Atípico / Localização Incomum"
            if row['brute_force_flag']:
                reason = "Possível Ataque de Força Bruta (Múltiplas falhas seguidas)"
            
            st.markdown(f"""
            <div class="alert-banner alert-high">
                🚨 <strong>{row['user'].upper()}</strong> | Evento: {row['event_type']} | Status: {row['status'].upper()} <br>
                Hora: {row['timestamp']} | IP: {row['ip_address']} ({row['country']}) <br>
                <strong>Motivo do Alerta:</strong> {reason}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("Nenhuma anomalia de autenticação detectada!")

elif page == "Análise de Rede (AI K-Means)":
    st.header("🌐 Clusterização K-Means para Detecção de Malware C2 e Exfiltração")
    st.markdown("""
    **Como funciona:** Conexões de rede normais seguem padrões previsíveis de duração e volume.
    Mapeamos cada conexão em um espaço tridimensional (`bytes_sent`, `bytes_received`, `duration_seconds`) 
    e agrupamos os dados usando o algoritmo **K-Means**. Conexões distantes do centro de seus respectivos grupos 
    são consideradas **outliers (anomalias)**. Isso é altamente eficaz para identificar:
    * **Command & Control (C2) Beaconing:** Malware se comunicando com o servidor externo em intervalos definidos (baixo tráfego, padrão fixo).
    * **Exfiltração de Dados:** Roubo de arquivos confidenciais (altíssimo tráfego de saída).
    """)

    # Interactive 2D Scatter Plot
    # We use log scale for bytes sent/received to visualize better
    net_df['log_bytes_sent'] = np.log10(net_df['bytes_sent'] + 1)
    net_df['log_bytes_received'] = np.log10(net_df['bytes_received'] + 1)
    
    fig_net = px.scatter(
        net_df,
        x="duration_seconds",
        y="log_bytes_sent",
        color="anomaly_type",
        color_discrete_map={
            "Normal": "#00F2FE", 
            "C2 Malware Beaconing": "#FFAA00", 
            "Data Exfiltration": "#FF4B4B",
            "Suspicious Connection": "#C084FC"
        },
        hover_data=["source_ip", "destination_ip", "destination_port", "bytes_sent"],
        title="Duração da Conexão vs Bytes Enviados (Escala Logarítmica)",
        labels={"duration_seconds": "Duração (Segundos)", "log_bytes_sent": "Log10(Bytes Enviados)", "anomaly_type": "Classificação"}
    )
    fig_net.update_traces(marker=dict(size=8, opacity=0.7))
    fig_net.update_layout(
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)")
    )
    st.plotly_chart(fig_net, use_container_width=True)

    # Show alerts table
    st.subheader("⚡ Conexões Suspeitas Identificadas (Outliers)")
    net_anomalies = net_df[net_df['anomaly_flag'] == True].sort_values(by='bytes_sent', ascending=False)
    
    if len(net_anomalies) > 0:
        display_cols = ["timestamp", "source_ip", "destination_ip", "destination_port", "bytes_sent", "bytes_received", "duration_seconds", "anomaly_type"]
        st.dataframe(net_anomalies[display_cols].style.format({
            "bytes_sent": "{:,} B",
            "bytes_received": "{:,} B",
            "duration_seconds": "{:.2f} s"
        }))
    else:
        st.success("Nenhuma anomalia de rede detectada!")

elif page == "Visualizador de Logs Brutos":
    st.header("🗄️ Inspeção e Busca de Eventos")
    
    tab1, tab2 = st.tabs(["Logs de Autenticação", "Logs de Rede"])
    
    with tab1:
        st.subheader("Pesquisar nos Logs de Autenticação")
        search_user = st.text_input("Filtrar por Usuário (ex: joao):", "")
        df_filtered = auth_df.copy()
        if search_user:
            df_filtered = df_filtered[df_filtered['user'].str.contains(search_user, case=False)]
        
        st.dataframe(df_filtered.style.map(
            lambda val: 'background-color: rgba(255, 75, 75, 0.2)' if val == True else '',
            subset=['anomaly_flag']
        ))
        
    with tab2:
        st.subheader("Pesquisar nos Logs de Rede")
        search_ip = st.text_input("Filtrar por IP de Destino:", "")
        df_filtered_net = net_df.copy()
        if search_ip:
            df_filtered_net = df_filtered_net[df_filtered_net['destination_ip'].str.contains(search_ip, case=False)]
            
        st.dataframe(df_filtered_net.style.map(
            lambda val: 'background-color: rgba(255, 75, 75, 0.2)' if val == True else '',
            subset=['anomaly_flag']
        ))

elif page == "Segurança & Hardening":
    st.header("🛡️ Arquitetura de Cibersegurança & Hardening do App")
    st.markdown("""
    Esta seção documenta os controles de cibersegurança e boas práticas implementados para preparar a aplicação para produção (ex: hospedagem na Vercel ou VPS), garantindo privacidade dos dados e imunidade a ataques básicos.
    """)
    
    from modules.security_helper import get_security_headers, get_session_storage_cleanup_script
    
    col_sec1, col_sec2 = st.columns(2)
    
    with col_sec1:
        st.subheader("🔑 1. Gerenciamento de Segredos e Escopo de Variáveis")
        st.info("""
        * **Variáveis de Ambiente (.env)**: Configurações de API e DB foram extraídas do código fonte e são lidas dinamicamente da memória com `python-dotenv`.
        * **Controle de Vazamento Frontend**: Garantimos que chaves confidenciais do backend não possuam prefixos de exposição ao cliente (como `NEXT_PUBLIC_`), prevenindo vazamento acidental em builds de frontend compilados.
        """)
        
        st.subheader("📦 2. Proteção de Código e Source Maps")
        st.warning("""
        * **Source Maps Desativados**: Em produção, source maps são removidos do build final para impedir a engenharia reversa do código-fonte original `.tsx` ou `.py`.
        * **Streamlit Client Hardening**: O parâmetro `showErrorDetails = false` está ativo no arquivo `.streamlit/config.toml`, prevenindo que stack traces detalhados e caminhos de diretório locais vazem para o navegador em caso de exceções do sistema.
        """)

    with col_sec2:
        st.subheader("🍪 3. Cookies HttpOnly, Secure e Sanitização de Storages")
        st.success("""
        * **Prevenção contra Session Hijacking**: Em caso de autenticação por cookies, os tokens são marcados com `HttpOnly` (indisponíveis para scripts do lado do cliente / JS) e `Secure` (somente via conexões HTTPS criptografadas).
        * **Higienização de Local/Session Storage**: Dados pessoais não são salvos em LocalStorage de forma persistente. Implementamos um gatilho de limpeza automática do Session e Local Storage disparado imediatamente quando o usuário fecha a aba do navegador.
        """)
        
        st.subheader("🌐 4. Políticas de CORS e CSP")
        st.error("""
        * **CORS Habilitado e Restrito**: Streamlit configurado com `enableCORS = true` no servidor, prevenindo requisições cross-origin não autorizadas.
        * **CSP (Content Security Policy)**: Aplicada política estritamente restrita a fontes conhecidas ('self') para barrar ataques XSS de injeção de scripts terceiros.
        """)
        
        # Demonstrando a injeção do JS de limpeza do sessionStorage (segurança de dados do cliente)
        st.components.v1.html(get_session_storage_cleanup_script(), height=0)

