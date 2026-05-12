🛡️ ThreatIntel Pro
ThreatIntel Pro é uma plataforma avançada de inteligência de ameaças projetada para centralizar a ingestão, análise e visualização de indicadores de comprometimento (IOCs). O projeto foca em automatizar a triagem de artefatos suspeitos, permitindo que analistas de SOC e pesquisadores de segurança processem dados de múltiplas fontes em um único dashboard.

🚀 Funcionalidades Principais
Leitor Multimodal de Ingestão: * URLs: Captura automática de conteúdo, análise de reputação e detecção de phishing.

Arquivos Locais: Suporte para upload e parsing de arquivos (PDF, LOG, TXT, JSON) para extração de padrões maliciosos.

Extração de IOCs: Identificação automática de endereços IP, hashes (MD5, SHA256), domínios e e-mails suspeitos.

Integração com APIs de Segurança: (Ex: VirusTotal, URLScan, AbuseIPDB).

Análise Estática: Extração de metadados de arquivos sem execução (segurança em primeiro lugar).

Dashboard Interativo: Visualização em tempo real do nível de criticidade dos dados analisados.

🛠️ Tech Stack
Backend: Python (FastAPI / SQLModel)

Banco de Dados: PostgreSQL (Migrado para escalabilidade)

Análise de Dados: BeautifulSoup4, PyMuPDF, Pandas

Segurança: Integração com Shodan e rede Tor para anonimização de consultas.

Frontend: [Insira sua tecnologia, ex: React/Streamlit]

📁 Estrutura do Projeto
Bash
├── src/
│   ├── ingestion/       # Módulo de leitura de arquivos e URLs
│   ├── analysis/        # Motores de busca e integração com APIs
│   ├── database/        # Modelagem e migrações (PostgreSQL)
│   └── api/             # Endpoints da aplicação
├── tests/               # Testes unitários e de integração
├── requirements.txt     # Dependências do projeto
└── main.py              # Ponto de entrada


⚙️ Como Instalar e Rodar
Clone o repositório:

Bash
git clone https://github.com/seu-usuario/threat-intel-pro.git
Configure o ambiente virtual:

Bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
.\venv\Scripts\activate  # Windows
Instale as dependências:

Bash
pip install -r requirements.txt
Configure as chaves de API:
Crie um arquivo .env na raiz e adicione suas chaves:

Snippet de código
VT_API_KEY=seu_token_aqui
SHODAN_API_KEY=seu_token_aqui
⚠️ Disclaimer (Aviso Legal)
Este projeto foi desenvolvido para fins estritamente educacionais e de pesquisa em segurança cibernética. O autor não se responsabiliza pelo uso indevido da ferramenta. Sempre analise arquivos suspeitos em ambientes controlados (Sandboxes).

👨‍💻 Autor
Desenvolvido por Gabriel – Estudante de Segurança da Informação.
