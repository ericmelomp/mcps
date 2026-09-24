# Validação — 2026-09-24

Ambiente: Windows, Python 3.13.4, MCP SDK 1.30.0, boto3 1.43.101.

Comandos executados:

```text
python -m pytest -q
20 passed in 6.51s

python -m pip check
No broken requirements found.

python scripts/measure_payload.py
synthetic_instances: 1000
normalized_input_bytes: 150000
summary_bytes: 3633
payload_reduction_percent: 97.58
measures_tokens: false
```

Os testes incluem subprocesso MCP real via stdio, descoberta de ferramentas, validação de argumentos e respostas sem configuração AWS. Coleta, autenticação e análise são verificadas com mocks e Stubber, sem rede AWS. O processo isolado é testado com timeout e limite de itens.

O benchmark compara os mesmos dados sintéticos antes e depois da redução. O tamanho do resumo inclui metadados e amostra de 20 instâncias. Não inclui overhead completo do protocolo, schemas, prompts ou consultas posteriores de evidência. Não estima tokens nem custo real.

Limitação: nenhum smoke test em conta AWS real, login SSO real, cliente de IA configurado ou teste de carga multiusuário. O servidor foi projetado para execução local por um usuário.
