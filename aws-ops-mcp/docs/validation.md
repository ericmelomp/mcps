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

### 2026-09-28 — Extensão EKS com bastion SSM

- Resultado: 60 testes offline aprovados em 7,24 segundos, incluindo os 30 testes anteriores e a integração de nove ferramentas no protocolo MCP stdio.
- Cenários EKS: isolamento de credenciais/profile, identidade local e remota, operações permitidas, paginação, falhas parciais, kubeconfig temporário, normalização sem env/Secrets, workloads, correlações, limites de stdout SSM, logs com redação, cancelamento sem falsa confirmação, submissão ambígua, múltiplos clusters, capacidade/TTL e modelos de parâmetros botocore.
- Dependências: pip check retornou "No broken requirements found".
- Empacotamento: wheel aws_ops_mcp-0.2.0-py3-none-any.whl construído com sucesso. A tentativa sem isolamento identificou setuptools ausente no ambiente; o build isolado instalou suas dependências de build e concluiu, sem alterar dependências de runtime.
- Smoke test do wheel extraído fora do checkout: sessão MCP stdio iniciada, nove ferramentas descobertas, capabilities anunciou EKS e receita remota compilou. Nenhuma chamada AWS.
- Revisão: git diff --check sem erros. Exemplos e instruções em docs/eks.md, config/eks-bastions.example.json, config/eks-diagnostics-policy.example.json e config/eks-rbac.example.yaml.
- Limites: não foi realizada execução real de AWS CLI, SSM ou kubectl contra contas/clusters. Testes usam dados sintéticos. Nenhuma configuração ativa, IAM, RBAC, infraestrutura ou cliente MCP foi alterado.
- Publicação: sem commit/push; cliente uvx fixado no GitHub permanece na versão previamente instalada. Wheel de validação permanece em dist/, ignorado pelo Git.

### 2026-09-28 — Validação real EKS/SSM e correções

- Autorização: usuário forneceu credenciais temporárias para teste direto e pediu continuidade. Importação efetuada via stdin com identidade STS validada; valores e configuração operacional permanecem fora do Git.
- Executado: descoberta AWS, mapeamento de bastion Linux Online na VPC do alvo e investigação pelo servidor MCP local real, via stdio. Evidências operacionais e relatório foram salvos fora do repositório, em ~/.aws/aws-ops-mcp/reports.
- Primeiro incidente: uma submissão SSM teve retorno local não confirmado. O coletor parou sem repetir o comando. Consulta posterior ao histórico SSM confirmou execução e término; uma receita seguinte funcionou. Não foi atribuída uma causa específica sem evidência.
- Falha reproduzida: EndpointSlice com endpoints nulos causava erro de normalização. Correção: tratar a coleção nula como vazia, incluindo condições opcionais dos endpoints. Adicionado teste de regressão.
- Limitação reproduzida: truncamento de evidências impedia correlações completas. Correção: compressão zlib/base64 antes do limite SSM, descompressão limitada a 4 MiB e paginação entre chamadas SSM. Páginas grandes são reduzidas e repetidas no mesmo resourceVersion; mudança de snapshot ou falha posterior preserva os dados anteriores como parciais.
- Resultado final real: coleta AWS/Kubernetes e correlações concluídas sem lacunas, sem coleções de evidências truncadas e sem comandos remotos com término pendente. Resultado operacional degraded por achados reais; execução do MCP concluída. Truncamento do resumo não significa perda das evidências paginadas.
- Verificação local: 66 testes aprovados em 9,60 segundos, incluindo protocolo MCP stdio, endpoints nulos, transporte comprimido, rejeição de descompressão excessiva, adaptação de páginas, preservação de resultados e consistência do snapshot. Wheel 0.2.0 reconstruído.
- Limites: validação real restrita a um cluster autorizado. Nenhuma remediação, alteração IAM/RBAC ou de workloads; logs de aplicação não foram coletados. O acesso remoto executou receitas fixas e arquivos temporários conforme documentado. Identificadores e achados do cliente não foram adicionados ao repositório.
- Pendente: publicação e atualização do cliente fixado no GitHub. Sem commit/push.

## 2026-09-29 — CloudFront e ELB, versão local 0.3.0

- 86 testes offline aprovados (18,53 s), incluindo requisitos gRPC, seleção ordenada de behavior, paginação, caminho ambíguo, origem sem cobertura, falhas de identidade/acesso/deadline, ALB/NLB, redação de secrets e descoberta MCP.
- `pip check`: dependências consistentes. `git diff --check`: aprovado.
- Wheel 0.3.0 gerado com `pip wheel --no-deps --wheel-dir dist .`. A tentativa inicial sem isolamento não encontrou setuptools no ambiente virtual; build isolado concluiu.
- Sessão MCP stdio com wheel no PYTHONPATH e cwd fora do checkout descobriu as 11 ferramentas e executou cloudfront_grpc_inspect. Autenticação expirada impediu coleta AWS; não houve validação de configuração real de CloudFront/ELB.
- Cliente publicado/fixado no GitHub permanece separado desta validação local. Sem publicação ou atualização automática.

## 2026-10-01 — Security 0.4.0

107 testes offline aprovados, incluindo descoberta das 14 ferramentas por stdio e chamadas das novas ferramentas sem configuração, com erro estruturado. Dependências verificadas por pip check. Wheel construído com isolamento de build e iniciado via uvx, com 14 ferramentas e capabilities consistente.

Validação operacional pela MCP das três ferramentas concluída com acesso autorizado: inspeção WAF, correlação de dois Request IDs em S3 e consulta NAT/EIP. Sem alterações de infraestrutura. Evidências operacionais permanecem externas ao Git. Backend CloudWatch validado somente com respostas simuladas; sem teste real nesta sessão.
