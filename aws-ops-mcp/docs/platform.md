# Etapa1 — Organizations e custos (0.8.0)

O servidor mantém as18 ferramentas atuais e adiciona organization_summary, cost_summary, ops_investigate e ops_investigation_get. Esta entrega é a primeira etapa da expansão; não cobre automaticamente as28 seções da especificação.

## Organizations

organization_summary(account, region, include_policies=true) consulta organização, contas, roots, OUs e pais. Quando habilitado, coleta metadados das políticas SCP/RCP diretamente anexadas e lista os IDs observados em cada nível de ancestralidade. Retorna estado de conta com State e fallback legado Status; omite emails e conteúdo de políticas. Conta fora de ACTIVE gera finding informativo para revisão de intenção.

Uma lista de políticas anexadas não comprova permissão efetiva. Sem acesso, o campo correspondente é null e o resultado parcial. Tipos de política não habilitados no root são observados sem chamadas redundantes. A conta de gerenciamento não é governada por SCP. Não implementa scp_analyze, RCP applicability por recurso, Control Tower ou compliance de Landing Zone.

## Custos

cost_summary(account, region, start_date, end_date, metric="UnblendedCost", granularity="MONTHLY", organization_scope=false, usage_region="") consulta GetCostAndUsage por SERVICE. Datas YYYY-MM-DD, fim exclusivo, até366dias, fim no máximo a data UTC atual. Métricas aceitas: UnblendedCost, AmortizedCost, NetUnblendedCost, NetAmortizedCost; DAILY ou MONTHLY.

Por padrão, filtro LINKED_ACCOUNT limita à conta autenticada. organization_scope=true retira esse filtro e retorna apenas a visão de cobrança acessível ao caller, que pode ser incompleta por permissões/Billing Views. usage_region é filtro de utilização, não região de autenticação. Nunca somar resultados payer/member sobrepostos. Valores Decimal preservam créditos negativos e moedas separadas; estimated vem da API. Totais só são verificados depois de toda a paginação concluída. Nenhum grupo retornado não comprova gasto zero. Não calcula forecast, economia ou direitos de RI/Savings Plans.

**Cost Explorer cobra consultas por API.** Não há preço fixado no código. Esta ferramenta torna esse efeito explícito; jobs com quatro aliases podem multiplicar consultas. Não roda automaticamente ao iniciar o servidor.

## Múltiplos escopos

ops_investigate(scopes=[{"account":"sandbox","region":"us-east-1"}], analysis="organization") inicia job e retorna investigation_id. analysis="cost" exige start_date/end_date e aceita os filtros da ferramenta de custos. Consultar ops_investigation_get(investigation_id); evidence_get expande evidências de cada escopo.

Até4 aliases distintos,2escopos em paralelo por job,2jobs ativos,20jobs retidos, expiração900s após término. Cada consulta valida identidade/allowlist de regiões e isola sessão/clientes. Os dois módulos iniciais são globais em AWS comercial: uma região de autenticação por alias e endpoint us-east-1; GovCloud/China ficam explicitamente não suportados. Não inventar localização regional para recursos globais. Nenhuma soma monetária entre escopos. Erro de um escopo mantém resultado parcial agregado e evidência dos demais. Jobs não oferecem cancelamento nesta etapa. Jobs EKS permanecem separados.

## Limites, respostas e auditoria

ReadContext permite somente APIs fixas;60s nominais por escopo, até200calls,10páginas/1.000objetos por API;100nós de árvore e1.000grupos de custos. Timeouts/retries Boto3 existentes são reaproveitados; chamada em andamento pode ultrapassar deadline. Resumos seguem schema1.0, account/region/collected_at/coverage/errors existentes, com account_id verificado aditivo. Findings incluem severity/confidence; API sources no cache incluem operação/timestamp/status. Saídas até12KiB; detalhes paginados até24KiB. Truncamento e números de evidências ficam explícitos.

Consultas novas sempre fresh, cache_age_seconds=0. EvidenceStore é snapshot, não cache de queries, e expira em900s. Não ativado cache de coleta para decisões críticas.

Auditoria local opcional: AWS_OPS_AUDIT_FILE com caminho absoluto de arquivo existente ou pai existente, fora do repo, em diretório privado. Grava timestamp, account_id, região de autenticação, serviço/operação, duração e status. Não grava parâmetros, respostas brutas, erros brutos, emails ou credenciais. Sem stdout. Arquivo limitado a5MiB; sem rotação automática. Se habilitada mas indisponível/cheia, resultado parcial e audit_unavailable. STS é verificado antes do acesso; este log cobre APIs dos novos collectors, não substitui CloudTrail nem audita módulos antigos.

## IAM e validação

[Exemplo de permissões](../config/platform-read-policy.example.json) não aplicado. Acesso Organizations depende das permissões/contexto organizacional; habilitação e visibilidade de Cost Explorer são externas ao servidor. Read-only não equivale a consulta gratuita.

Testes offline abrangem protocolo MCP, API shapes, árvore/herança, paginação vazia/cíclica, estados desconhecidos, datas/Decimal, erros sanitizados, limites, auditoria, concorrência/TTL e isolamento. Não foram feitas consultas AWS reais desta etapa nem testes de billing do cliente instalado.

## Fontes oficiais consultadas

- [Organizations ListAccounts/State](https://docs.aws.amazon.com/boto3/latest/reference/services/organizations/client/list_accounts.html)
- [ListPoliciesForTarget](https://docs.aws.amazon.com/boto3/latest/reference/services/organizations/client/list_policies_for_target.html)
- [SCP e escopo da conta de gerenciamento](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Cost Explorer GetCostAndUsage](https://docs.aws.amazon.com/boto3/latest/reference/services/ce/client/get_cost_and_usage.html)

Regras e limites operacionais deste módulo são versionados com o pacote; preços, quotas de serviço e comportamento efetivo precisam de consulta atualizada. A documentação é referência, não instrução executável.
