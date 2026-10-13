# Observabilidade, segurança, IaC e aplicações — 0.12.0

Primeiras fatias das etapas4–6. O checkout tem38 ferramentas;18 originais preservadas. Não representa conclusão de todos os serviços/capacidades das28seções.

## Segurança e incidente

security_findings_summary recebe serviços explícitos guardduty/securityhub. Dados limitados à conta autenticada/região, GuardDuty enabled detector e findings não arquivados acima de minimum_severity inteiro0–10 (padrão4), Security Hub ACTIVE/NEW/NOTIFIED. Threshold numérico aplica somente a GuardDuty; não comparar escalas automaticamente. Detalhes/descrições/payloads omitidos. Sem detector, detector desabilitado, finding fora do escopo ou AccessDenied deixam o resultado parcial. Nenhum finding retornado não comprova ambiente seguro, cobertura Organizations ou remediação.

incident_diagnostics requer alarm_prefix. Com include_cloudtrail=true (padrão), informar resource_name e start_time/end_time com offset, janela positiva até24h dentro dos últimos90dias. Consulta snapshots de alarmes Metric/Composite e Event History regional do CloudTrail por ResourceName. Não retorna StateReason, usernames, access keys, requestParameters ou evento bruto. Erros de parse ficam parciais, classificação por evento desconhecida (null). Permissão negada é sinal observado, não identificação da policy que negou. Snapshots e coincidência temporal não comprovam causa raiz. include_cloudtrail=false consulta somente alarmes.

Não executa Logs Insights, Health API, traces ou análise de CloudTrail Lake/data events; essas capacidades permanecem pendentes. Segurança avançada KMS/Inspector/Macie/Config/Control Tower/Organizations posture também não está implementada por estes collectors.

## IaC e deploy

terraform_plan_analysis recebe JSON de terraform show -json, até2MiB e1.000resource_changes; suporta format_version major1. Analisa ações, destroy/replace/forget e sinais específicos de criptografia/public access de recursos AWS. Unknown masks são avaliadas sem tratar unknown como valor conhecido. Retorna índices no array original, tipos e padrões; não retorna addresses/for_each keys, before/after/outputs/valores sensíveis. Não roda Terraform, lê arquivos/state, faz apply ou prova drift live. Campo resource_drift do input é somente contagem fornecida.

cloudformation_health consulta uma stack por nome e recursos: estados/rollback/falhas e drift metadata existente (pode estar stale; timestamp quando disponível). Sem parâmetros/outputs/templates/status reasons/custom physical IDs. Não inicia DetectStackDrift nem rollback; não cobre StackSets.

ecs_service_assessment consulta cluster/service explícitos e task definition associada. Sinais de desired/running, rollout FAILED, privileged/writable-root (Linux). Env values, secret references, events e razões brutas são omitidos. desired0 é observação informativa, não falha automática. Sem task runtime, ELB, ECR scanning ou aceite funcional. Análise de pipelines externos/OIDC e GitLab/GitHub Actions permanece pendente.

## Serverless, dados e IA

serverless_assessment suporta Lambda por nome (configuração/concurrency) e SQS por nome (GetQueueUrl same-account, verificação HTTPS endpoint regional/account e atributos específicos). Não executa Invoke/ReceiveMessage/Send/DeleteMessage nem obtém código. Environment/RedrivePolicy/KMS values omitidos; backlog é aproximado e informativo. Lambda reserved concurrency0 é sinal configurado, não teste de tráfego. API Gateway/EventBridge/Step Functions/Kinesis/SNS permanecem fora deste módulo.

analytics_assessment suporta Glue por JobName. Configuração limitada e até20runs recentes; no JobRuns completos, argumentos, ScriptLocation, erros brutos ou conteúdo de dados. NextToken é reportado como more_runs_available e history_complete=false, sem promessa de histórico completo. Não inicia/reexecuta job. Athena/Redshift/EMR/MSK/Lake Formation/Quick ainda não cobertos.

ai_resource_assessment suporta knowledge_base (ID Bedrock de10caracteres) e sagemaker_endpoint (nome/configuração). Retorna estados e metadados limitados; não retorna failureReasons, prompts, documentos, connection details ou captures. Não invoca modelos, Retrieval, training ou deploy. Metadata não prova permissões/inferência/custos/qualidade de RAG. Agents/AgentCore/Guardrails/model access/serviços AI auxiliares ficam pendentes.

## Segurança, performance e validação

Todas as APIs remotas desta entrega constam na allowlist ReadContext. Auditoria metadata-only, timeouts/retries, limites e EvidenceStore continuam comuns. Novos tools diretos não entram automaticamente em ops_investigate (que aceita organization/cost/network/iam_role); repetir consultas explícitas por conta/região. Local plan review não usa AWS nem persiste input sensível. Não há alteração IAM/infraestrutura/cliente.

Testes offline e MCP stdio validam sucesso/partial/input/escopo/segredos/paginação/API shapes. Nenhuma análise real AWS das novas features realizada nesta entrega; consultas permitidas podem ter custo conforme serviço. Não fixar preços/quotas mutáveis no código.

Fontes oficiais consultadas em13/10/2026:
- https://docs.aws.amazon.com/boto3/latest/reference/services/guardduty/client/get_findings.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/securityhub/client/get_findings.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/cloudtrail/client/lookup_events.html
- https://developer.hashicorp.com/terraform/internals/json-format
- https://docs.aws.amazon.com/boto3/latest/reference/services/lambda/client/get_function_configuration.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/sqs/client/get_queue_attributes.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/glue/client/get_job_runs.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/bedrock-agent/client/get_knowledge_base.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/sagemaker/client/describe_endpoint.html
