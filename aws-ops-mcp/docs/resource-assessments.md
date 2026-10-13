# Avaliações direcionadas — 0.10.0

Entrega inicial de compute, bancos, storage e backup. São30 ferramentas no checkout; versões anteriores preservadas. Esta entrega não conclui todos os serviços listados na especificação.

## compute_assessment

Requer1–5instance_ids, conta/região explícitas. Observa IMDS, presença de IP público e volumes EBS associados/criptografia. include_metrics=false por padrão; quando true, consulta GetMetricData para CPU Average/Maximum e NetworkIn/Out Sum, período1h, janela24–336h. Valores têm timestamps/contagens/status e lacunas por série. Não há agente de memória, direitos de idle, sizing de família, ASG ou Compute Optimizer. Nenhum comando guest ou user data é lido/retornado.

## database_assessment

Requer database_kind e resource_name. Suporta instância RDS, cluster Aurora, tabela DynamoDB (inclui PITR) e replication group ElastiCache. Retorna metadados de disponibilidade, criptografia, backups e exposição configurada. Single-AZ/single-instance é informativo e depende dos requisitos. PubliclyAccessible não comprova alcance pela internet. Ausência de SSEDescription em DynamoDB não significa ausência de criptografia. Não retorna MasterUsername, passwords ou connection strings. Sem SQL, métricas de bancos, testes de failover/restore, DocumentDB/Neptune/Redshift/MemoryDB.

## s3_assessment

Bucket explícito e ExpectedBucketOwner da conta autenticada. Região é conferida antes das demais configurações. Consulta defaults de criptografia, versioning, flags de public access block, classificação pública de política e contagens de lifecycle. Nenhum objeto, ACL ou documento bruto de policy é retornado. NoSuchBucketPolicy/Lifecycle/PublicAccessBlock são configurações ausentes, não AccessDenied. AccessDenied permanece parcial. Bucket/account/org controles e ACLs interagem: este módulo não afirma acesso público efetivo. Default SSE não comprova criptografia dos objetos existentes nem economia em lifecycle.

## backup_assessment

ARN regional/same-account explícito; maximum_age_hours define limiar de revisão, padrão24h, não um RPO presumido. Recovery points e status/CreationDate vêm de ListRecoveryPointsByResource. COMPLETED permite calcular idade da criação mais recente; nunca comprova restore/RTO/RPO. AVAILABLE/continuous points não são promovidos silenciosamente a COMPLETED. Nenhum completed observado significa apenas falta dessa evidência no escopo, não ausência de backup em todos os sistemas. Não inclui avaliação de vault policies, retenção compliance ou backups externos; ARNs globais sem account ID (como buckets S3) ficam fora deste contrato inicial.

As novas análises usam ReadContext/allowlist, fontes, erros parciais, auditoria opt-in e snapshots compartilhados. Tools são diretas; ops_investigate ainda cobre apenas organization/cost/network/iam_role. Para outros recursos, repetir explicitamente por conta/região; não prometer fanout que não existe.

Consultas CloudWatch têm custos possíveis conforme API; nenhuma consulta real foi feita nesta implementação. IAM de exemplo apenas preparado, nunca aplicado.

Fontes oficiais consultadas em13/10/2026:
- https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_instances.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/cloudwatch/client/get_metric_data.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/rds/client/describe_db_instances.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_encryption.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/backup/client/list_recovery_points_by_resource.html

Limites operacionais são versionados; nenhum preço, quota AWS ou conclusão de performance é fixado como verdade atual.
