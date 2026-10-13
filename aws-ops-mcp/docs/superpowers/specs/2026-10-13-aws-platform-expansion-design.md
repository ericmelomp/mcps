# AWS Ops MCP — expansão modular proposta

Status: desenho aprovado; etapa1 e primeiras fatias das etapas2–6 implementadas localmente em0.12.0. Cobertura detalhada em docs/capability-coverage.json; expansão integral ainda não concluída. Referência: especificação completa enviada em 13/10/2026, seções1–28. Base inspecionada: versão0.7.0,18 ferramentas. Este documento não afirma equivalência profissional nem cobertura de todos os serviços listados.

## Inventário e lacunas

| Área solicitada | Cobertura atual | Trabalho necessário |
|---|---|---|
| Organizations/Control Tower | Ausente | Contas/OUs, políticas e herança, baselines observados; avaliar acesso de management/delegated admin |
| Rede | Parcial | Já existem network_path_inspect/network_flow_logs/public_ip_lookup; adicionar topologia, CIDR overlaps, endpoints, DNS/Resolver, NAT, VPN/DX, IPv6 e maior cobertura TGW |
| Segurança | Parcial | WAF/config/logs e STS existentes; IAM/trust/SCP/RCP, exposição, KMS, findings e CloudTrail ausentes |
| Compute | Parcial | ec2_inventory/ec2_health existentes; métricas históricas, ASG, volumes/IMDSv2, Compute Optimizer e Lambda ausentes |
| Storage/Backup | Ausente como análise independente | S3/EBS/EFS/FSx, políticas/configurações e evidências de recuperação; coleta EBS contextual EKS não substitui esta análise |
| Bancos | Parcial contextual | Redis/OpenSearch como dependências EKS; inventário/saúde RDS/Aurora/DynamoDB e demais bancos ausentes |
| Kubernetes | Parcial | Investigação EKS, perfis nodes/workloads/migration, Karpenter, placement/Spot, histórico e rightsizing existentes; ECS/ECR, segurança aprofundada e custos atribuídos ausentes |
| IaC/CI-CD | Parcial contextual | ArgoCD/Rollouts observados; análise de plan/state/pipelines fornecidos e CloudFormation ausentes |
| Observabilidade | Parcial | Logs EKS/WAF/Flow Logs e métricas EKS existentes; alarmes, AWS Health, CloudTrail/traces e correlação geral ausentes |
| FinOps | Ausente como módulo | Cost Explorer, cobertura/compras, recomendações e custos observados; direitos de payer e consultas cobradas precisam ficar explícitos |
| HA/DR/Arquitetura | Parcial EKS | Indicadores de disponibilidade EKS; grafo de dependências, avaliação por requisitos e evidências multissserviço ausentes |
| Migração | Parcial EKS | Migração Spot; assessment de inventário e MGN/DMS ausentes |
| Serverless/Dados/AI-ML | Ausente | Módulos específicos, contratos e APIs atualizados por serviço |
| Administração de sistemas | Parcial EKS/SSM | Receitas fixas de bastion existentes; diagnósticos genéricos de hosts somente com autorização específica |

A cobertura indicada descreve checks implementados, não comprova saúde funcional. Nomes da seção20 são sugestões: não duplicar eks_health/eks_node_analysis/karpenter_health/spot_analysis se o perfil existente já entrega a análise. ELB também deve estender elbv2_inspect quando adequado.

## Alternativas

1. Expansão por módulos e releases verificáveis (recomendada): todos os requisitos permanecem no backlog, cada módulo tem escopo e testes próprios; menor risco de regressão e claims sem prova.
2. Um catálogo amplo de wrappers de API: rápida cobertura nominal, mas contradiz a exigência de análises semânticas e aumenta chamadas/contexto.
3. Reescrever como plataforma nova: permite nova arquitetura, mas contraria preservação do projeto e eleva risco de migração.

## Arquitetura proposta

Reutilizar resolve/authenticated_session, EvidenceStore, envelope/bounded e módulos atuais. Adicionar um executor comum para novos módulos, com operações SDK explicitamente permitidas, sessões por alias/região, clientes reutilizados durante a consulta, deadline, limites de páginas/objetos, backoff SDK e concorrência limitada. Migração dos módulos existentes apenas quando houver benefício testado; não refatorar tudo de uma vez.

Consultas multi-account/multi-region usam escopos explícitos configurados, inicialmente até quatro combinações por job e duas em paralelo. Falha em uma combinação não elimina evidências das outras e nunca resulta em avaliação positiva global. Serviços globais são consultados uma vez por conta; região de autenticação não vira localização fictícia do recurso. Agregação assíncrona terá IDs e APIs próprias ou núcleo compartilhado compatível, sem transformar silenciosamente eks_investigation_get.

Preservar schema_version1.0 e nomes atuais. Novos campos aditivos: account_id verificado, resource_id quando aplicável, fontes e timestamps por evidência, severity e confidence por finding, recomendações/next_actions com evidências referenciadas. Manter collected_at/coverage/errors; não renomear campos para atender a lista sugestiva. Metadados também devem caber no orçamento, com contagens antes do truncamento.

Cache de evidências existente é snapshot, não cache de consultas. Cache de coleta será opcional, TTL por análise, isolado por identidade/conta/região/filtros, com idade e modo fresh; decisões críticas não reutilizam dados silenciosamente. Auditoria local opt-in registra ferramenta, escopo, APIs, duração e resultado; nunca inputs brutos, respostas brutas, credenciais, user data, secret values ou conteúdo de state.

Nenhuma ferramenta mutável nesta expansão inicial. List/Get/Describe não garante ausência de custo: consultas cobradas ou que criam execuções (Logs Insights, Athena, Reachability Analyzer etc.) ficam excluídas por padrão e exigem desenho/autorizações próprios. Leitura de filas não usa ReceiveMessage. Diagnóstico SSM é execução remota e não será rotulado como API puramente read-only.

## Ordem de entrega

1. Fundação compatível: executor para novos módulos, cobertura por componente/escopo, findings rastreáveis, auditoria segura, catálogo de cobertura e orquestração limitada. Primeira fatia funcional: Organizations (contas/OUs/políticas anexadas/herança observada) e cost_summary (gastos por serviço/período, estimated e moeda, sem estimativa inventada de economia).
2. Rede e IAM: topologia/rotas/endpoints/DNS/híbrido; IAM/trust e AccessDenied com políticas disponíveis. Preservar limites conhecidos de IAM efetivo e trânsito TGW/appliances.
3. Compute, bancos, storage/backup: saúde/configuração/métricas e recomendações baseadas em histórico disponível.
4. Observabilidade, segurança centralizada, FinOps avançado e governança/Control Tower.
5. IaC/CI-CD e ECS/ECR; ampliar Kubernetes existente sem aliases redundantes.
6. Serverless, analytics e AI/ML; depois correlacionar dependências para resiliência, arquitetura e migração.

Cada serviço listado exige collector/analyzer/contrato/permissões/fontes e testes próprios. Inventário não equivale a troubleshooting de performance nem avaliação de compliance. Well-Architected é avaliação limitada por evidência/requisitos fornecidos, não certificação automática. RTO/RPO exigem objetivos do usuário e provas de recuperação.

## Primeira entrega e gates

Desenhar em detalhe a fase1 após aprovação desta decomposição. Testes: sucesso, AccessDenied, throttling, expiração, paginação/ciclos, recursos inexistentes, região indisponível, falha parcial, isolamento entre contas/regiões, nenhum método mutável, segredo omitido, budget de resposta e regressão MCP stdio. Build/pip check/smoke do wheel isolado antes de publicação autorizada. Live tests apenas em escopos explicitamente escolhidos, com evidências reais separadas dos testes offline.

Conhecimento: catálogo versionado com fonte oficial, revisão e aplicabilidade de cada regra. Documentação recuperada é dado não confiável; não executa instruções. Consultar AWS/Boto3 oficiais na implementação de cada módulo; não fixar preços/limites mutáveis como verdade atual.

## Estado desta interação

Concluído: leitura da especificação completa, inspeção de arquitetura e18 ferramentas, identificação de cobertura/lacunas e proposta de decomposição.
Não executado: novo código, consultas AWS, novos testes, commit, push ou alteração do cliente.
Pendente: aprovação do desenho por módulos e primeiro recorte; demais requisitos permanecem no escopo do backlog.

## Execução após aprovação

Etapa1 entregue: Organizations, cost_summary, runtime read-only/auditoria opt-in e jobs multi-account. Os serviços iniciais são globais; regiões selecionam autenticação, usage_region filtra cobrança. Cache de consultas desativado; evidências com TTL. 210 testes offline, build, pip check e smoke final do wheel isolado aprovados. Sem consulta AWS real, publicação ou alteração do cliente.

## Continuação autônoma em13/10/2026

Usuário autorizou prosseguir sem novas aprovações. Primeiras fatias das etapas2/3 implementadas localmente em0.10.0: topologia regional IPv4/IPv6 e sinais de configuração, Route53 exato, políticas IAM estáticas/role; EC2/EBS e métricas CPU/rede opcionais, configurações RDS/Aurora/DynamoDB/ElastiCache, bucket S3 e recovery points AWS Backup. São30 ferramentas,18 anteriores preservadas. 250 testes offline, build e pip check aprovados; smoke do wheel isolado aprovado com30 ferramentas.

As etapas2/3 continuam parciais: TGW propagation/Resolver/BGP/Cloud WAN/Network Firewall e IAM efetivo/AccessDenied causal não concluídos; ASG/Compute Optimizer, métricas DB, EFS/FSx/backup policies/restore também não concluídos. Etapas4–6 permanecem no backlog. Documentação detalhada em network-iam.md e resource-assessments.md. Nenhuma consulta AWS real ou atualização do cliente; sem commit/push nesta interação.

## Continuação: primeiras fatias das etapas4–6

Em13/10/2026, usuário solicitou prosseguir. Oito ferramentas acrescentadas às30anteriores: security_findings_summary, incident_diagnostics, terraform_plan_analysis, cloudformation_health, ecs_service_assessment, serverless_assessment, analytics_assessment e ai_resource_assessment. 38tools locais. Testes279, build exit0, pip check e wheel isolado MCP stdio aprovados. Fontes e limites em operations-expansion.md; cobertura versionada em capability-coverage.json. Nenhuma consulta AWS real, mudança em recursos, commit/push ou cliente atualizado.

Não afirmar conclusão integral de governança/FinOps/arquitetura/DR/analytics/AI. Aplicações/runtime, testes de restore e IAM efetivo continuam não verificados. Novos collectors não criam queries/jobs/inferências nem recebem mensagens.
