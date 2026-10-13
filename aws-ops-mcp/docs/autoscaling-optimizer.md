# Auto Scaling e Compute Optimizer — 0.13.0

## Contratos

`autoscaling_assessment(account, region, group_name)` inspeciona um ASG explicitamente selecionado. Mostra min/desired/max, unidade de capacidade, instâncias e pesos, processos suspensos, distribuição configurada e composição real obtida das EC2. Não confunde desired em vCPU/memória/unidades ponderadas com quantidade de nodes. Peso ou estado ausente resulta em evidência parcial. ASG não representa NodePool do Karpenter.

Consulta até 100 instâncias e uma amostra de 20 atividades, filtradas localmente para as últimas 24 horas. Token de continuação indica coleta parcial; ausência de falha nessa amostra não comprova histórico limpo. Falhas recentes são observações, sem inferência da causa. Warm pools, políticas/schedules e conteúdo de launch templates ficam fora do escopo. Textos livres, tags, user data e causas brutas são omitidos.

`compute_optimizer_assessment(account, region, instance_ids, maximum_age_hours=168)` consulta recomendações EC2 para 1–5 instâncias da conta/região autenticadas. Retorna classificação AWS, atualização, lookback, presença de métrica de memória e até três opções com risco/diferenças de plataforma. A idade máxima é um critério explícito do operador; não é SLA AWS. Recomendações ausentes, erros por recurso, paginação ou dados fora do escopo nunca significam otimização confirmada.

Recomendação stale e falta de memória são sinalizadas. Diferenças de arquitetura exigem revisão de compatibilidade. Estimativas monetárias não são retornadas; economia realizada, aceite funcional e direitos de resize não são inferidos. Não habilita enrollment nem altera EC2.

## Exemplos sintéticos

```json
{"account":"sandbox","region":"us-east-1","group_name":"demo-apps"}
```

```json
{"account":"sandbox","region":"us-east-1","instance_ids":["i-00000001"],"maximum_age_hours":168}
```

Permissões adicionais em `config/compute-read-policy.example.json`: exemplo preparado, não aplicado. Aliases, STS, orçamento de coleta, auditoria opcional, envelope e `evidence_get` reutilizam a plataforma. Testes offline/stdio não comprovam funcionamento real em uma conta.

## Fontes oficiais revisadas em 13/10/2026

- [DescribeAutoScalingGroups](https://docs.aws.amazon.com/boto3/latest/reference/services/autoscaling/client/describe_auto_scaling_groups.html)
- [DescribeScalingActivities](https://docs.aws.amazon.com/boto3/latest/reference/services/autoscaling/client/describe_scaling_activities.html)
- [GetEC2InstanceRecommendations](https://docs.aws.amazon.com/boto3/latest/reference/services/compute-optimizer/client/get_ec2_instance_recommendations.html)

## Próximas lacunas

ASG policies/schedules/warm pools, recomendações de ASG/EBS/Lambda, métricas de memória do agente, validação live, direitos efetivos e prova de rightsizing/economia continuam pendentes.
