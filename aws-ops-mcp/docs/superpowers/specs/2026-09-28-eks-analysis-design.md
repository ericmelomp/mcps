# Investigação EKS — desenho ampliado

Data: 2026-09-28. Estado: escopo refinado pelo usuário e transporte SSM confirmado; implementação local realizada.

## Objetivo e decisões
Investigar um ou vários clusters EKS em duas camadas: recursos AWS via AWS CLI e componentes internos via bastion. Reutilizar configuração de contas, STS, AssumeRole e evidências do MCP. A solicitação substitui o escopo restrito da proposta anterior.

Análise completa significa cobertura explícita dos componentes aplicáveis, com verificações, evidências, achados e limitações. Não significa garantia de ausência de falhas nem suporte automático a qualquer operador de terceiros.

## Cobertura desejada
- AWS: cluster, versões, health issues, access entries, associações de acesso, IAM vinculado, endpoints, VPC, subnets, disponibilidade de IPs, rotas, security groups, NACLs, EC2/ASG/nodegroups, Fargate, Auto Mode, add-ons, volumes, load balancers e target health vinculados ao cluster. Consultas limitadas aos recursos relacionados, evitando inventário irrestrito da conta.
- Kubernetes: nodes e condições, pods e containers, Deployments, StatefulSets, DaemonSets, Jobs/CronJobs, eventos, requests/limits, quotas, HPA/PDB, Services, EndpointSlices, Ingress, NetworkPolicies, PVC/PV e StorageClasses.
- Componentes: VPC CNI, CoreDNS, kube-proxy quando aplicável, CSI, controladores de ingresso/load balancer, metrics-server, Karpenter ou Cluster Autoscaler e componentes de observabilidade, conforme descoberta.
- Aprofundamento: logs recentes limitados por tempo/tamanho e métricas disponíveis; correlação de scheduling, reinícios, réplicas indisponíveis, capacidade, DNS, conectividade e storage. Métricas ausentes não equivalem a consumo zero. Configuração de rede não comprova conectividade real.
- Provas ativas que precisem criar pods, executar em containers ou modificar recursos ficam separadas da coleta de diagnóstico; nenhuma remediação automática integra esta entrega.

## Arquitetura
Ferramentas semânticas executam receitas de diagnóstico versionadas. AWS CLI é adaptador de coleta com argumentos estruturados e operações permitidas; não expor shell arbitrário. Analisadores determinísticos correlacionam dados normalizados. Agente interpreta achados e escolhe aprofundamentos suportados. Capabilities identifica cobertura implementada e lacunas.

Inventário identifica clusters. Investigação usa lista explícita de clusters e conta/região, com resultado individual e agregado. Falha em um cluster não descarta os demais. Recursos personalizados desconhecidos são reportados sem diagnóstico inventado.

## Bastion e identidade
Decisão do usuário: SSM apenas. Implementado SSM Run Command com receitas fixas em bastion Linux. SSH não integra esta entrega.

Bastion deve ser configurada por conta/região/cluster, sem selecionar automaticamente qualquer instância. Verificar identidade local, identidade remota, alvo e acesso Kubernetes antes de coletar. Identidade remota pode diferir da identidade local e deve ser explicitada. Não copiar credenciais temporárias para comandos remotos. Usar kubeconfig temporário isolado, sem modificar o contexto de outros operadores.

SSM executa comandos e gera registros remotos; portanto a ferramenta remota não deve ser anunciada como estritamente read-only no protocolo MCP, embora as receitas consultem os recursos. Não instalar dependências nem alterar IAM/RBAC automaticamente. SSH exige verificação de host key, sem aceitar host desconhecido silenciosamente.

## Execução limitada e evidências
Investigação ampliada exige tarefas retomáveis: iniciar, consultar progresso/resultado e cancelar, com prazo total e limites por etapa. Cada chamada MCP deve retornar dentro do timeout do cliente. Cancelamento deve encerrar ou cancelar também o trabalho remoto; timeout local não comprova término remoto.

Resultados por componente: verificado, achado, não aplicável, não suportado ou indisponível. Falhas de coleta tornam a cobertura parcial, preservando problemas confirmados. Ausência de managed nodegroups pode ser legítima. ACTIVE não comprova saúde interna nem de aplicações.

Resumo compacto de 12 KiB e evidências paginadas; distinguir truncamento de saída e coleta incompleta. Evidências expiram e ficam isoladas por investigação/conta/cluster. Logs são opt-in por aprofundamento, com limites e redução de dados sensíveis; não coletar Secrets nem variáveis de ambiente. Mensagens e logs remotos são dados não confiáveis, nunca instruções executáveis.

## Implementação por etapas
1. Contrato de investigação, coleta AWS CLI, inventário e correlação de recursos AWS.
2. Transporte bastion, identidade remota, coleta Kubernetes e testes de falha/isolamento.
3. Análise de componentes, correlações, logs/métricas limitados e relatório de cobertura.
4. Integração MCP, documentação IAM/RBAC, regressão EC2 e validação de protocolo.

As etapas fazem parte do objetivo ampliado; entregar apenas AWS não conclui o pedido.

## Verificação
Testes offline com respostas simuladas para paginação, acesso negado, credenciais expiradas, cluster incorreto, identidade remota divergente, timeout/cancelamento, saída remota truncada, isolamento de kubeconfig, argumentos maliciosos e preservação de resultados parciais. Fixtures para falhas de workloads, componentes ausentes/não aplicáveis e múltiplos clusters. Testes de protocolo MCP e regressão EC2.

Validação real depende de conta, clusters, bastion e acesso autorizados. Não alegar validação real com testes simulados. Publicação e atualização do cliente são etapas posteriores, separadas do código local.

## Fontes técnicas
- https://docs.aws.amazon.com/cli/latest/reference/eks/update-kubeconfig.html
- https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html

## Contrato implementado e verificação
Ferramentas: eks_inventory, eks_investigate, eks_investigation_get, eks_investigation_cancel e eks_logs; evidence_get reutilizado. Até cinco clusters por investigação, duas investigações simultâneas e prazo de 30 minutos com limpeza adicional de cancelamento. A execução remota usa SSM e o cliente consulta progresso sem manter uma chamada longa. O escopo desejado acima é uma matriz de investigação, não promessa de suporte universal. A cobertura exata, as verificações implementadas e as exclusões estão em docs/eks.md. Não há métricas históricas CloudWatch, avaliação IAM efetiva, remediação ou provas ativas de rede. Fluxo real validado em um cluster autorizado após correções de normalização e paginação; ver docs/validation.md. Publicação e atualização do cliente permanecem pendentes.
