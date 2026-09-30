# Investigação EKS por AWS CLI e bastion SSM

A implementação local adiciona inventário de clusters, investigação AWS/Kubernetes e coleta explícita de logs. Não altera workloads nem instala dependências. O transporte de bastion é exclusivamente SSM, conforme decisão do usuário.

## Ferramentas

| Ferramenta | Uso |
|---|---|
| `eks_inventory(account, region)` | Inicia inventário AWS CLI de até 100 clusters. |
| `eks_investigate(account, region, clusters)` | Inicia investigação de 1 a 5 clusters explícitos, cada um com bastion mapeada. |
| `eks_investigation_get(investigation_id)` | Consulta progresso, achados, cobertura e ID das evidências finais. |
| `eks_investigation_cancel(investigation_id)` | Solicita cancelamento local e do comando SSM em andamento. |
| `eks_logs(account, region, cluster, namespace, pod, container)` | Inicia consulta explícita de logs de um container. |
| `evidence_get(evidence_id, offset, limit)` | Recupera páginas de evidências normalizadas, achados e cobertura por componente. |

As ferramentas de início retornam imediatamente um `investigation_id`; consulte o progresso até `summary.state` ser `finished` ou `cancelled`. `status=partial` durante execução é esperado. A falha de um cluster preserva os resultados dos demais. O relatório só fica `ok` quando os checks implementados foram concluídos sem achados de alerta/erro. Isso não comprova saúde funcional de aplicações.

## Configuração local

1. Mantenha `AWS_OPS_CONFIG` apontando para o arquivo de aliases existente. O onboarding de credenciais temporárias não muda.
2. Instale AWS CLI v2 no computador que executa o MCP; nenhuma instalação é feita automaticamente.
3. Copie `config/eks-bastions.example.json` para uma pasta local fora do Git, como `~/.aws/aws-ops-mcp/eks-bastions.json`, e ajuste alias, região, cluster e instance ID.
4. Configure `AWS_OPS_EKS_CONFIG` com o caminho absoluto desse arquivo no processo MCP. Um mapeamento exato e único é obrigatório por cluster.
5. A bastion precisa ser Linux, estar Online no SSM, alcançar a API Kubernetes e ter `python3`, `aws` e `kubectl` disponíveis ao usuário do SSM Agent.

O arquivo de bastions não contém credenciais. `role_arn` opcional identifica a role usada pelo `aws eks get-token` remoto. `expected_identity_arn` opcional confere o ARN exato da identidade AWS de origem da bastion; sessões STS podem mudar de nome, portanto não preencher com ARN de sessão transitória sem considerar essa renovação. A conta remota deve corresponder à conta local validada. O ARN do cluster remoto deve ser idêntico ao descoberto localmente.

O SSM Agent pode executar como root. A identidade desse processo pode diferir da sessão interativa de um operador; o relatório registra a identidade efetiva. Nenhuma credencial local é inserida no script remoto. A receita cria kubeconfig JSON em diretório temporário exclusivo, verifica o certificado do cluster e remove o diretório no término normal. Encerramento forçado pode deixar resíduos temporários sem tokens persistidos. O kubeconfig padrão não é alterado.

## Permissões

`config/eks-diagnostics-policy.example.json` é um exemplo para a identidade local: leituras AWS, consulta de SSM e `SendCommand` restrito à instância/documento indicados. Substitua conta, região e bastion fictícias; reduza recursos e condições conforme a conta. Se houver AssumeRole local, a identidade de origem também precisa de autorização para assumir a role configurada.

Na bastion, a identidade de origem precisa de `eks:DescribeCluster`. Se `role_arn` estiver configurada, também precisa de `sts:AssumeRole` e trust correspondente. A identidade usada pelo token EKS precisa estar autorizada no cluster, via mecanismo de acesso adotado pelo ambiente. IAM para AWS não substitui RBAC Kubernetes.

`config/eks-rbac.example.yaml` define apenas ClusterRoles de leitura; não concede acesso sem binding. O papel de logs é separado. Nenhuma permissão para Secrets, exec, criação ou remoção de recursos é incluída. O MCP nunca aplica IAM, RBAC ou access entries.

SSM `SendCommand` é execução remota, não uma API somente leitura. A permissão IAM para `AWS-RunShellScript` permite shell ao titular; a restrição a receitas fixas é implementada pelo MCP, não pelo IAM. Por isso, `eks_investigate`, `eks_logs` e cancelamento declaram `readOnlyHint=false`. As receitas consultam recursos e geram registros SSM/arquivos temporários.

## Cobertura implementada

- AWS: cluster, managed nodegroups, add-ons, Fargate, Auto Mode observado, access entries e associações de políticas; inventário de roles relacionadas, trust e nomes de políticas. Não calcula autorização IAM efetiva nem expande documentos de todas as políticas.
- Infraestrutura: subnets, rotas, NACLs e security groups da VPC compartilhada; instâncias com tag EKS; ASGs de nodegroups; status checks dos nodes identificados por Kubernetes; volumes EBS referenciados por PVs CSI; ELBv2/target groups/target health identificados por hostname de Service/Ingress.
- Kubernetes: nodes, pods/containers, workloads, Jobs/CronJobs, eventos Warning, requests/limits, quotas, HPA/PDB, Services/EndpointSlices, Ingress, NetworkPolicies, PV/PVC, StorageClasses, service accounts, CRDs, recursos Karpenter v1 e snapshots da Metrics API.
- Verificações: estados AWS, health issues, pouca disponibilidade de IPs em subnets (menos de 16), rotas blackhole, nodes não Ready/pressão, pods Pending/Failed/Unknown, CrashLoopBackOff/ImagePullBackOff e erros relacionados, OOM observado, réplicas indisponíveis, geração pendente, Jobs Failed, HPA sem condições de operar, PVC não Bound, PV Failed e condições Karpenter.
- Correlações: Service sem endpoints prontos, pod com dependência PVC ausente/não vinculada, pod em node não Ready; status EC2 e targets ELBv2. Eventos e reinícios são observações, não prova de falha atual ou causa raiz.
- Componentes como CoreDNS, CNI, CSI, ingress, Karpenter, autoscaler e observabilidade são identificados por nomes de workloads/pods. Seus estados são avaliados como workloads; não há teste funcional de DNS/CNI ou garantia de identificar todo componente renomeado. Auto Mode pode operar componentes sem pods visíveis.

Uma API opcional Karpenter só é considerada não aplicável quando a coleção completa de CRDs confirma ausência do CRD. API v1 ausente com CRD existente, falta de acesso a CRDs ou Metrics API indisponível permanecem lacunas. Operadores de terceiros desconhecidos são inventariados via CRDs, sem diagnóstico específico inventado.

VPCs podem ser compartilhadas: achados de subnets/rotas não provam impacto no cluster. Volumes não EBS, ELB clássico, métricas históricas CloudWatch, testes funcionais de aplicação, provas ativas de rede, análise de custos e remediação não estão implementados. Dados de requests/limits, quotas, políticas de rede e métricas são evidências para investigação; não implicam cálculo completo de capacidade ou simulação de tráfego.

## Limites e cancelamento

- Até 2 investigações simultâneas, 20 registros em memória, TTL de 15 minutos após conclusão. IDs pertencem ao processo MCP atual; reinício perde os registros.
- Deadline de 30 minutos por investigação, chamadas CLI de até 25 segundos, receita SSM com execução de até 180 segundos e espera local de até 240 segundos. Cancelamento pode levar uma chamada CLI em andamento e até duas chamadas adicionais de limpeza.
- Até 100 páginas AWS e 1.000 itens por coleção; até 20 páginas Kubernetes, solicitando inicialmente 100 recursos por página. Cada página Kubernetes é transportada por uma chamada SSM. Se uma página exceder o limite comprimido, o coletor reduz seu tamanho e repete a página no mesmo resourceVersion antes de contabilizá-la. Tokens de continuação preservam o snapshot; divergência de versão ou falha posterior mantém os resultados anteriores como parciais. Métricas agregadas podem ignorar paginação; a saída bruta de uma chamada remota é limitada a 4 MiB na leitura.
- Até 2.000 evidências e 2.000 achados detalhados por tipo Kubernetes; contagens de recursos/achados continuam refletindo todos os objetos analisados. A saída normalizada é comprimida com zlib e codificada em base64 antes de aplicar o limite de 18.000 caracteres do transporte SSM. O cliente limita a descompressão a 4 MiB e rejeita dados inválidos. Coleções que ainda excedem esses limites são sinalizadas como truncadas, sem depender do limite de 24.000 caracteres do `GetCommandInvocation`. Truncamento é explícito; correlações por ausência exigem coleções completas, sem amostras truncadas.
- Até 4 MiB e 10.000 registros de evidência por investigação, itens de no máximo 12.000 bytes. Resumo de 12 KiB e páginas de evidência de 24 KiB reutilizam o contrato existente. Limites atingidos aparecem como lacunas; não se promete recuperar itens descartados.
- Logs: somente alvo explícito, últimos 10 minutos, até 100 linhas e 10.000 bytes. Redação de padrões comuns de credenciais é best effort. Logs podem conter dados sensíveis que não correspondem aos padrões; trate as evidências como dados operacionais privados. Não são gravados no repositório.

Um pedido de cancelamento SSM aceito não prova que o processo remoto terminou. `unconfirmed_remote_commands` informa comandos sem término confirmado; seus IDs ficam nas evidências. Se `SendCommand` expirar antes de retornar um ID, a submissão é ambígua e a investigação para, sem repetir a execução. O operador deve consultar o histórico SSM da bastion. Reinício do MCP não cancela comandos remotos já enviados; o timeout da receita continua sendo a proteção remota.

## Validação e publicação

Testes offline cobrem análise, isolamento, paginação, falhas, cancelamento, limites e protocolo MCP stdio. Não comprovam IAM, RBAC, rede ou execução SSM em uma conta real. O smoke test real precisa de conta, região, clusters e bastions autorizados e configurados.

O cliente configurado com `uvx` em commit fixo do GitHub continua executando a versão publicada. Alterar este checkout não atualiza esse cliente. Publicação, troca do commit e recarga do cliente são uma etapa separada.

Referências: [GetCommandInvocation](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetCommandInvocation.html), [SendCommand](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html), [paginação Kubernetes](https://kubernetes.io/docs/reference/using-api/api-concepts/), [autenticação kubectl no EKS](https://docs.aws.amazon.com/eks/latest/userguide/create-kubeconfig.html).
