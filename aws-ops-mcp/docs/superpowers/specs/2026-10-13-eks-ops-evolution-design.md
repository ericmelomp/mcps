# AWS Ops MCP — evolução EKS 0.5.0 (proposta)

## Objetivo

Responder com evidência compacta quais workloads dependem de um pool antigo, se os destinos têm capacidade e quais falhas precisam de atenção. Reduzir consultas desnecessárias sem mudar o comportamento padrão da investigação completa. Projeto genérico; exemplos e testes sintéticos, sem credenciais ou inventário de clientes.

## Abordagens

Recomendada: ampliar eks_investigate com perfis e análises determinísticas sobre evidências existentes. Alternativa: ferramenta separada para migração, com duplicação de coleta/contratos. Uma CLI genérica não é proposta: aumentaria superfície de execução e perderia limites de comandos fixos.

## Entregas

1. Normalização por allowlist de labels de nodes, selectors/tolerations/afinidades relevantes e spec de dimensionamento do NodePool. Nunca reter specs completos, env, secrets ou annotations arbitrárias. Referência EC2 por provider ID para lifecycle quando o label não estiver disponível; classificações unknown explícitas.
2. Resumo de migração: pods/workloads por nodegroup/NodePool/capacidade, dependências remanescentes e distinção de DaemonSets, controllers e StatefulSets. Não rotular retirada como segura automaticamente: volumes, PDBs, réplicas/dispersão, cobertura e teste funcional devem aparecer como evidências ou lacunas.
3. Capacidade: allocatable, soma de requests efetivos (incluindo init containers e overhead suportados), uso instantâneo e overhead de DaemonSets; folga por node/pool, maiores workloads e limites do Karpenter. Não prometer que memória real provocará autoscaling nem simular scheduler completo. Percentuais referenciados ao allocatable. Ausência de métricas não vira zero.
4. Perfis opcionais de coleta: full (padrão preservado), nodes, workloads e migration. Sets fixos de APIs/receitas por perfil, validação de entrada e cobertura explícita de análises não solicitadas. Evidências parciais durante job com indicador provisório e paginação estável, se compatível com armazenamento atual; caso contrário, entregar resumo progressivo sem expor evidência inconsistente.
5. Contexto para alertas: mapear Service/EndpointSlice/workload desejado=0 a target groups; manter unhealthy como estado real e informar ausência de backend. Para reinícios, coletar timestamps seguros e diferenciar acumulado de delta somente quando houver dois snapshots comparáveis. Probes Ready atuais não apagam Warning recente.
6. ArgoCD Applications e Argo Rollouts opcionais: descoberta de CRDs e leitura limitada de sync/health/phase/conditions e gerações; sem operação sync/rollback. Ausência CRD=not_applicable, AccessDenied=partial. Não reter fontes Git/Helm/valores/credenciais.

## Critérios de aceite

- Investigação padrão, ferramentas antigas e contratos de segurança continuam funcionando.
- Fixture sintética com pools mistos informa contagens e remanescentes corretamente; labels ausentes/contraditórios não são inferidos pelo nome.
- Filtros de agendamento úteis sem exportação de dados sensíveis.
- Requests efetivos testados com init/sidecars/overhead, ou caso não suportado explicitamente marcado como lacuna.
- Perfil nodes não consulta pods/LBs desnecessários; migration só consulta dependências definidas.
- Alertas de workloads zero preservam estado de target e não concluem que estão desligados intencionalmente.
- ArgoCD/Rollouts presentes, ausentes, negados e paginados testados.
- Testes offline de regressão, protocolo MCP stdio e smoke de pacote local; documentação de cobertura/permissões atualizada.
- Publicação, pin do cliente e smoke real são fases separadas. Implementação local não significa ferramenta instalada no cliente.

## Plano de execução

1. Evidências/normalização e testes de segurança.
2. Resumo de migração e capacidade com fixtures.
3. Perfis de coleta e progresso compatível.
4. Contexto de alertas e CRDs opcionais.
5. Documentação, versão e pacote local verificado.

## Status

Proposta preparada e revisada; implementação não iniciada. Revisão do usuário pendente. Sem commit/push ou alteração de infraestrutura/clientes. Arquivo uv.lock preexistente preservado.