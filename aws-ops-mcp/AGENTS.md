# AWS Ops MCP

- Projeto independente dentro do repositório mcps.
- Ler e atualizar este histórico a cada interação; preservar registros anteriores.
- Comunicação curta e simples em português.
- Nunca registrar credenciais ou dados reais de clientes no Git.
- Manter execução determinística separada do agente que desenvolve novas capacidades.
- Coleta incompleta ou sem permissão nunca significa recurso saudável.
- Quando o usuário fornecer credenciais temporárias identificadas por conta, seguir docs/temporary-access.md: importação local via stdin, identidade verificada e profiles automáticos. Não pedir edição manual de profiles/JSON nesse fluxo. Nunca registrar valores de credenciais neste histórico, código ou saída de comandos.

## Histórico

### 2026-09-24 — Organização e especificação
- Solicitação: continuar AWS Ops MCP com expansão assistida, dentro de uma pasta com seu nome no repositório mcps.
- Decisão aprovada: MCP executa análises; agente desenvolvedor amplia módulos e análises com testes. O servidor não se reescreve durante consultas.
- Concluído: criada pasta aws-ops-mcp; preservado contexto original; escrita e revisada especificação inicial.
- Proposta: primeira entrega local, somente leitura, com descoberta de capacidades, EC2, configuração de contas, evidências limitadas e procedimento de extensão assistida.
- Pendente: revisão da especificação escrita conforme skill brainstorming; primeiro módulo EC2 ainda é uma escolha proposta. Implementação, testes e configuração real não iniciados.

## Etapas
- [x] Explorar contexto, instruções e estado do repositório.
- [x] Recuperar intenção e esclarecer expansão de capacidades.
- [x] Comparar execução especializada, CLI genérica e autoalteração.
- [x] Registrar desenho proposto e separar decisões aprovadas de propostas.
- [x] Escrever especificação e revisar consistência, escopo e critérios.
- [x] Revisão da especificação pelo usuário.
- [x] Plano de implementação.
- [x] Implementar, testar e documentar instalação.
- Acompanhamento visual: dispensado; projeto sem interface gráfica nesta etapa.

### 2026-09-24 — Primeira versão implementada
- Solicitação: usuário aprovou a especificação e autorizou prosseguir.
- Concluído: pacote Python instalável, servidor MCP stdio e ferramentas capabilities, ec2_inventory, ec2_health e evidence_get.
- Concluído: aliases de conta/região validados, AssumeRole opcional, conferência de identidade, processo de coleta isolado com deadline, limites de paginação/instâncias e cache de evidências limitado.
- Concluído: README, exemplo de configuração sem credenciais, política EC2 de leitura, procedimento de expansão assistida, plano e fotografia de dependências.
- Verificado: 20 testes offline passaram em 6,51 segundos; incluem sessão MCP stdio real, erros, paginação, timeout com preservação de resultados, limites, identidade e AssumeRole simulados. pip check sem dependências incompatíveis.
- Medido: benchmark sintético de 1.000 instâncias, 150.000 bytes normalizados contra 3.633 bytes de resumo (97,58% menos bytes). Não é medição de tokens ou economia líquida de conversa.
- Ambiente: .venv local com Python 3.13.4, MCP SDK 1.30.0 e boto3 1.43.101; arquivos locais e ambiente ignorados pelo Git.
- Nota de processo: writing-plans não encontrada nas skills/plugins; plano documentado diretamente após autorização. Sem delegação para subagentes.
- Pendente: definir conta/profile/região reais e cliente MCP, configurar conexão e executar smoke test AWS autorizado. Nenhuma AWS real consultada, nenhum cliente configurado, nenhum commit ou push realizado.

### 2026-09-24 — README com visão das capacidades
- Solicitação: mostrar com clareza o poder do MCP no README.
- Concluído: README ampliado com pedidos em linguagem natural, fluxo Mermaid, benefícios ligados à implementação, benchmark com limites, exemplo de resultado, interpretação dos status, expansão assistida e possibilidades futuras explicitamente não implementadas.
- Concluído: README raiz do repositório atualizado com catálogo e link para AWS Ops MCP.
- Verificação: conteúdo confrontado com server.py, service.py e relatório de validação; links locais e blocos Markdown verificados. Sem alteração de código ou nova execução de testes.
- Pendente: configuração AWS real e conexão do cliente permanecem necessárias.

### 2026-09-24 — Preparação do commit e push
- Solicitação: publicar o MCP no repositório remoto.
- Concluído: revisão do conjunto código/testes/documentação; destino origin/main identificado. Ambiente virtual e arquivos de configuração local excluídos pelo .gitignore.
- Planejado: commit feat(aws-ops-mcp): add read-only EC2 diagnostics e push normal. Consultar histórico Git e AGENTS.md da pasta de trabalho externa ao repositório para resultado do envio.

### 2026-09-24 — Orientação de configuração no Codex
- Solicitação: como configurar o MCP para uso neste Codex.
- Concluído: confirmados CLI codex mcp add/get disponível e Python do .venv existente. Servidor aws-ops-mcp ainda não registrado; accounts.local.json ainda ausente.
- Concluído: consultada documentação oficial e preparada orientação para mapear conta/profile/região e registrar transporte stdio.
- Pendente: usuário informar o profile AWS e região desejados; configurar conta e registro do cliente. Nenhuma credencial lida ou configuração global alterada nesta etapa.

### 2026-09-24 — Arquivo local para preenchimento
- Solicitação: criar arquivo de configuração para o usuário substituir os valores.
- Concluído: criado accounts.local.json com alias minha-conta, ID fictício, placeholder de profile e região de exemplo. JSON validado; git check-ignore confirmou exclusão pelo .gitignore.
- Pendente: usuário preencher conta/profile/regiões; registrar MCP no Codex. Nenhuma consulta AWS ou alteração na configuração global realizada.

### 2026-09-24 — Credenciais temporárias sem cadastro manual
- Solicitação: usuário fornece uma ou várias credenciais temporárias identificadas por conta; agente prepara acesso e executa análise, sem exigir edição manual de profiles/JSON. Preferência por profiles locais separados do arquivo de contas.
- Concluído: importador local via stdin, validação STS de todas as identidades antes de gravar, profiles exclusivos fora do repositório, renovação por alias, detecção de conta divergente e erros sem valores secretos. Suporte opcional a credentials_file por conta mantém os quatro tools existentes.
- Concluído: documentação docs/temporary-access.md, README e procedimento de uso atualizados. Nenhuma credencial real recebida ou acessada.
- Verificado: 30 testes offline passaram em 7,43s; inclui múltiplas contas, renovação, expiração simulada, isolamento e leitura efetiva do Session Token pelo SDK.
- Concluído: servidor aws-ops-mcp registrado no Codex local via stdio, usando .venv e accounts.local.json; timeout do cliente 75s para acomodar deadline de coleta e limpeza. codex mcp get confirmou servidor habilitado.
- Pendente: reabrir/recarregar Codex para disponibilizar ferramentas nesta sessão e fornecer credenciais/contas e escopo de análise para teste real. Novas alterações não commitadas nem enviadas ao GitHub.

### 2026-09-24 — Execução carregada do GitHub
- Solicitação: usar código do GitHub e executar neste computador sem depender da pasta clonada; opção confirmada pelo usuário.
- Concluído: confirmado uvx disponível e pacote da versão publicada carregado do GitHub em cache externo ao checkout. Preparada configuração de contas em ~/.aws/aws-ops-mcp/accounts.json, preservando o arquivo original.
- Concluído: entrypoint aws-ops-import-credentials adicionado para importação independente do checkout; instruções em docs/github-install.md e README.
- Planejado: publicar atualização de credenciais temporárias e entrypoint, validar pacote publicado via stdio fora do projeto e trocar configuração Codex para uvx com commit fixo. Resultado final registrado no AGENTS.md da pasta de trabalho externa ao repositório.
- Validação anterior mantida: 30 testes offline aprovados. Nenhuma credencial real ou consulta AWS nesta tarefa.

### 2026-09-24 — Solicitação de diagnóstico EKS
- Solicitação: usar AWS Ops MCP para verificar funcionamento do cluster EKS de produção; usuário pediu continuidade.
- Concluído: capabilities chamado pelo conector MCP ativo; confirmou somente EC2 e quatro ferramentas. Inspecionada apenas lista de aliases/regiões da configuração ativa: nenhuma conta cadastrada.
- Resultado: nenhuma análise de saúde EKS realizada; não há evidências para concluir saúde do cluster. Nenhuma chamada a recursos AWS ou Kubernetes realizada.
- Pendente: receber acesso temporário identificado por conta, região e nome exato do cluster. Ampliar capacidades para EKS/Kubernetes e verificar autorização de leitura no cluster antes do diagnóstico. Não substituir saúde de Kubernetes por saúde EC2.

### 2026-09-24 — Diagnóstico EKS parcial com acesso temporário
- Solicitação: usuário forneceu credenciais temporárias e escopo EKS para análise de leitura.
- Concluído: importador publicado validou identidade e registrou acesso fora do repositório. Consultas diretas às APIs AWS confirmaram alvo e estados de cluster, nodegroups e add-ons. MCP ativo permanece limitado a EC2; nenhum módulo EKS foi declarado implementado.
- Limitação: endpoint Kubernetes privado sem conectividade TCP deste computador (timeout). Não foi possível verificar pods, nodes Ready, workloads ou eventos internos.
- Evidências: relatório operacional por cliente salvo fora do repositório, em ~/.aws/aws-ops-mcp/reports. Credenciais e dados de cliente não registrados neste histórico.
- Pendente: conectividade autorizada com a rede privada do cluster para completar análise Kubernetes; extensão EKS do MCP continua pendente. Nenhuma alteração AWS efetuada.

### 2026-09-28 — Desenho da extensão EKS
- Solicitação: prosseguir com implementação de análise EKS no MCP.
- Concluído: consultados históricos, memória relevante e implementação atual; confirmadas quatro ferramentas e runner específico para EC2. Alteração preexistente neste histórico preservada.
- Concluído: escrita e revisada proposta em docs/superpowers/specs/2026-09-28-eks-analysis-design.md, com alternativas, interfaces, cobertura, erros e validação.
- Recomendação: inventário AWS e análise de um cluster com APIs AWS e Kubernetes; inacessibilidade Kubernetes resulta em cobertura parcial.
- Pendente: revisão do escopo proposto antes de implementar conforme gate explícito da skill brainstorming. Nenhum código, acesso AWS, commit, push ou configuração de cliente alterado.

### 2026-09-28 — Escopo EKS ampliado para bastion
- Solicitação: investigar recursos EKS pela AWS CLI e acessar bastion para validar cluster e componentes internos.
- Concluído: proposta reescrita com camadas AWS/Kubernetes, componentes, correlação, investigação de múltiplos clusters, execução remota e cobertura explícita. Consultada documentação oficial de update-kubeconfig e SSM SendCommand.
- Decisão do usuário: escopo deve incluir investigação interna via bastion; somente controle AWS não satisfaz o pedido.
- Pendente: identificar transporte de bastion (SSM, SSH ou ambos), finalizar contrato e implementar. Nenhuma conexão remota, alteração AWS, implementação ou publicação realizada nesta interação.

### 2026-09-28 — Investigação EKS via SSM implementada localmente
- Solicitação: investigar recursos EKS pela AWS CLI e validar cluster/componentes internos pela bastion. Usuário definiu SSM como transporte habitual; adotado SSM apenas.
- Concluído: versão local 0.2.0 com eks_inventory, eks_investigate, eks_investigation_get, eks_investigation_cancel e eks_logs. Ferramentas EC2 e evidence_get preservadas.
- Concluído: operações AWS CLI limitadas, validação STS/profile, mapeamento exato de bastion, receitas SSM fixas, identidade remota, kubeconfig temporário, coleta/análise Kubernetes, recursos AWS relacionados, evidências normalizadas, múltiplos clusters, progresso e cancelamento com término remoto não confirmado explícito.
- Concluído: documentação da cobertura/exclusões e exemplos IAM/RBAC, plano e desenho atualizados; README do projeto e catálogo do repositório atualizados. Alterações preexistentes no histórico preservadas.
- Verificado: 60 testes offline aprovados; pip check sem incompatibilidades; wheel 0.2.0 construído e validado fora do checkout por sessão MCP stdio com nove ferramentas e compilação da receita. Detalhes em docs/validation.md.
- Limites: não há suporte universal a operadores, avaliação IAM efetiva, métricas históricas CloudWatch, provas ativas de rede ou remediação. Cobertura incompleta não gera diagnóstico saudável. Logs possuem redação best effort.
- Pendente: configurar mapeamento das bastions e validar acesso real autorizado. Publicação e atualização do commit fixado no cliente continuam separadas. Nenhuma conta real consultada, permissão concedida, alteração de infraestrutura, configuração ativa, commit ou push nesta interação.

### 2026-09-28 — Teste direto na conta e correções verificadas
- Solicitação: usuário forneceu credenciais temporárias para teste real do MCP e solicitou continuidade.
- Concluído: identidade validada com STS e credenciais renovadas via stdin fora do Git; descoberta AWS e configuração local do mapeamento de bastion SSM. Testado o servidor local por protocolo MCP stdio.
- Concluído: reproduzida e corrigida falha de EndpointSlices com endpoints nulos. Corrigida perda de evidências por truncamento mediante transporte comprimido e paginação SSM com resourceVersion consistente e preservação de resultados parciais.
- Verificado: 66 testes offline aprovados e wheel atualizado. Investigação real final em um cluster concluiu AWS, Kubernetes e correlações sem lacunas de coleta nem evidências truncadas. Resultado degraded corresponde a achados dos recursos, não a falha de execução.
- Concluído: submissão SSM inicialmente não confirmada reconciliada com histórico remoto; término confirmado. Dados operacionais e relatório preservados exclusivamente fora do Git, em ~/.aws/aws-ops-mcp/reports. Detalhes técnicos genéricos em docs/validation.md.
- Limites: teste real em um cluster; nenhuma remediação, alteração de infraestrutura, IAM/RBAC ou coleta de logs de aplicação. Cliente fixado no GitHub não atualizado.
- Pendente: publicação e atualização do cliente. Sem commit/push.

### 2026-09-29 — Extensão CloudFront/ELB para diagnóstico gRPC
- Solicitação: ampliar as capacidades da MCP para investigar chamadas gRPC no caminho público; continuidade autorizada.
- Concluído: versão local 0.3.0, com cloudfront_grpc_inspect e elbv2_inspect. Reutilizados autenticação STS, adaptador CLI restrito, deadline e cache de evidências. Preservada a extensão EKS/SSM preexistente e suas alterações locais.
- Concluído: descoberta de distribuições/balanceadores, análise ordenada de behaviors, requisitos gRPC/POST/HTTP2/HTTPS, listeners, regras host/path, protocolos de targets e saúde. Segredos de headers/OIDC omitidos; cobertura e falhas explícitas.
- Concluído: documentação docs/edge.md, exemplo IAM somente leitura e testes de regressão. Nenhuma política IAM aplicada.
- Verificado: 86 testes offline aprovados; pip check e git diff --check aprovados. Wheel 0.3.0 construído com isolamento de build e validado por MCP stdio fora do checkout, com 11 ferramentas.
- Validação operacional: tentativa de descoberta CloudFront pelo pacote local parou na autenticação expirada. Nenhuma configuração atual de infraestrutura foi coletada. Dados da tentativa permanecem fora do Git.
- Limites: não há testes ativos DNS/TLS/RPC, avaliação WAF nem execução de regras de roteamento. Configuração compatível não comprova saúde funcional.
- Pendências: renovar acesso para teste real, informar alvo da análise e publicar/atualizar cliente fixado no GitHub. Nenhum commit/push ou alteração de infraestrutura realizada.


### 2026-09-30 ? Prepara??o da publica??o 0.3.0
- Solicita??o: fazer push da MCP e utiliz?-la a partir do GitHub.
- Conclu?do: conferidos origin/main e altera??es das extens?es EKS/SSM e CloudFront/ELB; documenta??o de capacidades e instala??o atualizada. 86 testes aprovados e pip check sem conflitos.
- Valida??o operacional anterior: ferramentas CloudFront/ELB foram usadas em conta autorizada ap?s renova??o de acesso; evid?ncias operacionais permanecem fora do Git. Isso n?o comprova sa?de funcional.
- Autorizado e planejado: commit/push normal para origin/main, teste do pacote obtido do GitHub fora do checkout e atualiza??o do commit fixado no cliente. N?o hospedar credenciais ou endpoint remoto no GitHub.
- Resultado da publica??o/configura??o ser? registrado no hist?rico externo ao reposit?rio para manter a ?rvore publicada limpa.

### 2026-10-01 — Proposta de cobertura WAF e IP de saída
- Solicitação: incorporar à MCP as consultas usadas fora dela no diagnóstico recente.
- Concluído: lidos históricos e inspecionados servidor, contratos, adaptador AWS e estado Git limpo na versão 0.3.0.
- Proposta: ferramentas especializadas somente leitura para configuração WAFv2, correlação de logs S3/CloudWatch por janela e Request ID e busca de IP público em NAT Gateways/EIPs das contas configuradas. Reutilizar identidade validada, limites e cache de evidências; omitir headers sensíveis e payloads.
- Alternativa avaliada: executor AWS genérico oferece amplitude, mas perde contratos e limites específicos; não recomendado.
- Validação planejada: testes de correlação, paginação, limites, acesso negado, logs malformados, redação de segredos e descoberta MCP stdio.
- Pendente: aprovação do desenho exigida pela skill brainstorming antes de implementar. Código, permissões AWS e configuração do cliente não alterados; sem commit/push.

### 2026-10-01 — Extensão WAF e IP público implementada
- Solicitação: usuário aprovou implementar as três capacidades propostas para incorporar consultas antes externas à MCP.
- Concluído: versão 0.4.0 com waf_inspect, waf_logs_search e public_ip_lookup; 14 ferramentas totais. Sessão SDK autenticada reutilizada, mantendo a interface EC2. Incluídos documentação, política de leitura de exemplo e desenho/plano aprovado.
- Verificado: 107 testes offline, incluindo descoberta/chamadas MCP stdio, paginação, fuso, correlação, acesso negado, limites, gzip e omissão de dados sensíveis. pip check e git diff --check passaram. Wheel isolado iniciou pelo uvx e anunciou 14 ferramentas; capabilities corresponde à descoberta.
- Validação real: três ferramentas executadas por MCP stdio em conta autorizada. Inspeção WAF e consulta NAT/EIP concluídas; busca S3 correlacionou os dois IDs solicitados em 72 objetos/6034 registros, sem erros. Detalhes operacionais mantidos fora do repositório. CloudWatch validado por testes simulados, sem destino real disponível nesta investigação.
- Limites: coleta somente leitura, sem Firehose/layout customizado ou expansão de grupos referenciados; ausência de resultado não comprova ausência de bloqueio nem propriedade do IP. Nenhuma permissão ou infraestrutura alterada.
- Publicação planejada conforme autorização anterior: commit normal em origin/main e atualização do cliente fixado no GitHub. Resultado final registrado no histórico externo para manter checkout publicado limpo.
