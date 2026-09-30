# CloudFront e ELB: configuração gRPC

A versão local 0.3.0 acrescenta duas ferramentas somente leitura. Reutiliza o adaptador AWS CLI com operações permitidas explicitamente, identidade STS verificada, região autorizada, deadline e evidências do servidor. Não altera distribuições, listeners, targets, IAM ou Kubernetes.

## Ferramentas

- `cloudfront_grpc_inspect(account, region, hostname="", distribution_id="", path="")`: sem seletor, lista distribuições. Com hostname ou ID, consulta a configuração e verifica HTTP/2, POST, gRPC por behavior, HTTPS da origem, habilitação e propagação. Com caminho RPC canônico, seleciona o primeiro behavior correspondente; sem caminho, avalia todos e avisa que os achados podem não afetar a chamada desejada. Alias não comprova resolução DNS. Aliases ambíguos exigem ID explícito. Caminhos com query, escapes ou segmentos relativos são rejeitados para evitar falsa seleção.
- `elbv2_inspect(account, region, load_balancer_arn="", dns_name="")`: sem seletor, lista balanceadores. Com ARN ou nome DNS AWS exato, coleta atributos relevantes, listeners, regras host/path, versões de protocolo e saúde dos targets. O nome DNS deve ser o do ELB, não um CNAME de aplicação. Regras de autenticação e condições de headers não expõem seus valores.

CloudFront é global; `region` valida a configuração da conta usada pelo adaptador. ELB é regional. Origem cujo domínio corresponda ao DNS AWS de um ELB pode ser investigada pela segunda ferramenta. Não há correlação automática por DNS nem execução de regras de ALB.

## Contrato e limites

- Resumo de até 12 KiB; detalhes por `evidence_get`, usando o mesmo processo MCP, por 15 minutos.
- Até 60 segundos por consulta, 100 páginas por API e 2.000 registros de evidência. Coleta interrompida preserva evidências já normalizadas e retorna `partial` ou `error`.
- Permissão negada, token inválido, origem não avaliada ou timeout nunca produzem confirmação de saúde.
- `ok` significa apenas ausência de achados nas verificações declaradas. Não comprova sucesso da aplicação.
- Não coleta valores de headers customizados de origem, secrets OIDC ou condições arbitrárias de headers. Nomes de recursos, hosts e caminhos permanecem dados operacionais; não publicar evidências de cliente no Git.
- Não valida DNS, handshake TLS/ALPN, WAF, políticas completas de forwarding, roteamento Kubernetes ou execução de RPC. Não interpreta configurações de origem S3, VPC origin ou grupos de origem como prontidão gRPC.
- Target TCP saudável em NLB não comprova HTTP/2. Target group HTTP1 de ALB é incompatível com gRPC, mas pode pertencer a outra rota; a ferramenta não afirma que causou a falha relatada.

## Permissões

Exemplo em `config/edge-read-policy.example.json`. O arquivo é referência para revisão, não é aplicado pela ferramenta. Manter permissões de autenticação/AssumeRole já necessárias no ambiente.

## Implementação e validação

Foram consideradas uma CLI genérica e consultas semânticas específicas. As consultas semânticas foram adotadas para preservar limites, análise determinística e evidências compactas. A extensão EKS/SSM existente é reutilizável para a etapa Kubernetes, sem recriar esse módulo.

Critérios: descoberta MCP das duas ferramentas; casos de behavior, requisitos gRPC, erros e redação; preservação dos testes existentes; pacote instalável. Publicação GitHub e atualização do commit do cliente não são realizadas automaticamente. É possível validar o pacote local por MCP stdio antes da publicação.

Referências oficiais:

- [gRPC no CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-using-grpc.html)
- [GrpcConfig](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GrpcConfig.html)
- [Protocolos dos target groups ALB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html)
