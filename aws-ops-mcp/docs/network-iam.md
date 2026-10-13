# Rede e IAM — expansão0.9.0

Quatro ferramentas novas, preservando as22 anteriores:

- network_topology: VPCs/subnets, CIDRs IPv4/IPv6 e overlaps, rotas/blackholes, NAT, IGW, endpoints, peering, attachments TGW e regras SG públicas. Seleção opcional de até5VPCs; limite50VPCs observadas. Sem probes, prova de conectividade, completa propagação TGW ou avaliação Network Firewall/Cloud WAN/IPAM.
- dns_diagnostics: zona Route53 explícita e nome exato, Alias/TTL/routing. TXT e tipos arbitrários omitidos. Sem resolver runtime, delegação pública, estado dos health checks ou síntese wildcard. Não valida navegação/TLS.
- iam_policy_analyze: análise local de JSON até32KiB e100statements, padrões wildcard/NotAction/NotResource/Principal/OIDC. Não retorna documentos, valores de conditions ou principals. Não substitui IAM Access Analyzer nem simulação/autorização efetiva; policies com denies/conditions/boundaries/SCP/RCP precisam de contexto.
- iam_role_assessment: role explícita, trust, inline/attached policies e permissions boundary; metadados e sinais estáticos com origem rastreável. Nunca AssumeRole de teste, secret retrieval ou documentos brutos. Erros de permissões ficam parciais.

include_hybrid=true em network_topology consulta metadados VPN/DX da região inteira, não exclusivamente vinculados às VPCs selecionadas. Não retorna CustomerGatewayConfiguration/TunnelOptions/PSKs. DOWN de túnel é observação, não diagnóstico de BGP/on-prem nem indisponibilidade global da VPN.

ops_investigate agora aceita network e iam_role. network permite até4combinações conta/região, inclusive uma conta em regiões distintas; serviços globais continuam com um alias por job. Clientes EC2/DX usam região configurada; IAM/Route53 usam endpoint global comercial. Jobs nunca somam custos entre escopos. China/GovCloud continuam não suportados nos novos módulos.

Padrões arriscados geram degraded; lacunas/permissões negadas geram partial. Nenhuma regra pública comprova exposição real ou intenção. IAM findings afirmam somente padrão observado, com effective_authorization_verified=false. Diagnóstico detalhado de caminhos ENI reutiliza network_path_inspect, sem ferramenta duplicada.

ReadContext, auditoria opt-in, deadlines, fontes e EvidenceStore permanecem compartilhados. Consultas novas são fresh. Operações SDK são fixas e read-only; nenhum recurso ou IAM é alterado. Permissões de exemplo não aplicadas.

Fontes oficiais consultadas em13/10/2026:
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_role.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_vpc_endpoints.html

Validação offline: casos IAM, OIDC/segredos, IAM Marker pagination, IPv6 overlap, blackholes, metadata VPN sem segredo, erros parciais, Route53 exato e isolamento regional. Sem provas AWS reais das novas ferramentas.

Lacunas de etapa2 ainda explícitas: AccessDenied causal com CloudTrail, análise efetiva SCP/RCP, resolver/runtime DNS, TGW propagação ampla, Cloud WAN, Network Firewall e Direct Connect virtual interfaces/BGP. Não declarar essas capacidades concluídas.
