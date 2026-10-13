# Troubleshooting de rede â€” 0.7.0

Duas ferramentas somente leitura, com identidade AWS validada por alias, evidÃªncias paginadas e erros sanitizados. NÃ£o criam Reachability Analyzer, nÃ£o executam sondas e nÃ£o alteram SGs, NACLs ou rotas.

## network_path_inspect

Informe `account`, `region`, `source_eni_id`, `destination_eni_id`, `port` e opcionalmente `protocol` (`tcp` ou `udp`). `source_port` permite avaliar a porta de retorno exata; sem ela, Ã© usada a faixa presumida 1024â€“65535 e uma negaÃ§Ã£o parcial dessa faixa permanece inconclusiva.

`source_ip` e `destination_ip` selecionam IPv4 primÃ¡rio, secundÃ¡rio ou pertencente a prefixo delegado da ENI. IP que nÃ£o pertence Ã  ENI Ã© rejeitado. `destination_account` consulta a ENI de destino em outro alias; `network_account` consulta metadados de rede na conta proprietÃ¡ria da VPC compartilhada. Todos os aliases devem estar configurados, na mesma regiÃ£o, e sÃ£o autenticados separadamente. Um Ãºnico alias de rede atende os dois endpoints.

A avaliação seleciona associaÃ§Ã£o explÃ­cita de route table ou a tabela principal, aplica longest prefix match, expande managed prefix lists e verifica rota de ida e retorno. SGs sÃ£o avaliados pela uniÃ£o das permissÃµes; NACLs pela primeira regra aplicável, incluindo retorno. ReferÃªncias de SG sÃ£o avaliadas para caminho local ou peering ativo entre as VPCs esperadas.

TGW: consulta attachments, associaÃ§Ã£o das tabelas e longest prefix match para os dois destinos. A cobertura permanece parcial: NACLs das subnets de attachment e configuraÃ§Ãµes de suporte a referÃªncias de SG via TGW nÃ£o sÃ£o avaliadas. NAT, appliances e demais saltos intermediários também deixam o caminho inconclusivo.

`configuration_consistent` indica consistência apenas dos checks cobertos. `configuration_blocked` registra negaÃ§Ã£o observada. `insufficient_evidence` e cobertura parcial indicam lacunas. `connection_verified` Ã© sempre falso: DNS, NetworkPolicy, firewall do host, listener, TLS e autenticaÃ§Ã£o da aplicaÃ§Ã£o exigem verificaÃ§Ã£o prÃ³pria.

## network_flow_logs

Informe `account`, `region`, `log_group_name`, `start_time`, `end_time` (ISO 8601 com offset) e pelo menos um seletor: `interface_id`, `source_ip` ou `destination_ip`. `port` filtra a porta de destino. Janela positiva de atÃ© uma hora.

A ferramenta lê Flow Logs retidos no CloudWatch no formato padrÃ£o de 14 campos v2, podendo ignorar campos adicionados ao final. Formatos reordenados e S3 nÃ£o sÃ£o suportados. Retorna apenas campos normalizados, sem mensagem bruta ou payload. Registros de outra conta sÃ£o omitidos e sinalizados como lacuna.

ACCEPT nÃ£o comprova sucesso do serviço; REJECT nÃ£o distingue sozinho SG de NACL. SKIPDATA e formatos inválidos tornam a coleta parcial. NODATA ou ausÃªncia de registros nÃ£o comprovam ausÃªncia de tráfego: retenÃ§Ã£o, entrega e configuraÃ§Ã£o de logging podem produzir lacunas. `history_complete` permanece falso.

## Limites e permissÃµes

Prazo nominal de coleta de 45 segundos, com timeouts SDK; uma chamada em andamento pode ultrapassar esse prazo. Até 10 pÃ¡ginas/1.000 objetos por consulta, 1.000 eventos examinados e 200 registros correspondentes. Limites e ciclos de paginação geram resultado parcial com evidÃªncias jÃ¡ coletadas. Detalhes sÃ£o recuperados por `evidence_get`.

Use as permissÃµes opcionais no [exemplo IAM](../config/eks-diagnostics-policy.example.json): DescribeNetworkInterfaces, DescribeRouteTables, DescribeSecurityGroups, DescribeNetworkAcls, GetManagedPrefixListEntries, DescribeVpcPeeringConnections, DescribeTransitGatewayAttachments, SearchTransitGatewayRoutes e logs:FilterLogEvents. O exemplo nÃ£o foi aplicado; restrinja acesso aos recursos necessários no ambiente.

## ValidaÃ§Ã£o

Suite offline cobre rotas, prefix lists, SGs, ordem de NACL/retorno, peering, TGW, isolamento entre contas, formato/filtros de Flow Logs, limites, erros, parÃ¢metros SDK e MCP stdio. Fixtures sintéticas, sem dados de clientes. Essa validação nÃ£o substitui consulta real nem teste funcional da aplicaÃ§Ã£o.
