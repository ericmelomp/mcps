# Extensão WAF e IP público — desenho aprovado

O usuário aprovou em 01/10/2026 três capacidades somente leitura: inspeção WAFv2, correlação de logs S3/CloudWatch e localização de IP público em NAT Gateways/EIPs. Não há remediação automática.

## Decisões

Ferramentas especializadas preservam contratos e limites verificáveis. Um executor AWS genérico foi descartado por ampliar desnecessariamente o escopo. O SDK reutiliza a autenticação STS existente, incluindo profile, arquivo externo de credenciais, AssumeRole e conferência de conta. A coleta EC2 preexistente preserva sua interface.

`waf_inspect` recebe alias, região e ARN da ACL. Mostra regras ordenadas, ação padrão, IP sets diretamente referenciados e logging. Não expande grupos de regras. Strings de match e headers/respostas customizados são omitidos.

`waf_logs_search` recebe ARN, janela ISO com fuso e Request IDs ou host. Filtros adicionais combinam com AND. Consulta somente o destino atual informado pelo WAF. Retorna campos normalizados, origem da evidência e cobertura, sem headers de autenticação, query string ou corpo. S3 aceita layout nativo WAF gzip; CloudWatch usa FilterLogEvents paginado. Firehose e layouts customizados ficam fora da cobertura.

`public_ip_lookup` consulta NAT Gateways e Elastic IPs de uma conta/região configurada. Para múltiplas contas, repetir a ferramenta em cada alias autorizado. Associação do IP não prova a rota de um pod. Ausência não estabelece propriedade externa.

## Limites e erros

Janela máxima de 24 horas, deadline de coleta de 45 segundos mais chamada em andamento, 100 páginas por API, 1000 itens/objetos, 4 MiB comprimidos por objeto, 32 MiB comprimidos por consulta, 16 MiB descomprimidos por objeto e 100000 registros. Respostas usam o envelope e cache de evidências existentes. Qualquer limite, acesso negado ou corrupção torna a coleta incompleta. Logs ausentes não significam ALLOW.

## Plano de implementação e aceite

1. Extrair sessão autenticada mantendo interface EC2.
2. Implementar módulo security e três interfaces MCP.
3. Testar correlação, fuso, paginação, limites, segredo omitido, erros e descoberta stdio.
4. Documentar permissões e limites. Executar suíte e smoke MCP; teste AWS depende da validade do acesso local.

A skill writing-plans não foi localizada no catálogo; o plano foi registrado diretamente após aprovação do usuário. Nenhum dado operacional de cliente entra no Git. A aprovação do escopo autoriza implementação; publicação e atualização do cliente são registradas separadamente.
