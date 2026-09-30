# Plano executado — EKS via SSM

Data: 2026-09-28.

O usuário ampliou o objetivo para investigação AWS CLI e validação interna por bastion e definiu SSM como transporte. A implementação segue essa autorização; não há SSH ou remediação automática. A skill writing-plans não está no catálogo desta sessão; o plano foi registrado diretamente, como no histórico anterior do projeto.

1. Adaptador AWS CLI: operações fixas, isolamento de profile, STS, AssumeRole, timeouts e paginação.
2. Receitas SSM: mapeamento exato da bastion, validação de identidade/alvo, kubeconfig temporário, coleta paginada, normalização e cancelamento remoto.
3. Coletores/analisadores: recursos AWS relacionados, Kubernetes, componentes e correlações; falhas parciais preservadas.
4. Ciclo assíncrono: iniciar, consultar e cancelar investigações; evidências limitadas e expiráveis; múltiplos clusters.
5. Integração MCP: preservar ferramentas EC2, registrar novas ferramentas e efeitos remotos corretos.
6. Validação: regressão EC2, cenários EKS offline, protocolo stdio real, dependências e empacotamento.
7. Documentação: README, cobertura, configuração e exemplos de IAM/RBAC; históricos cumulativos.

Critério de conclusão local: ferramentas integradas e testes aprovados, com limitações explícitas. Publicação, atualização do cliente fixado em commit e validação real são etapas separadas. Não declarar conectividade, permissões ou saúde real a partir dos testes simulados.
