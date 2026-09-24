# Procedimento de expansão assistida

Este é um procedimento para o agente com acesso ao repositório. Não é um agente embutido no servidor nem uma skill instalada automaticamente.

1. Consultar `capabilities` antes de diagnosticar um serviço novo.
2. Se uma análise não existir, informar a lacuna. Nunca substituir silenciosamente por uma análise diferente.
3. Se as evidências existentes bastarem, consultar somente as páginas necessárias e apresentar a interpretação como inferência da IA.
4. Caso contrário, registrar a nova análise no desenho: entrada, APIs de leitura, campos necessários, cobertura, falhas e permissões. Não adicionar executor genérico de comandos.
5. Implementar coletor e analisador separados. Reutilizar identidade, limites de saída, deadline e cache. Novos módulos ficam no pacote deste MCP, sem modificar outros projetos.
6. Testar sucesso, acesso negado, dados ausentes, paginação, truncamento e timeout. Testes offline não usam contas reais. Qualquer ação de escrita exige desenho específico e autorização, fora da primeira entrega.
7. Registrar ferramenta e atualizar `capabilities`, política IAM de exemplo, README e AGENTS.md somente depois dos testes.
8. Reiniciar o servidor e reconectar o cliente para disponibilizar a nova capacidade. Registrar o que foi realmente validado. Mudanças IAM são separadas de mudanças de código.

Não há aprendizado persistente ou autoexpansão só por chamar uma ferramenta. O crescimento ocorre pela alteração versionável de código, feita pelo agente desenvolvedor no fluxo autorizado pelo usuário.
