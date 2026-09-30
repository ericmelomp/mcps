# Repositório mcps

- Cada MCP deve ficar em uma pasta própria, com o nome do projeto.
- Ler o AGENTS.md do MCP antes de trabalhar nele.
- Manter histórico cumulativo. Separar ações concluídas de planos.
- Não misturar dados, credenciais ou históricos de clientes entre projetos.

## Histórico

### 2026-09-24
- Solicitação: adicionar AWS Ops MCP em uma pasta separada dentro deste repositório.
- Concluído: repositório localizado e inspecionado; continha README.md e estava sem alterações. Criado este AGENTS.md e documentação do projeto em aws-ops-mcp.
- Pendente: revisão da especificação e implementação do MCP. Nenhuma conexão AWS realizada.

### 2026-09-24 — AWS Ops MCP implementado
- Solicitação: prosseguir após aprovação da especificação.
- Concluído: primeira versão em aws-ops-mcp, quatro ferramentas somente leitura, documentação e 20 testes offline aprovados.
- Resultado: comunicação MCP stdio validada localmente; nenhum outro projeto alterado. Detalhes no AGENTS.md do MCP.
- Pendente: configuração real de conta AWS e cliente MCP. Sem commit ou push.

### 2026-09-24 — Documentação das capacidades
- Solicitação: visão clara do poder do AWS Ops MCP no README.
- Concluído: README raiz com catálogo e README do projeto com exemplos, capacidades atuais, economia medida, expansão assistida e possibilidades futuras.
- Verificado: links locais e blocos Markdown. Nenhum código alterado; conexão AWS real continua pendente.

### 2026-09-24 — Publicação solicitada
- Solicitação: fazer push do AWS Ops MCP.
- Concluído: revisados escopo, remoto origin (github.com/ericmelomp/mcps), branch main e histórico; remoto consultado. Validação existente: 20 testes offline aprovados, sem mudanças posteriores no código.
- Autorizado: commit da primeira versão, testes e documentação; envio normal para origin/main.
- Planejado: commit feat(aws-ops-mcp): add read-only EC2 diagnostics e push. Resultado final do envio registrado no AGENTS.md da pasta de trabalho externa ao repositório e verificável pelo histórico Git.

### 2026-09-24 — Acesso temporário assistido
- Solicitação: utilizar credenciais temporárias nomeadas de uma ou várias contas sem configuração manual pelo usuário.
- Concluído: AWS Ops MCP ampliado com importador local, profiles automáticos, documentação e 30 testes offline aprovados. Servidor registrado no Codex local.
- Pendente: recarregar cliente, receber credenciais reais e executar análise solicitada. Sem novo commit/push.

### 2026-09-24 — Origem GitHub para o AWS Ops MCP
- Solicitação: carregar do GitHub e executar localmente sem depender do checkout.
- Concluído: documentação e entrypoint de importação preparados; dados de contas separados da pasta do projeto.
- Planejado: publicar versão atualizada e configurar uvx com commit fixo após validar carregamento remoto. Sem envio de credenciais ou configuração de contas ao GitHub.

### 2026-09-28 — AWS Ops MCP ampliado para EKS/SSM
- Solicitação: análise EKS pela AWS CLI e validação interna por bastion SSM.
- Concluído: extensão local 0.2.0 em aws-ops-mcp com cinco novas ferramentas, investigação assíncrona, evidências e exemplos de acesso. Catálogo atualizado.
- Verificado: 60 testes offline e smoke test do wheel por MCP stdio com nove ferramentas. Histórico detalhado em aws-ops-mcp/AGENTS.md.
- Pendente: validação real, publicação e atualização do cliente instalado. Sem commit/push ou alteração de contas/infraestrutura.

### 2026-09-28 — Validação real da extensão EKS
- Solicitação: testar AWS Ops MCP diretamente na conta autorizada, incluindo bastion SSM.
- Concluído: fluxo local AWS/Kubernetes validado em um cluster; corrigidos endpoints nulos e truncamento de evidências com transporte comprimido e paginação consistente. 66 testes aprovados e wheel atualizado.
- Resultado: coleta final sem lacunas; achados operacionais e credenciais mantidos fora do repositório. Histórico detalhado em aws-ops-mcp/AGENTS.md.
- Pendente: publicação e atualização do cliente. Sem commit/push ou remediação de infraestrutura.

### 2026-09-29 — Extensão CloudFront/ELB
- Solicitação: ampliar AWS Ops MCP para diagnóstico gRPC.
- Concluído: versão local 0.3.0 com duas novas ferramentas somente leitura; 11 ferramentas totais. Código EKS/SSM anterior preservado. Documentação e exemplo IAM incluídos, sem aplicação de permissões.
- Verificado: 86 testes, dependências e diff; pacote validado por MCP stdio fora do checkout. Teste operacional bloqueado por autenticação expirada.
- Pendências: acesso renovado e alvo para diagnóstico; publicação e atualização do cliente. Sem commit/push ou alteração de infraestrutura.


### 2026-09-30 ? Prepara??o da publica??o 0.3.0
- Solicita??o: fazer push da MCP e utiliz?-la a partir do GitHub.
- Conclu?do: conferidos origin/main e altera??es das extens?es EKS/SSM e CloudFront/ELB; documenta??o de capacidades e instala??o atualizada. 86 testes aprovados e pip check sem conflitos.
- Valida??o operacional anterior: ferramentas CloudFront/ELB foram usadas em conta autorizada ap?s renova??o de acesso; evid?ncias operacionais permanecem fora do Git. Isso n?o comprova sa?de funcional.
- Autorizado e planejado: commit/push normal para origin/main, teste do pacote obtido do GitHub fora do checkout e atualiza??o do commit fixado no cliente. N?o hospedar credenciais ou endpoint remoto no GitHub.
- Resultado da publica??o/configura??o ser? registrado no hist?rico externo ao reposit?rio para manter a ?rvore publicada limpa.
