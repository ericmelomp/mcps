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
