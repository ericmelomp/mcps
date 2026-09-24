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
