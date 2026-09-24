# AWS Ops MCP — primeira entrega

Data: 2026-09-24. Status: especificação aprovada pelo usuário; primeira entrega implementada e validada offline.

## Objetivo

Mover coleta repetitiva e análises determinísticas para código Python. A IA recebe resultados pequenos com cobertura e evidências, sem precisar interpretar toda a resposta das APIs. Não há promessa percentual de economia antes de medir.

## Abordagens

1. Ferramentas semânticas e expansão assistida: recomendada e aceita como direção. Mais trabalho inicial por capacidade, com reaproveitamento nas próximas consultas.
2. Executor genérico de CLI: flexível, mas mantém decisões e grandes resultados na conversa. Não será a interface da primeira entrega.
3. Servidor que gera e instala seu próprio código: exige isolamento e controle adicionais. Fora desta entrega; desenvolvimento fica em um agente separado.

## Escopo proposto

Servidor local via stdio, Python, SDK MCP e boto3. Sem LLM interno. Primeiro módulo EC2, somente leitura, como escolha inicial proposta. EC2 valida autenticação, paginação, cobertura, evidências e economia antes de incluir Kubernetes ou custos.

Ferramentas previstas:

- `capabilities`: lista serviços e análises suportados e suas limitações, sem consultar AWS.
- `ec2_inventory`: consulta uma conta e região explícitas, retorna totais e uma amostra limitada de instâncias.
- `ec2_health`: consulta estado e status checks de instâncias; sinaliza falhas observadas. Não representa diagnóstico de aplicações, rede ou métricas históricas.
- `evidence_get`: recupera páginas limitadas de evidência normalizada de uma consulta anterior, por identificador opaco e com limite imposto pelo servidor.

## Componentes e fluxo

Adaptador MCP valida entradas e chama serviços Python testáveis. Configuração resolve alias de conta. Camada de autenticação cria sessão boto3. Coletores consultam APIs e paginam dentro de limites. Analisadores determinísticos geram achados. Formatador limita saída e registra cobertura. Armazenamento temporário em memória mantém evidências normalizadas por 15 minutos, até 100 consultas e 20 MiB totais; descarta as mais antigas ao atingir os limites.

Configuração local mapeia alias para account ID esperado, profile de origem, região permitida e role ARN opcional. Sem chaves no arquivo. Usa credenciais obtidas pelo mecanismo padrão do SDK; login externo deve ocorrer previamente quando necessário. AssumeRole só ocorre se configurado. Validar identidade da sessão final antes de consultar EC2; divergência de conta interrompe a consulta. Uma consulta não troca automaticamente de conta ou região em caso de erro.

## Contrato de resposta

Cada resultado inclui `schema_version`, `account`, `region`, `collected_at`, `status`, `summary`, `findings`, `coverage`, `errors` e `evidence_id` quando houver evidências.

`status` distingue `ok`, `degraded`, `partial`, `error` e `unsupported`. `ok` significa somente que os checks declarados foram concluídos sem achados; não significa saúde global da conta. Em resultados parciais, preservar achados já observados e explicar os checks ausentes.

`coverage` informa análises executadas, itens examinados, término da paginação e truncamentos. Contagens parciais nunca aparecem como totais completos. Instâncias paradas não são automaticamente falhas; status checks não aplicáveis ou indisponíveis ficam explícitos.

Resumo padrão limitado a 12 KiB de JSON UTF-8; até 20 achados ou amostras por resposta. Evidência paginada limitada a 50 itens e 24 KiB por chamada. Truncamento reduz listas e detalhes sem apagar campos de cobertura e erro. Coleta limitada a 100 páginas por operação e deadline total de 60 segundos, com timeouts de rede e tentativas limitadas. Limite atingido retorna `partial`.

Erros são normalizados: autenticação expirada, acesso negado, conta divergente, throttling, timeout e configuração inválida. Não devolver stack traces ou credenciais ao cliente. Logs operacionais vão para stderr; stdout é reservado ao protocolo MCP.

Evidências contêm apenas campos selecionados para a análise. Não coletar user data ou tags arbitrárias. IDs de infraestrutura podem ser sensíveis; documentação deve indicar que resultados enviados à IA saem do processo local. Identificadores de evidência expiram e não aceitam caminhos de arquivos.

## Extensão assistida

O agente consulta `capabilities`. Quando dados existentes bastarem, pode interpretá-los explicitando a inferência. Quando faltarem dados ou análise, informa a lacuna. O servidor nunca inventa um diagnóstico para uma análise ausente.

Um procedimento versionado orientará o agente desenvolvedor a definir contrato e permissões necessárias, implementar coletor ou analisador, adicionar testes e registrar a capacidade. Código validado entra em uma nova execução do servidor. O catálogo deve refletir apenas ferramentas realmente implementadas. O cliente pode precisar reconectar para reconhecer novas ferramentas.

Não inclui agente autônomo embutido, hot reload de código gerado, instalação automática nem concessão de IAM. Uso pontual de ferramentas externas depende da disponibilidade e autorização do ambiente consumidor.

## Fora desta entrega

Alterações AWS, role operacional, EKS/Karpenter, Terraform, rede, custos, GitLab CI/CD, servidor remoto e isolamento multiusuário. A arquitetura permite adicionar esses módulos depois, sem declarar suporte antecipado.

## Validação e aceite

- Testes offline com respostas simuladas verificam paginação, falhas de permissão, sessão de conta errada, status checks, limites e evidência expirada.
- Integração local verifica inicialização MCP, descoberta e chamada de ferramentas sem AWS real.
- Casos de coleta interrompida preservam achados e nunca retornam `ok`.
- Comparação reproduzível mede bytes UTF-8 de entradas normalizadas versus resumo usando o mesmo conjunto de dados. Bytes são proxy, não contagem exata de tokens nem economia líquida de uma conversa.
- Documentar instalação, configuração de exemplo sem contas reais, permissões mínimas das APIs efetivamente usadas e procedimento de extensão.
- Smoke test real depende de conta, região e autenticação disponíveis; não bloquear testes offline nem afirmar validação AWS sem execução.

## Próximos passos

Base e módulo EC2 implementados. Próximo passo: configurar um ambiente AWS escolhido pelo usuário e conectar o cliente MCP.

## Detalhes consolidados na implementação

- Limite adicional de 10.000 instâncias por consulta para limitar memória; excedê-lo gera resultado parcial.
- Processo isolado impõe deadline de 60 segundos incluindo autenticação; limpeza do processo pode acrescentar até dois segundos.
- Respostas são texto JSON para não duplicar o mesmo conteúdo em campos textual e estruturado do protocolo.
- Até 20 amostras e 20 achados por resumo, sempre subordinados ao orçamento de 12 KiB.
- MCP SDK 1.x explicitamente limitado a versões menores que 2; dependências testadas registradas em arquivo próprio.
- Eventos marcados pela AWS como concluídos não geram alerta ativo; EBS não aplicável não vira falha.
