# Acesso temporário fornecido ao agente

Quando instalado pelo GitHub/uvx, use `aws-ops-import-credentials` com o mesmo commit do servidor e `--config ~/.aws/aws-ops-mcp/accounts.json` (expandir para caminho absoluto). Veja [instalação pelo GitHub](github-install.md). O `accounts.local.json` citado abaixo é a alternativa do checkout de desenvolvimento.

## Experiência do usuário

Forneça o nome da conta e o conjunto de Access Key, Secret Key e Session Token, junto do pedido de análise. Pode fornecer vários conjuntos, cada um identificado. O agente prepara o acesso local e utiliza as ferramentas do MCP. Não é necessário criar profiles nem editar JSON manualmente.

Exemplo de pedido, sem valores reais:

```text
Conta: desenvolvimento
AWS_ACCESS_KEY_ID: <valor>
AWS_SECRET_ACCESS_KEY: <valor>
AWS_SESSION_TOKEN: <valor>

Conta: produção
AWS_ACCESS_KEY_ID: <outro valor>
AWS_SECRET_ACCESS_KEY: <outro valor>
AWS_SESSION_TOKEN: <outro valor>

Verifique as EC2 das duas contas em us-east-1.
```

A região vem do pedido, não da credencial. Se faltar a região e ela não estiver definida no contexto, o agente pergunta. Apelidos com espaços ou acentos são convertidos em aliases simples e essa associação é informada ao usuário.

Credenciais enviadas na conversa fazem parte dela. O importador não repete os valores na saída, mas não remove mensagens nem controla a retenção do cliente de IA. Para fornecer os valores fora da conversa, também é possível usar entrada local via stdin.

## O que o agente faz

1. Converte os conjuntos recebidos para o formato de entrada abaixo. Nunca executa comandos shell colados pelo usuário apenas para extrair credenciais.
2. Chama o importador com JSON em stdin; não coloca segredos nos argumentos de linha de comando, documentos ou histórico do projeto.
3. O importador verifica cada identidade via STS `GetCallerIdentity`, usando os três valores explícitos. Todas as identidades são validadas antes de gravar os arquivos.
4. Cria/atualiza profiles exclusivos em `~/.aws/aws-ops-mcp/credentials`, separado do repositório e do arquivo padrão `~/.aws/credentials`.
5. Atualiza `accounts.local.json` com alias, ID verificado, regiões, nome do profile e caminho do arquivo. Esse JSON não recebe Access Key, Secret Key ou Session Token.
6. Executa `ec2_inventory` ou `ec2_health` com alias e região. O MCP verifica novamente a identidade antes de consultar EC2.

Um alias existente não pode mudar de Account ID durante uma renovação. Para outra conta, usar outro alias. As regiões do lote substituem as regiões permitidas daquele alias, portanto incluir todas as regiões necessárias ao pedido. Registros e profiles de outras contas são preservados.

O arquivo de profiles guarda as credenciais em texto local, no formato padrão do SDK. Em Windows, herda as permissões da pasta de usuário; em POSIX, o arquivo é criado com acesso restrito ao usuário. Não há sincronização ou envio desse arquivo ao Git.

## Contrato para o agente

Com o ambiente instalado, executar:

```text
python -m aws_ops_mcp.import_credentials --config <caminho-absoluto/accounts.local.json>
```

Fornecer em stdin, com os valores recebidos do usuário:

```json
{
  "accounts": [
    {
      "alias": "desenvolvimento",
      "regions": ["us-east-1"],
      "aws_access_key_id": "<valor>",
      "aws_secret_access_key": "<valor>",
      "aws_session_token": "<valor>"
    }
  ]
}
```

`account_id` é opcional na entrada. Quando informado, precisa corresponder à identidade verificada. Credenciais incompletas, inválidas ou vencidas impedem a importação. Valores nunca aparecem na resposta do importador; a saída inclui apenas aliases, Account IDs e regiões ou códigos de erro.

O importador é um comando local do agente, não uma nova ferramenta MCP. As quatro ferramentas de análise continuam iguais. Clientes que não permitem execução local precisam de um operador local para importar as credenciais.

## Renovação e falhas

Forneça novas credenciais para o mesmo alias quando expirarem. O importador substitui o profile correspondente. Como cada consulta inicia uma sessão nova, consultas seguintes utilizam os valores atualizados sem reinstalar o MCP. Uma consulta que já esteja em andamento pode continuar com a sessão anterior.

Não há renovação automática de credenciais coladas nem remoção automática dos valores ao expirar. Falhas de autenticação não causam fallback para outra conta. O suporte existente a profiles SSO e AssumeRole continua disponível para contas configuradas manualmente.

Importações simultâneas são recusadas por um lock. Se o processo for interrompido abruptamente, pode restar `~/.aws/aws-ops-mcp/credentials.import.lock`; só removê-lo depois de confirmar que não há importação ativa. As duas gravações são individualmente atômicas, não uma transação conjunta: se a segunda falhar, repetir a importação após corrigir o problema local.

## Verificação

30 testes offline passaram após esta alteração, incluindo duas contas, renovação isolada, Account ID divergente, lote com token expirado, substituição do template inicial, rejeição de entrada inválida e carregamento do Session Token pelo mesmo caminho utilizado nas consultas EC2. Nenhuma credencial real foi usada.

Referência: [credenciais no Boto3](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html).
