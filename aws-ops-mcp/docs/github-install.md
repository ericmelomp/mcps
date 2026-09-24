# Carregar do GitHub sem depender do checkout

O código vem de `https://github.com/ericmelomp/mcps`, subpasta `aws-ops-mcp`. O uvx baixa o pacote e o executa em um ambiente isolado no cache local. A pasta clonada e seu `.venv` não são necessários para usar o MCP. A execução e as credenciais continuam neste computador.

## Configuração Codex

Exemplo de `config.toml`; substituir `SEU_USUARIO` e `COMMIT_VALIDADO`. É necessário ter uv/uvx e Git disponíveis no ambiente do cliente.

```toml
[mcp_servers.aws-ops-mcp]
command = "uvx"
args = ["--from", "git+https://github.com/ericmelomp/mcps.git@COMMIT_VALIDADO#subdirectory=aws-ops-mcp", "aws-ops-mcp"]
startup_timeout_sec = 120
tool_timeout_sec = 75

[mcp_servers.aws-ops-mcp.env]
AWS_OPS_CONFIG = "C:/Users/SEU_USUARIO/.aws/aws-ops-mcp/accounts.json"
```

Uma referência fixa de commit mantém a versão escolhida até a próxima atualização. Para atualizar, publicar/testar a nova versão e trocar o commit na configuração. Usar `@main` é possível, mas pode exigir `--refresh-package aws-ops-mcp` para atualizar o cache; não é a configuração fixa acima.

O primeiro uso baixa código e dependências; precisa de acesso ao GitHub e ao índice de pacotes. O uv gerencia os arquivos de cache. O timeout maior de inicialização acomoda esse primeiro carregamento.

## Dados locais independentes

- `~/.aws/aws-ops-mcp/accounts.json`: aliases, IDs verificados, profiles e regiões.
- `~/.aws/aws-ops-mcp/credentials`: credenciais temporárias importadas.

O agente importa as credenciais usando o mesmo commit do servidor e JSON em stdin:

```powershell
$awsOpsSource = 'git+https://github.com/ericmelomp/mcps.git@COMMIT_VALIDADO#subdirectory=aws-ops-mcp'
uvx --from $awsOpsSource aws-ops-import-credentials --config "$env:USERPROFILE\.aws\aws-ops-mcp\accounts.json"
```

Não colocar segredos nos argumentos. Para o formato de entrada, consulte [acesso temporário](temporary-access.md). O helper cria o arquivo de contas se ele não existir. O servidor pode responder a `capabilities` antes de qualquer conta ser cadastrada.

O clone continua útil para desenvolver novos módulos, mas não participa da inicialização do MCP. Para a expansão assistida, alterar e testar o código no clone, publicar a versão e atualizar o commit configurado no cliente.

Referência: [ambientes de ferramentas do uv](https://docs.astral.sh/uv/concepts/tools/).
