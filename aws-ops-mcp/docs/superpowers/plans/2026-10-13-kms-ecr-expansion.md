# Continuação de segurança — KMS/ECR

Solicitação: prosseguir implementação das features pendentes. Desenho modular aprovado e autorização autônoma de testes/publicação preservados.

Alternativas: inventário amplo, extensão silenciosa das consultas existentes, ferramentas semânticas direcionadas. Escolhidas duas ferramentas independentes para manter seleção explícita, limites e cobertura clara.

Recorte: KMS metadata/rotação aplicável e ECR repositório/scan existente de digest. Excluir material criptográfico, policies brutas, novos scans, layers/manifest, Inspector enablement e conclusões de compliance/segurança integral. Comparar contas/regiões antes de cada consulta seguinte e validar retornos. Reutilizar executor e evidence store, sem novo framework.

Gates: inputs antes de autenticação; SDK parâmetros válidos; state/scan absent/stale/incomplete; dados fora de escopo; AccessDenied/throttling/expiração; material/textos secretos omitidos; nenhuma operação mutável; preservação das40 ferramentas anteriores; regressão, build, pip check, wheel/stdIO isolados e pacote GitHub antes de considerar cliente pronto.

Revisão: recorte alinhado ao backlog, contratos e exclusões explícitos. IAM exemplo preparado, não aplicado. Validação live e demais domínios seguem pendentes.
