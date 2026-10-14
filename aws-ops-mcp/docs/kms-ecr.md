# Segurança KMS/ECR — 0.14.0

`kms_key_assessment(account, region, key_arn)` exige ARN de uma chave da conta/região autenticada. Consulta estado, origem, manager, uso e spec. Rotação automática é consultada somente para chaves CUSTOMER, SYMMETRIC_DEFAULT, ENCRYPT_DECRYPT, AWS_KMS fora de custom stores. Demais tipos não recebem alerta falso de rotação desabilitada. Estado diferente de Enabled é observado; não comprova impacto em workloads. Rotação configurada não demonstra histórico de rotação manual nem compliance.

Não consulta policies/grants, aliases, material criptográfico ou tags/descrições brutas. Não usa Encrypt/Decrypt, geração de data keys, mudanças de estado ou rotação. Policy/SCP efetiva, disponibilidade do custom store e aceite criptográfico continuam fora do escopo. AccessDenied mantém metadados coletados e marca resultado parcial.

`ecr_image_assessment(account, region, repository_name, image_digest, maximum_age_hours=168)` exige repositório privado e digest sha256 explícito. Consulta repositório da conta e resultados existentes de scan. Retorna status, contagens agregadas por severidade e idade do último scan concluído. Estado COMPLETE/ACTIVE com contagens e timestamp observados pode completar a coleta, mas nunca comprova imagem segura.

Obtém somente uma página de detalhes, maxResults=1. As contagens vêm do agregado AWS e não dessa amostra; o token de continuação é informado, detalhes ficam excluídos e não são devolvidos. Não consulta manifests/layers, não faz pull, não habilita Inspector nem inicia scan. Missing scan, estado pendente/erro, contagens/timestamp ausentes e permissão negada resultam em evidência parcial. Enhanced scanning ACTIVE sem timestamp de conclusão é parcial conservador. ZERO findings observados não equivale a ausência de vulnerabilidades.

Idade máxima é critério explícito do operador, não SLA AWS. HIGH/CRITICAL e scan antigo geram sinais rastreáveis. Mutabilidade/exceções de tags são configuração observada, sem alegar comprometimento. Não associa automaticamente digest a pods ECS/EKS.

Exemplos sintéticos:

```json
{"account":"sandbox","region":"us-east-1","key_arn":"arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"}
```

```json
{"account":"sandbox","region":"us-east-1","repository_name":"demo","image_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","maximum_age_hours":168}
```

Permissões em `config/kms-ecr-read-policy.example.json` são exemplo não aplicado. STS, allowlist, limites, auditoria metadata-only, envelope e evidence_get reutilizam a plataforma. Validação offline e stdio não substitui validação AWS real.

Fontes oficiais revisadas em 13/10/2026:

- [KMS DescribeKey](https://docs.aws.amazon.com/boto3/latest/reference/services/kms/client/describe_key.html)
- [KMS GetKeyRotationStatus](https://docs.aws.amazon.com/boto3/latest/reference/services/kms/client/get_key_rotation_status.html)
- [ECR DescribeImageScanFindings](https://docs.aws.amazon.com/boto3/latest/reference/services/ecr/client/describe_image_scan_findings.html)

Pendências: análise efetiva de policies/grants/SCP, Inspector/Macie/Config, detalhes de vulnerabilities, signatures/SBOM, mapeamento de workloads e aceite real.
