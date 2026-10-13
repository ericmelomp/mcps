# Etapa1 — plano de execução aprovado

Autorização: “Manda bala” após desenho modular. Skill writing-plans não encontrada no catálogo/filesystem; plano registrado diretamente, sem novo bloqueio.

1. Preservar ferramentas e schema atuais; adicionar ReadContext com allowlist SDK, clientes por consulta, deadlines/paginação/calls, auditoria opt-in e erros sanitizados.
2. Implementar Organizations: inventory/account state, roots/OUs/parents, SCP/RCP metadata e herança observada, sem policy contents/effective IAM claims.
3. Implementar Cost Explorer: datas e janela explícitas, SERVICE, filtro default de conta autenticada, escopo payer explícito, moedas/Decimal e estimated; sem soma entre escopos.
4. Adicionar orquestração assíncrona de até4 aliases,2 consultas paralelas por job,2jobs ativos, TTL900s, API separada de EKS. Serviços iniciais globais: uma região de autenticação por alias, usage_region explícita em custos.
5. Expor quatro ferramentas novas; testar schema stdio e preservar descoberta antiga.
6. Validar erros/permissões/limites/isolações/segredos e regressão; build/smoke wheel fora do checkout; documentar fonte e gaps.

Cache: novas consultas são fresh. EvidenceStore mantém snapshots por900s; cache de consultas opcional não ativado. Não modificar infraestrutura/IAM nem cliente instalado. Nenhuma aceitação live pode ser afirmada por fixtures offline.
