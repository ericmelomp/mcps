# Etapa3 — primeira fatia direcionada

Autorização de continuidade sem novas perguntas. Reutilizar runtime/evidências, preservar inventário/health antigos. Adicionar quatro análises semânticas: EC2 explícito + EBS + métricas opcionais; quatro tipos de banco + PITR; bucket S3 com ExpectedBucketOwner e metadados seguros; recovery points AWS Backup com limiar solicitado. Não coletar conteúdo sensível, comandos guest, objetos, SQL ou realizar restore/probes. Testar negados/ausentes/erros de região e dono, serialização de datas, métricas faltantes e shapes SDK; regressão/build/smoke final.

Lacunas não concluídas ficam documentadas (ASG/Compute Optimizer, métricas de DB, EFS/FSx/backup policies e restore). Nenhum stub para serviços ainda não implementados.
