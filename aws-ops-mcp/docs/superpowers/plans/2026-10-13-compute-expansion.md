# Continuação de compute — desenho aprovado por módulos

Solicitação: continuar implementação das novas features; autorização anterior para execução autônoma e publicação preservada. Recorte do backlog de compute: ASG e recomendações EC2 do Compute Optimizer. Não requer novos serviços mutáveis ou coleta remota SSM.

Alternativas: estender o inventário EC2, acrescentar ferramentas semânticas direcionadas, ou consultar toda a conta. Escolhida a segunda: contratos independentes, seleções explícitas e testes específicos; evita ampliar o custo/volume do inventário existente.

Plano: collectors limitados; validação antes de autenticar; APIs em allowlist; facade existente; duas ferramentas aditivas; permissões de exemplo; documentação/catálogo; testes de unidades ponderadas, isolamento, dados faltantes, segredos, SDK parameters e protocolo; regressão/build/pip check/wheel isolado antes da publicação.

Critérios: preservar 38 ferramentas anteriores, distinguir unidades de instâncias, composição real EC2, recomendações ausentes não positivas, freshness explícita, sem economia ou causa raiz inventadas, sem mutação AWS. Revisão do desenho: sem campos pendentes; validação live continua fora desta implementação offline.
