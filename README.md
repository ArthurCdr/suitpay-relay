# SuitPay relay

Backend Node.js 20+ / Express que encaminha pagamentos Pix à SuitPay e registra todos os acessos HTTP em `public.info09_pix_requests` no Supabase. Cada acesso ocupa uma linha própria, identificada por `record_type = relay_request`; os registros de saque existentes permanecem com `record_type = payout`.

## Configuração

1. Execute `npm ci`.
2. Copie `.env.example` para `.env` e configure `RELAY_SECRET`, `SUPABASE_URL` e `SUPABASE_SECRET_KEY` (chave secreta de servidor). Também aceita a chave legada em `SUPABASE_SERVICE_ROLE_KEY`. Nunca use chave pública nem exponha essas variáveis no frontend.
3. Configure `AUDIT_SPOOL_DIR` em um **volume persistente**, exclusivo por processo/réplica, com permissão de escrita. Sem volume persistente, registros pendentes podem ser perdidos ao recriar o container.
4. Inicie com `node --env-file=.env index.js`. Em produção, com variáveis injetadas pelo provedor, use `npm start`.

As migrations versionadas adicionam os campos de auditoria à tabela existente, preservam a validação dos saques e transferem os logs da antiga tabela separada, que é removida. Elas já foram aplicadas ao projeto `uaqrztydzdfjrlefaald`. Para outro projeto, a tabela de negócio `info09_pix_requests` deve existir com seu schema original; aplique as migrations em `supabase/migrations/` na ordem antes de iniciar. A autenticação MCP do Codex não fornece credenciais ao processo Node.js.

O serviço recusa iniciar sem as variáveis obrigatórias. Configure-as **antes de publicar esta versão**. Se a fila não puder registrar uma nova requisição em disco, o relay retorna 503 antes de executar a operação.

## Rotas

- `POST /pix-payment`: cabeçalho `x-relay-secret`; JSON com `ci`, `cs` e `payload`. Encaminha o payload e preserva o status HTTP da SuitPay. Falhas de rede/JSON e timeout retornam 502. O timeout não comprova que o pagamento falhou; confira na SuitPay antes de tentar novamente.
- `GET /test-pix`: **solicita um Pix real de R$ 0,10 para a chave fixa do código**. Mantém a autenticação legada por `?secret=...`, e credenciais `SUITPAY_CI`/`SUITPAY_CS` ou query. Evite credenciais em URLs, pois proxies podem registrá-las. Com filtro de domínio ativo, chamadas de servidor precisam também do cabeçalho `x-relay-secret`.
- `GET /health`: liveness do processo (não indica disponibilidade do Supabase).
- `GET /my-ip`: IP público de saída.

`ALLOWED_DOMAINS` permite domínios e subdomínios; vazio desativa o filtro. A chave secreta continua obrigatória para pagamentos. O segredo correto no cabeçalho permite chamadas servidor-servidor.

## Auditoria e recuperação

Linhas de auditoria têm `payout_status = NULL` e dados de Pix no JSON `request_body`/`response_body`, evitando que um acesso seja interpretado como saque pendente. Consultas de negócio devem filtrar `record_type = payout`; consultas de auditoria, `record_type = relay_request`. Filas em disco de versões anteriores também são enviadas à tabela consolidada.

Cada requisição que chega ao Express ganha UUID próprio no cabeçalho `X-Request-Id`, inclusive bloqueios, OPTIONS, diagnósticos, rotas inexistentes, JSON inválido e corpos grandes demais. São gravados método, caminho, query sanitizada, IP do socket, origem, corpo JSON sanitizado, resposta JSON sanitizada, status HTTP, status da SuitPay, duração e código de erro.

A fila salva um registro inicial em disco antes de processar, com gravação atômica e fsync. Na conclusão, atualiza o registro. Um worker envia ao Supabase por upsert em `session_id` (UUID do acesso); reenvios não duplicam registros nem executam pagamentos. Erros de sincronização são informados no stderr e mantêm os arquivos para a próxima tentativa (a cada 5 segundos). Monitore esses erros e o espaço em disco.

Estados: `received`, `success`, `blocked`, `error`, `aborted`, `interrupted`. `success` significa resposta HTTP bem-sucedida, **não confirmação de liquidação do Pix**. Após reinício, registros incompletos são marcados `interrupted`, pois o resultado da operação pode ser desconhecido. Desconexões registram `aborted`. Não há garantia de capturar tráfego bloqueado antes do Node.js, falha total de disco ou o resultado final após queda do processo.

Credenciais, cookies e autorização não são armazenados. Headers são restritos a origem/referer sem query. Corpos inválidos não são armazenados em formato bruto. Valores longos, arrays e objetos têm limites de tamanho/profundidade para a auditoria. Dados de Pix e outros dados pessoais presentes no payload ainda podem constar dos registros; o acesso da tabela é exclusivo do backend (`service_role`), sem leitura pública. Não há retenção/expurgo automático nesta versão.

## Verificação

Execute `npm test`. Os testes simulam SuitPay e Supabase: não fazem pagamentos reais. Cobrem 200/204/400/401/403/404/413/422/502, remoção de segredos, desconexão e recuperação da fila após indisponibilidade/reinício.
