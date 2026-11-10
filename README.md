# Sentinel 2.0 — auditoria externa baseada em evidências

Aplicação web responsiva com função serverless `/api/scan`, pronta para Vercel.

## O que mudou

O Sentinel 2.0 amplia os testes de exposição e melhora a confirmação dos achados. Uma vulnerabilidade só entra como **CRITICAL** quando o endpoint responde HTTP 200 e o conteúdo retornado contém uma assinatura compatível com o artefato esperado. Respostas genéricas, páginas 404 disfarçadas e cabeçalhos ausentes não são promovidos a vulnerabilidades críticas.

Verifica, entre outros pontos, arquivos `.env`, metadados Git/Subversion, backups ZIP/TAR.GZ, dumps SQL, `.DS_Store`, credenciais Composer/npm, phpinfo, status Apache e Spring Actuator env. Também registra observações sobre cabeçalhos HTTP, CORS, cookies e listagem de diretórios. Essas observações não são automaticamente classificadas como críticas.

## Deploy na Vercel

1. Extraia o ZIP e importe a pasta `sentinel-v2` na Vercel ou envie-a a um repositório Git.
2. Em **Project → Settings → Environment Variables**, configure uma chave de IA:
   - OpenAI: `OPENAI_API_KEY`; opcional `OPENAI_MODEL` (padrão `gpt-6-luna`).
   - Ou Gemini: `GEMINI_API_KEY`; opcional `GEMINI_MODEL` (padrão `gemini-2.5-flash`).
3. Se ambas estiverem configuradas, OpenAI tem prioridade.
4. Faça o deploy e abra o endereço publicado.

A chave fica exclusivamente na função serverless, nunca no navegador. A cobrança da OpenAI e a do Gemini são independentes.

## Execução local

Requer Node.js 20+ e Vercel CLI:

```bash
npm install
npx vercel dev
```

## Limites e segurança

- Uso somente em domínios próprios ou com autorização documentada.
- Requisições HTTPS GET limitadas, com leitura máxima de 48 KiB por resposta e timeout por requisição.
- Sem login, força bruta, exploração de falhas, upload, alteração de dados ou varredura de portas.
- Bloqueia destinos que resolvem para endereços privados/locais e não segue redirecionamentos.
- A ausência de achados não prova que o domínio esteja seguro; caminhos personalizados, conteúdo autenticado, WAF e limites de leitura podem impedir a detecção. Os caminhos testados são conhecidos e não cobrem todas as aplicações ou falhas possíveis.
- Para auditoria completa, complemente com SAST, DAST autenticado autorizado, revisão de código e pentest profissional.
- Configure proteção contra abuso/rate limiting na Vercel ou WAF antes de disponibilizar publicamente. Limites em memória de funções serverless não são confiáveis.

## Arquivos

- `api/scan.js`: motor de auditoria e resumo opcional por IA.
- `app.js`, `index.html`, `styles.css`: interface.
- `vercel.json`: configuração de função e cabeçalhos.
- `.env.example`: variáveis de ambiente de exemplo.
