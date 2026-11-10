import dns from "node:dns/promises";
import net from "node:net";

const USER_AGENT = "Sentinel-Authorized-Audit/2.0";
const MAX_BODY = 48 * 1024;
const TIMEOUT_MS = 5500;
const CONCURRENCY = 4;

// A finding becomes CRITICAL only when a public response returns HTTP 200
// and its body contains a strong marker for the exposed artifact.
const PROBES = [
  // Secrets and configuration files: CRITICAL only when secret-like values appear.
  ...['/.env','/.env.local','/.env.production','/.env.development','/.env.backup','/.env.old','/.env.save','/config/.env','/app/.env'].map(path => ({path,label:'Arquivo de ambiente exposto',kind:'secrets',impact:'Pode expor credenciais de banco, nuvem e serviços externos.'})),
  {path:'/.npmrc',label:'Token npm exposto',kind:'npm',impact:'Pode permitir acesso ou publicação em pacotes privados.'},
  {path:'/composer.auth.json',label:'Credenciais Composer expostas',kind:'composer',impact:'Pode expor tokens de repositórios e pacotes privados.'},
  {path:'/credentials.json',label:'Arquivo de credenciais exposto',kind:'jsonsecrets',impact:'Pode expor credenciais de serviços e contas de aplicação.'},
  {path:'/service-account.json',label:'Chave de conta de serviço exposta',kind:'serviceaccount',impact:'Pode permitir acesso a recursos vinculados à conta de serviço.'},
  {path:'/.aws/credentials',label:'Credenciais AWS expostas',kind:'aws',impact:'Pode permitir acesso à conta AWS conforme as permissões da chave.'},
  {path:'/wp-config.php',label:'Configuração WordPress exposta',kind:'wpconfig',impact:'Pode expor credenciais do banco de dados WordPress.'},
  {path:'/config.php',label:'Arquivo de configuração PHP exposto',kind:'phpconfig',impact:'Pode revelar credenciais e segredos da aplicação.'},
  {path:'/config.yml',label:'Arquivo de configuração YAML exposto',kind:'yamlconfig',impact:'Pode revelar credenciais e parâmetros internos.'},
  {path:'/config/database.yml',label:'Configuração de banco Rails exposta',kind:'yamlconfig',impact:'Pode revelar credenciais e nomes de bancos de dados.'},
  {path:'/id_rsa',label:'Chave privada SSH exposta',kind:'privatekey',impact:'Pode permitir autenticação indevida em sistemas que confiem nessa chave.'},
  {path:'/.ssh/id_rsa',label:'Chave privada SSH exposta',kind:'privatekey',impact:'Pode permitir autenticação indevida em sistemas que confiem nessa chave.'},
  {path:'/private.key',label:'Chave privada exposta',kind:'privatekey',impact:'Pode comprometer serviços que utilizem essa chave.'},
  {path:'/database.sql',label:'Dump SQL público',kind:'sql',impact:'Pode expor estrutura e registros do banco de dados.'},
  {path:'/db.sql',label:'Dump SQL público',kind:'sql',impact:'Pode expor estrutura e registros do banco de dados.'},
  {path:'/dump.sql',label:'Dump SQL público',kind:'sql',impact:'Pode expor estrutura e registros do banco de dados.'},
  {path:'/backup.sql',label:'Backup SQL público',kind:'sql',impact:'Pode expor estrutura e registros do banco de dados.'},
  {path:'/backup.zip',label:'Backup ZIP público',kind:'zip',impact:'Pode permitir baixar cópias de segurança com dados ou código interno.'},
  {path:'/backup.tar.gz',label:'Backup TAR.GZ público',kind:'gzip',impact:'Pode permitir baixar cópias de segurança com dados ou código interno.'},
  {path:'/site-backup.zip',label:'Backup do site público',kind:'zip',impact:'Pode expor arquivos e dados internos.'},
  {path:'/www.zip',label:'Arquivo compactado do site público',kind:'zip',impact:'Pode expor código-fonte e arquivos internos.'},
  // Source-control metadata and operational consoles.
  {path:'/.git/config',label:'Configuração interna do Git exposta',kind:'gitconfig',impact:'Pode revelar repositórios e facilitar recuperação do código-fonte.'},
  {path:'/.git/HEAD',label:'Metadados do repositório Git expostos',kind:'githead',impact:'Confirma exposição de metadados internos do repositório.'},
  {path:'/.git/index',label:'Índice do repositório Git exposto',kind:'gitindex',impact:'Pode revelar nomes e estrutura de arquivos versionados.'},
  {path:'/.svn/entries',label:'Metadados Subversion expostos',kind:'svn',impact:'Pode revelar estrutura e metadados do código versionado.'},
  {path:'/.svn/wc.db',label:'Banco interno Subversion exposto',kind:'sqlite',impact:'Pode revelar caminhos e metadados do código versionado.'},
  {path:'/.DS_Store',label:'Índice de diretório macOS exposto',kind:'dsstore',impact:'Pode revelar nomes de arquivos e caminhos internos.'},
  {path:'/phpinfo.php',label:'Página phpinfo pública',kind:'phpinfo',impact:'Pode revelar versões, caminhos, variáveis e configuração interna.'},
  {path:'/server-status',label:'Status interno Apache público',kind:'apachestatus',impact:'Pode revelar requisições, clientes e detalhes operacionais.'},
  {path:'/actuator/env',label:'Spring Actuator env público',kind:'actuatorenv',impact:'Pode revelar variáveis e propriedades do ambiente da aplicação.'},
  {path:'/actuator/configprops',label:'Spring Actuator configprops público',kind:'actuatorconfig',impact:'Pode revelar configurações internas da aplicação.'},
  {path:'/actuator/mappings',label:'Spring Actuator mappings público',kind:'actuatormappings',impact:'Pode revelar rotas internas e superfície de API.'},
  {path:'/_profiler/',label:'Symfony Profiler público',kind:'profiler',impact:'Pode revelar consultas, parâmetros e detalhes internos de execução.'},
  {path:'/_debugbar/open',label:'Laravel Debugbar público',kind:'debugbar',impact:'Pode revelar consultas, sessões e dados de depuração.'},
  {path:'/telescope',label:'Laravel Telescope público',kind:'telescope',impact:'Pode revelar eventos, requisições e informações operacionais.'},
  {path:'/swagger.json',label:'Documentação Swagger pública',kind:'swagger',impact:'Expõe a descrição das rotas da API; valide se a publicação é intencional.'},
  {path:'/openapi.json',label:'Especificação OpenAPI pública',kind:'openapi',impact:'Expõe a descrição das rotas da API; valide se a publicação é intencional.'},
  {path:'/v3/api-docs',label:'Documentação Spring API pública',kind:'openapi',impact:'Expõe a descrição das rotas da API; valide se a publicação é intencional.'}
];

function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const [a,b] = ip.split(".").map(Number);
    return a===0 || a===10 || a===127 || a>=224 || (a===169&&b===254) ||
      (a===172&&b>=16&&b<=31) || (a===192&&b===168) || (a===100&&b>=64&&b<=127) ||
      (a===192&&b===0) || (a===198&&(b===18||b===19));
  }
  if (net.isIPv6(ip)) {
    const x=ip.toLowerCase();
    return x==="::" || x==="::1" || x.startsWith("fc") || x.startsWith("fd") ||
      x.startsWith("fe8") || x.startsWith("fe9") || x.startsWith("fea") || x.startsWith("feb") ||
      x.startsWith("ff") || x.startsWith("::ffff:127.") || x.startsWith("::ffff:10.") ||
      x.startsWith("::ffff:192.168.") || x.startsWith("::ffff:172.");
  }
  return true;
}

function normalizeDomain(input) {
  if (typeof input !== "string" || input.length > 300) throw new Error("Informe um domínio válido.");
  let u;
  try { u = new URL(input.includes("://") ? input : `https://${input}`); }
  catch { throw new Error("Domínio inválido."); }
  if (!['http:','https:'].includes(u.protocol) || u.username || u.password || u.port && !['80','443'].includes(u.port))
    throw new Error("Use um domínio público HTTP/HTTPS, sem credenciais ou portas alternativas.");
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || net.isIP(host))
    throw new Error("Informe um nome de domínio público, não um IP ou endereço local.");
  return { host, origin: `https://${host}` };
}

async function assertPublicHost(host) {
  const records = await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length || records.some(r => isPrivateIP(r.address)))
    throw new Error("O domínio resolve para endereço não público; auditoria bloqueada.");
}

async function safeGet(url, host, extraHeaders = {}) {
  const parsed = new URL(url);
  if (parsed.hostname !== host || parsed.protocol !== "https:") throw new Error("Destino externo bloqueado.");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      method: "GET", redirect: "manual", signal: controller.signal,
      headers: { "User-Agent": USER_AGENT, "Range": `bytes=0-${MAX_BODY-1}`, "Accept": "*/*", ...extraHeaders }
    });
    let body = "", size = 0, prefix = [];
    const reader = response.body?.getReader();
    if (reader) {
      while (size < MAX_BODY) {
        const {done,value} = await reader.read();
        if (done) break;
        const chunk = value.subarray(0, MAX_BODY-size);
        if (prefix.length < 8) prefix.push(...Array.from(chunk.subarray(0, 8-prefix.length)));
        body += new TextDecoder("utf-8", {fatal:false}).decode(chunk);
        size += chunk.length;
        if (chunk.length < value.length) break;
      }
      await reader.cancel().catch(() => {});
    }
    return { status: response.status, redirected: response.status >= 300 && response.status < 400,
      headers: response.headers, body, bytes_read: size, prefix_hex: prefix.map(x=>x.toString(16).padStart(2,"0")).join("") };
  } finally { clearTimeout(timer); }
}

function observation(observations, title, detail) {
  observations.push({ title, detail });
}

async function mapLimit(items, limit, worker) {
  const out = new Array(items.length);
  let cursor = 0;
  await Promise.all(Array.from({length:Math.min(limit,items.length)}, async () => {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      out[i] = await worker(items[i], i);
    }
  }));
  return out;
}

async function aiSummary(domain, findings, observations) {
  const prompt = `Analise este relatório de segurança defensiva. Não invente achados, não aumente severidade e diferencie evidência confirmada de observação. Domínio: ${domain}. Achados confirmados: ${JSON.stringify(findings)}. Observações: ${JSON.stringify(observations)}. Responda em português, até 150 palavras, priorizando correções.`;
  if (process.env.OPENAI_API_KEY) {
    const model = process.env.OPENAI_MODEL || "gpt-6-luna";
    const response = await fetch("https://api.openai.com/v1/responses", {
      method:"POST", headers:{"Content-Type":"application/json", "Authorization":`Bearer ${process.env.OPENAI_API_KEY}`},
      body:JSON.stringify({model,input:prompt,max_output_tokens:280}), signal:AbortSignal.timeout(9000)
    });
    if (!response.ok) throw new Error("OpenAI indisponível");
    const data = await response.json();
    const output = (data.output || []).flatMap(item => item.content || []).filter(part => part.type === "output_text").map(part => part.text || "").join("\n");
    return output.slice(0,2200) || "Resumo indisponível.";
  }
  const key = process.env.GEMINI_API_KEY;
  if (!key) return "Configure OPENAI_API_KEY ou GEMINI_API_KEY. As evidências técnicas permanecem disponíveis.";
  const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
    method:"POST", headers:{"Content-Type":"application/json", "x-goog-api-key":key},
    body:JSON.stringify({contents:[{parts:[{text:prompt}]}],generationConfig:{temperature:0.1,maxOutputTokens:280}}), signal:AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error("Gemini indisponível");
  const data = await response.json();
  return data.candidates?.[0]?.content?.parts?.map(p=>p.text||"").join("").slice(0,2200) || "Resumo indisponível.";
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (req.method !== "POST") { res.setHeader("Allow","POST"); return res.status(405).json({error:"Método não permitido."}); }
  try {
    const {host,origin} = normalizeDomain(req.body?.domain);
    await assertPublicHost(host);
    const findings = [], observations = [];
    let checks = 0, https = {ok:false}, homepageHeaders = null;

    try {
      const home = await safeGet(`${origin}/`, host);
      checks++;
      https = {ok: home.status > 0 && !home.redirected, status:home.status};
      homepageHeaders = home.headers;
      const h = home.headers;
      if (!h.get("strict-transport-security")) observation(observations,"HSTS ausente","A resposta HTTPS não envia Strict-Transport-Security. É uma melhoria de endurecimento, não uma falha crítica isolada.");
      if (!h.get("content-security-policy")) observation(observations,"CSP ausente","A página não envia Content-Security-Policy. Avalie uma política adequada aos scripts e recursos usados.");
      if (!h.get("x-content-type-options")) observation(observations,"X-Content-Type-Options ausente","Considere configurar nosniff para reduzir interpretação incorreta de MIME.");
      const server = h.get("server");
      if (server) observation(observations,"Identificação do servidor divulgada",`Cabeçalho Server: ${server.slice(0,120)}. Avalie reduzir divulgação de versão e tecnologia.`);
      const powered = h.get("x-powered-by");
      if (powered) observation(observations,"Tecnologia divulgada",`Cabeçalho X-Powered-By: ${powered.slice(0,120)}.`);
      const cors = h.get("access-control-allow-origin");
      const credentials = h.get("access-control-allow-credentials");
      if (cors === "*" || (cors && cors !== origin)) observation(observations,"CORS permissivo na página inicial",`Access-Control-Allow-Origin: ${cors}; credentials: ${credentials||"não informado"}. Confirme se a política é intencional e restrinja origens quando houver dados privados.`);
      const setCookie = h.getSetCookie?.() || (h.get("set-cookie") ? [h.get("set-cookie")] : []);
      for (const cookie of setCookie.slice(0,8)) {
        const name = cookie.split("=",1)[0].trim();
        const missing = [];
        if (!/;\s*secure\b/i.test(cookie)) missing.push("Secure");
        if (!/;\s*httponly\b/i.test(cookie)) missing.push("HttpOnly");
        if (!/;\s*samesite=/i.test(cookie)) missing.push("SameSite");
        if (missing.length) observation(observations,`Cookie ${name||"sem nome"} sem atributos recomendados`,`Atributos ausentes: ${missing.join(", ")}. Avalie conforme a finalidade do cookie.`);
      }
    } catch (e) {
      observation(observations,"HTTPS não validado",`A conexão HTTPS não pôde ser validada: ${String(e.message).slice(0,180)}.`);
    }

    const probeResults = await mapLimit(PROBES, CONCURRENCY, async item => {
      try {
        const r = await safeGet(`${origin}${item.path}`, host);
        checks++;
        if (![200,206].includes(r.status) || r.redirected) return null;
        const contentType = (r.headers.get("content-type") || "").toLowerCase();
        const body = r.body;
        const tests = {
          secrets: /(?:DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|GEMINI_API_KEY|STRIPE_SECRET_KEY|SECRET_KEY|JWT_SECRET|SMTP_PASSWORD)\s*[:=]\s*["']?[^\s"'#]{6,}/i,
          npm: /(?:_authToken|_password|:_auth)\s*=\s*[^\s#]{8,}/i,
          composer: /(?:http-basic|github-oauth|bearer)\s*["']?\s*:\s*["']?[^\s"']{8,}/i,
          jsonsecrets: /(?:client_secret|private_key|access_token|refresh_token)\s*["']?\s*:\s*["']?[^\s"']{8,}/i,
          serviceaccount: /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/i,
          aws: /(?:aws_access_key_id\s*=\s*AKIA[0-9A-Z]{16}|aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{30,})/i,
          wpconfig: /define\s*\(\s*["']DB_(?:NAME|USER|PASSWORD)["']\s*,\s*["'][^"']+["']/i,
          phpconfig: /(?:password|secret|api[_-]?key)\s*["']?\s*=>\s*["'][^"']{6,}["']/i,
          yamlconfig: /(?:password|secret|api[_-]?key):\s*["']?[^\s#"']{6,}/i,
          privatekey: /-----BEGIN (?:OPENSSH|RSA|EC|ENCRYPTED) PRIVATE KEY-----/i,
          sql: /(?:CREATE\s+TABLE\s+|INSERT\s+INTO\s+|--\s*(?:MySQL|PostgreSQL))/i,
          zip: null, gzip: null,
          gitconfig: /^\s*\[core\]/im,
          githead: /^(?:ref:\s+refs\/heads\/|[a-f0-9]{40})/im,
          gitindex: null, svn: /^(?:\d+\n|dir\n)/m, sqlite: null, dsstore: /Bud1|Iloc| plst/i,
          phpinfo: /<title>phpinfo\(\)<\/title>|PHP Version|phpinfo\(\)/i,
          apachestatus: /Apache Server Status|Server uptime|Total accesses/i,
          actuatorenv: /"propertySources"\s*:\s*\[|"activeProfiles"\s*:/i,
          actuatorconfig: /"contexts"\s*:\s*\{|"beans"\s*:\s*\{/i,
          actuatormappings: /"contexts"\s*:\s*\{|"mappings"\s*:\s*\{/i,
          profiler: /Symfony\s+Profiler|_profiler|token.*collector/i,
          debugbar: /Laravel Debugbar|debugbar|phpdebugbar/i,
          telescope: /Laravel Telescope|telescope\.entries|Telescope/i,
          swagger: /"swagger"\s*:\s*"2\.|"openapi"\s*:\s*"3\./i,
          openapi: /"openapi"\s*:\s*"3\./i
        };
        let confirmed = false, markerText = "", severity = "HIGH";
        if (item.kind === "zip") { confirmed = r.prefix_hex.startsWith("504b0304"); markerText = "assinatura ZIP válida"; severity = "CRITICAL"; }
        else if (item.kind === "gzip") { confirmed = r.prefix_hex.startsWith("1f8b"); markerText = "assinatura GZIP válida"; severity = "CRITICAL"; }
        else if (item.kind === "gitindex") { confirmed = r.prefix_hex.startsWith("44495243"); markerText = "assinatura Git DIRC"; }
        else if (item.kind === "sqlite") { confirmed = body.startsWith("SQLite format 3"); markerText = "assinatura SQLite válida"; }
        else {
          const re = tests[item.kind]; confirmed = !!re && re.test(body);
          markerText = confirmed ? `marcador compatível: ${body.match(re)?.[0]?.slice(0,90) || item.kind}` : "";
        }
        if (!confirmed) return null;
        if (["secrets","npm","composer","jsonsecrets","serviceaccount","aws","wpconfig","phpconfig","yamlconfig","privatekey","sql","zip","gzip"].includes(item.kind)) severity = "CRITICAL";
        if (["swagger","openapi","actuatormappings"].includes(item.kind)) severity = "INFO";
        if (item.kind === "actuatorenv" && /(?:password|secret|token|api[_-]?key)\s*["']?\s*:\s*["']?[^\s"']{6,}/i.test(body)) severity = "CRITICAL";
        return {title:item.label,severity,description:`O endpoint ${item.path} respondeu HTTP ${r.status} e apresentou conteúdo compatível com a exposição identificada.`,impact:item.impact,evidence:`GET ${item.path} → HTTP ${r.status}; Content-Type: ${contentType||"não informado"}; ${markerText}; ${r.bytes_read} bytes lidos.`,remediation:"Remova ou restrinja o artefato no servidor/CDN. Se houver segredo, revogue e gere outro imediatamente. Preserve logs e valide a correção com nova auditoria."};
      } catch { return null; }
    });
    for (const finding of probeResults) if (finding) findings.push(finding);

    // A directory index is only reported as an observation unless a sensitive
    // artifact is individually confirmed by one of the probes above.
    for (const path of ["/backup/","/backups/","/uploads/"]) {
      try {
        const r = await safeGet(`${origin}${path}`,host); checks++;
        if (r.status===200 && /<title>Index of\s|<h1>Index of\s|Directory listing for/i.test(r.body))
          observation(observations,`Listagem de diretório habilitada em ${path}`,"O servidor parece publicar um índice de arquivos. Revise os arquivos listados e desabilite autoindex/listing se não for necessário.");
      } catch {}
    }

    let ai_summary;
    try { ai_summary = await aiSummary(host,findings,observations); }
    catch { ai_summary = "O resumo por IA falhou nesta execução. As evidências técnicas continuam disponíveis no relatório."; }
    return res.status(200).json({
      domain:host, generated_at:new Date().toISOString(), checks_run:checks,
      https, findings, observations, ai_summary,
      verdict: findings.length ? "EXPOSIÇÃO CRÍTICA CONFIRMADA" : "NENHUMA EXPOSIÇÃO CRÍTICA CONFIRMADA",
      methodology:"Requisições HTTPS GET limitadas para caminhos públicos conhecidos, sem autenticação, exploração, força bruta, upload ou alteração de dados. Achados críticos exigem HTTP 200/206 e evidência de conteúdo ou assinatura compatível; documentação pública recebe INFO, não CRITICAL.",
      limitations:"A ausência de achados não prova que o domínio esteja seguro. Caminhos não padronizados, conteúdo protegido por login, WAF, respostas dinâmicas e limites de leitura podem ocultar exposições. Esta auditoria não substitui DAST autenticado, SAST, revisão de código ou pentest autorizado."
    });
  } catch (e) {
    return res.status(400).json({error:e.message||"Não foi possível executar a auditoria."});
  }
}
