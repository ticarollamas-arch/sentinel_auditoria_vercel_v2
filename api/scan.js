import dns from "node:dns/promises";
import net from "node:net";

const USER_AGENT = "Sentinel-Authorized-Audit/2.0";
const MAX_BODY = 48 * 1024;
const TIMEOUT_MS = 5500;
const CONCURRENCY = 4;

// A finding becomes CRITICAL only when a public response returns HTTP 200
// and its body contains a strong marker for the exposed artifact.
const PROBES = [
  { path: "/.env", label: "Arquivo de ambiente (.env) exposto", marker: /(?:DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|GEMINI_API_KEY|STRIPE_SECRET_KEY|SECRET_KEY)\s*=\s*[^\s#]{4,}/i, impact: "Pode expor credenciais de banco, nuvem ou serviços externos." },
  { path: "/.env.production", label: "Arquivo .env de produção exposto", marker: /(?:DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY)\s*=\s*[^\s#]{4,}/i, impact: "Pode expor segredos usados no ambiente de produção." },
  { path: "/.git/config", label: "Configuração interna do Git exposta", marker: /^\s*\[core\]/im, impact: "Pode revelar repositórios e permitir recuperar código-fonte e histórico." },
  { path: "/.git/HEAD", label: "Metadados do repositório Git expostos", marker: /^(?:ref:\s+refs\/heads\/|[a-f0-9]{40})/im, impact: "Confirma que metadados internos do repositório estão publicamente acessíveis." },
  { path: "/.svn/entries", label: "Metadados do Subversion expostos", marker: /^(?:\d+\n|dir\n)/m, impact: "Pode revelar estrutura e metadados do código versionado." },
  { path: "/backup.zip", label: "Backup ZIP público", binary: "zip", impact: "Pode permitir baixar cópias de segurança com dados ou código interno." },
  { path: "/backup.tar.gz", label: "Backup TAR.GZ público", binary: "gzip", impact: "Pode permitir baixar cópias de segurança com dados ou código interno." },
  { path: "/database.sql", label: "Dump SQL público", marker: /(?:CREATE\s+TABLE\s+|INSERT\s+INTO\s+|--\s*(?:MySQL|PostgreSQL))/i, impact: "Pode expor estrutura e registros do banco de dados." },
  { path: "/db.sql", label: "Dump SQL público", marker: /(?:CREATE\s+TABLE\s+|INSERT\s+INTO\s+|--\s*(?:MySQL|PostgreSQL))/i, impact: "Pode expor estrutura e registros do banco de dados." },
  { path: "/dump.sql", label: "Dump SQL público", marker: /(?:CREATE\s+TABLE\s+|INSERT\s+INTO\s+|--\s*(?:MySQL|PostgreSQL))/i, impact: "Pode expor estrutura e registros do banco de dados." },
  { path: "/.DS_Store", label: "Índice de diretório macOS exposto", marker: /Bud1|Iloc| plst/i, impact: "Pode revelar nomes de arquivos e caminhos internos." },
  { path: "/composer.auth.json", label: "Credenciais Composer expostas", marker: /(?:http-basic|github-oauth|bearer)\s*"?\s*:/i, impact: "Pode expor tokens privados de pacotes e repositórios." },
  { path: "/.npmrc", label: "Configuração npm potencialmente secreta exposta", marker: /(?:_authToken|_password|:_auth)\s*=/i, impact: "Pode expor tokens de publicação ou acesso a pacotes privados." },
  { path: "/wp-config.php", label: "Configuração WordPress exposta", marker: /(?:DB_NAME|DB_USER|DB_PASSWORD)\s*,\s*['\"]/i, impact: "Pode expor credenciais do banco de dados do WordPress." },
  { path: "/id_rsa", label: "Chave privada SSH exposta", marker: /-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----/i, impact: "Pode permitir autenticação indevida em sistemas que confiem nessa chave." },
  { path: "/.ssh/id_rsa", label: "Chave privada SSH exposta", marker: /-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----/i, impact: "Pode permitir autenticação indevida em sistemas que confiem nessa chave." },
  { path: "/credentials.json", label: "Arquivo de credenciais JSON exposto", marker: /(?:client_secret|private_key|access_token|refresh_token)\s*"?\s*:/i, impact: "Pode expor credenciais de serviços e contas de aplicação." },
  { path: "/service-account.json", label: "Credencial de conta de serviço exposta", marker: /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/i, impact: "Pode expor uma chave privada de conta de serviço." },
  { path: "/config/database.yml", label: "Configuração de banco Rails exposta", marker: /(?:password|username|database):\s*[^#\s][^\n]*/i, impact: "Pode revelar credenciais e nomes de bancos de dados." },
  { path: "/phpinfo.php", label: "Página phpinfo pública", marker: /PHP Version|phpinfo\(\)/i, impact: "Pode revelar versões, caminhos, variáveis e configuração interna do servidor." },
  { path: "/server-status", label: "Status interno do Apache público", marker: /Apache Server Status|Server uptime|Total accesses/i, impact: "Pode revelar requisições, clientes e detalhes operacionais do servidor." },
  { path: "/actuator/env", label: "Endpoint Spring Actuator env público", marker: /"propertySources"\s*:\s*\[|"activeProfiles"\s*:/i, impact: "Pode revelar variáveis e propriedades do ambiente da aplicação." }
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
        let confirmed = false, markerText = "";
        if (item.binary === "zip") confirmed = r.prefix_hex.startsWith("504b0304") || /application\/(?:zip|x-zip)/i.test(contentType);
        else if (item.binary === "gzip") confirmed = r.prefix_hex.startsWith("1f8b");
        else confirmed = item.marker.test(r.body);
        if (!confirmed) return null;
        markerText = item.binary ? `assinatura/Content-Type compatível com ${item.binary}` : `marcador de conteúdo: ${r.body.match(item.marker)?.[0]?.slice(0,90) || "confirmado"}`;
        return {title:item.label,severity:"CRITICAL",description:`O endpoint ${item.path} respondeu HTTP 200 e apresentou evidência compatível com o artefato exposto.`,impact:item.impact,evidence:`GET ${item.path} → HTTP ${r.status}; Content-Type: ${contentType||"não informado"}; ${markerText}; ${r.bytes_read} bytes lidos.`,remediation:"Remova o artefato da raiz pública, bloqueie o caminho no servidor/CDN, invalide e substitua segredos que possam ter sido expostos e preserve os logs para investigação."};
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
      methodology:"Requisições HTTPS GET limitadas, sem autenticação, exploração, força bruta, upload ou alteração de dados. Achados críticos exigem HTTP 200 e marcador de conteúdo compatível.",
      limitations:"A ausência de achados não prova que o domínio esteja seguro. Esta auditoria externa não substitui DAST autenticado, SAST, revisão de código ou pentest autorizado."
    });
  } catch (e) {
    return res.status(400).json({error:e.message||"Não foi possível executar a auditoria."});
  }
}
