const form=document.querySelector("#scan-form"),button=document.querySelector("#scan-button"),progress=document.querySelector("#progress-wrap"),results=document.querySelector("#results");
let latestReport=null;
const $=s=>document.querySelector(s);
function esc(v=""){return String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function render(report){
 latestReport=report;const findings=report.findings||[],obs=report.observations||[];
 $("#critical-count").textContent=findings.filter(x=>x.severity==="CRITICAL").length;
 $("#finding-state").textContent=findings.length?"EXPOSIÇÃO CONFIRMADA":"SEM CRÍTICA CONFIRMADA";
 $("#checks-count").textContent=report.checks_run??0;
 $("#https-status").textContent=report.https?.ok?"OK":"FALHA";
 $("#https-detail").textContent=report.https?.ok?"TLS validado":"HTTPS não validado";
 $("#scan-meta").textContent=`${report.domain} · ${new Date(report.generated_at).toLocaleString("pt-BR")}`;
 $("#findings").innerHTML=findings.length?findings.map(f=>`<article class="finding"><div class="finding-top"><div><h4>${esc(f.title)}</h4><p>${esc(f.description)}</p></div><span class="severity">CRÍTICA</span></div><p><b>Impacto:</b> ${esc(f.impact)}</p><div class="evidence">${esc(f.evidence)}</div><p><b>Correção:</b> ${esc(f.remediation)}</p></article>`).join(""):`<div class="empty">Nenhuma exposição crítica foi confirmada nas verificações executadas.</div>`;
 $("#observations").innerHTML=obs.length?obs.map(o=>`<div class="finding"><h4>${esc(o.title)}</h4><p>${esc(o.detail)}</p></div>`).join(""):`<div class="empty">Nenhuma observação adicional.</div>`;
 $("#ai-summary").textContent=report.ai_summary||"Resumo por IA indisponível. Consulte as evidências técnicas acima.";
 if(report.limitations) $(".disclaimer").textContent=report.limitations;
 results.hidden=false;results.scrollIntoView({behavior:"smooth",block:"start"});
}
form.addEventListener("submit",async e=>{
 e.preventDefault();if(!$("#authorized").checked)return;
 const domain=$("#domain").value.trim();button.disabled=true;button.querySelector("span").textContent="Analisando...";progress.hidden=false;results.hidden=true;
 $("#progress-text").textContent="Verificando DNS, HTTPS e exposições públicas...";
 try{
  const res=await fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain})});
  const data=await res.json();if(!res.ok)throw new Error(data.error||"Falha na auditoria.");
  render(data);
 }catch(err){alert(err.message||"Falha inesperada.");}
 finally{button.disabled=false;button.querySelector("span").textContent="Executar análise";progress.hidden=true;}
});
$("#download-report").addEventListener("click",()=>{
 if(!latestReport)return;const blob=new Blob([JSON.stringify(latestReport,null,2)],{type:"application/json"}),url=URL.createObjectURL(blob),a=document.createElement("a");
 a.href=url;a.download=`sentinel-audit-${latestReport.domain.replace(/[^a-z0-9.-]/gi,"_")}.json`;a.click();URL.revokeObjectURL(url);
});