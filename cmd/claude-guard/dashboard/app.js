// claude-guard dashboard — vanilla JS, no build step
const API = '';
let verdictChart, tierChart;

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('page-' + btn.dataset.page).classList.add('active');
        refresh();
    });
});

async function fetchJSON(url) {
    try { const r = await fetch(API + url); return r.ok ? r.json() : null; }
    catch { return null; }
}

function fmtTime(iso) {
    if (!iso) return '-';
    return new Date(iso).toLocaleTimeString('en-GB', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

function fmtDur(ms) {
    if (!ms || ms < 0.01) return '<1ms';
    return ms < 1000 ? Math.round(ms)+'ms' : (ms/1000).toFixed(1)+'s';
}

function badge(v) { return '<span class="verdict verdict-'+v+'">'+v+'</span>'; }
function trunc(s, n) { return !s ? '' : s.length > n ? s.slice(0,n)+'...' : s; }
function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

async function loadOverview() {
    const d = await fetchJSON('/api/stats?since=24h');
    if (!d) return;
    const pct = n => d.total > 0 ? (n/d.total*100).toFixed(1)+'%' : '0%';
    const timeSavedMin = d.time_saved ? d.time_saved.minutes_saved : 0;
    const interruptsAvoided = d.time_saved ? d.time_saved.interrupts_avoided : 0;
    const stopEvals = d.stop_hooks ? d.stop_hooks.total : 0;
    const stopInj = d.stop_hooks ? d.stop_hooks.injected : 0;
    document.getElementById('statsCards').innerHTML = `
        <div class="stat-card"><div class="label">Decisions</div><div class="value">${d.total}</div><div class="sub">last 24h</div></div>
        <div class="stat-card"><div class="label">Allow</div><div class="value">${d.by_verdict?.allow||0}</div><div class="sub">${pct(d.by_verdict?.allow||0)}</div></div>
        <div class="stat-card"><div class="label">Continue</div><div class="value">${d.by_verdict?.continue||0}</div><div class="sub">${pct(d.by_verdict?.continue||0)} prompted</div></div>
        <div class="stat-card"><div class="label">Deny</div><div class="value">${d.by_verdict?.deny||0}</div><div class="sub">${pct(d.by_verdict?.deny||0)}</div></div>
        <div class="stat-card"><div class="label">Latency p50</div><div class="value">${fmtDur(d.latency_p50_ms)}</div><div class="sub">p95: ${fmtDur(d.latency_p95_ms)}</div></div>
        <div class="stat-card"><div class="label">Cache</div><div class="value">${d.cache?.entries||0}</div><div class="sub">${d.cache?.verified||0} verified</div></div>
        <div class="stat-card"><div class="label">Stop Hook</div><div class="value">${stopInj}/${stopEvals}</div><div class="sub">continues injected</div></div>
        <div class="stat-card"><div class="label">Time Saved</div><div class="value">~${Math.round(timeSavedMin/60)}h</div><div class="sub">${interruptsAvoided} prompts avoided</div></div>`;

    const vd = d.by_verdict||{}, td = d.by_tier||{};
    const vc = document.getElementById('verdictChart')?.getContext('2d');
    const tc = document.getElementById('tierChart')?.getContext('2d');
    if (!vc || !tc) return;
    if (verdictChart) verdictChart.destroy();
    verdictChart = new Chart(vc, {type:'doughnut', data:{labels:Object.keys(vd), datasets:[{data:Object.values(vd), backgroundColor:['#27ae60','#f39c12','#c0392b','#8e44ad','#2980b9']}]}, options:{responsive:true, plugins:{legend:{position:'bottom',labels:{color:'#e0e0e0',font:{size:11}}}}}});
    if (tierChart) tierChart.destroy();
    tierChart = new Chart(tc, {type:'bar', data:{labels:Object.keys(td), datasets:[{label:'Decisions',data:Object.values(td),backgroundColor:'#2980b9'}]}, options:{responsive:true,indexAxis:'y', scales:{x:{ticks:{color:'#8892a4'},grid:{color:'#2c3e50'}},y:{ticks:{color:'#e0e0e0',font:{size:11}},grid:{display:false}}}, plugins:{legend:{display:false}}}});
}

async function loadTimeline() {
    const d = await fetchJSON('/api/decisions?since=1h&limit=100');
    const el = document.getElementById('timelineTable');
    if (!d?.length) { el.innerHTML = '<div class="empty-state"><p>No recent decisions</p></div>'; return; }
    el.innerHTML = `<table><thead><tr><th>Time</th><th>Verdict</th><th>Tier</th><th>Command</th><th>Reason</th></tr></thead><tbody>${d.map(r=>`<tr><td>${fmtTime(r.time)}</td><td>${badge(r.verdict)}</td><td>${esc(r.tier)}</td><td title="${esc(r.command)}">${esc(trunc(r.command,60))}</td><td>${esc(trunc(r.reason,50))}</td></tr>`).join('')}</tbody></table>`;
}

async function loadCache() {
    const m = document.getElementById('cacheSearch')?.value||'';
    const v = document.getElementById('cacheVerdict')?.value||'';
    let url = '/api/cache?limit=50';
    if (m) url += '&match='+encodeURIComponent(m);
    if (v) url += '&verdict='+v;
    const d = await fetchJSON(url);
    const el = document.getElementById('cacheTable');
    if (!d?.length) { el.innerHTML = '<div class="empty-state"><p>No cache entries</p></div>'; return; }
    el.innerHTML = `<table><thead><tr><th>Command</th><th>Verdict</th><th>Tier</th><th>Provider</th><th>Verified</th><th>Disagree</th></tr></thead><tbody>${d.map(r=>`<tr><td title="${esc(r.command)}">${esc(trunc(r.command,70))}</td><td>${badge(r.effective_verdict||r.verdict)}</td><td>${esc(r.tier)}</td><td>${esc(r.provider||'-')}</td><td class="badge-${r.verified}">${r.verified?'yes':'no'}</td><td class="badge-${r.disagreement}">${r.disagreement?'YES':'no'}</td></tr>`).join('')}</tbody></table>`;
}

async function loadLearned() {
    const d = await fetchJSON('/api/learned');
    const el = document.getElementById('learnedTable');
    if (!d?.length) { el.innerHTML = '<div class="empty-state"><p>No learned patterns yet</p></div>'; return; }
    el.innerHTML = `<table><thead><tr><th>Pattern</th><th>Program</th><th>Approvals</th><th>Scope</th></tr></thead><tbody>${d.map(r=>`<tr><td title="${esc(r.command)}">${esc(trunc(r.canonical_form||r.command,70))}</td><td>${esc(r.program||'-')}</td><td>${r.approval_count}</td><td>${r.cwd?'project':'global'}</td></tr>`).join('')}</tbody></table>`;
}

async function loadStopHooks() {
    const d = await fetchJSON('/api/stop-hooks?since=24h');
    const el = document.getElementById('stopHooksTable');
    if (!d?.length) { el.innerHTML = '<div class="empty-state"><p>No stop hook evaluations</p></div>'; return; }
    el.innerHTML = `<table><thead><tr><th>Time</th><th>Session</th><th>Injected</th><th>Rule</th><th>Continues</th></tr></thead><tbody>${d.map(r=>`<tr><td>${fmtTime(r.time)}</td><td>${esc((r.session_id||'').slice(0,8))}</td><td class="badge-${r.injected}">${r.injected?'YES':'no'}</td><td>${esc(r.fired_rule||'-')}</td><td>${r.continue_count}</td></tr>`).join('')}</tbody></table>`;
}

async function refresh() {
    const p = document.querySelector('.page.active')?.id;
    if (p==='page-overview') await loadOverview();
    else if (p==='page-timeline') await loadTimeline();
    else if (p==='page-cache') await loadCache();
    else if (p==='page-learned') await loadLearned();
    else if (p==='page-stop-hooks') await loadStopHooks();
}

document.getElementById('cacheSearch')?.addEventListener('input', ()=>loadCache());
document.getElementById('cacheVerdict')?.addEventListener('change', ()=>loadCache());

loadOverview();
setInterval(refresh, 5000);
