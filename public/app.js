'use strict';
const $ = selector => document.querySelector(selector);
const h = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const fa = value => Number(value).toLocaleString('fa-IR');
const date = value => value ? new Date(value).toLocaleString('fa-IR', { dateStyle: 'short', timeStyle: 'short' }) : '—';
const roles = { admin: 'مدیر', operator: 'اپراتور', viewer: 'ناظر' };
const statusNames = { pending: 'در انتظار تأیید', queued: 'در صف اجرا', running: 'در حال اجرا', cancelling: 'در حال توقف', succeeded: 'موفق', failed: 'ناموفق', rejected: 'رد شده', cancelled: 'متوقف شده', expired: 'منقضی', interrupted: 'قطع شده / نیازمند بررسی', timeout: 'پایان مهلت', connection_error: 'خطای اتصال', output_limit: 'سقف خروجی' };
const diagnostics = { system: 'سیستم‌عامل', uptime: 'زمان فعالیت', disk: 'فضای دیسک', memory: 'حافظه', failed_services: 'سرویس‌های ناموفق' };
const pages = {
  overview: ['◈', 'نمای کلی', 'OVERVIEW', 'وضعیت دسترسی، کارها و زیرساخت در یک نگاه'],
  servers: ['▤', 'سرورها', 'YOUR INFRASTRUCTURE', 'سرورهای مجاز و تنظیمات اتصال به آن‌ها'],
  jobs: ['≡', 'کارها و تأییدها', 'EXECUTION QUEUE', 'مشاهدهٔ دستورها، تأیید اجرا و بررسی خروجی'],
  users: ['♧', 'کاربران', 'ACCESS MANAGEMENT', 'حساب‌های کاربری و وضعیت دسترسی آن‌ها'],
  grants: ['⌘', 'مجوزها', 'SERVER PERMISSIONS', 'برای هر کاربر، دسترسی به هر سرور را مشخص کنید'],
  audit: ['◷', 'گزارش رخدادها', 'AUDIT TRAIL', 'ردیابی عملیات با زنجیرهٔ امضای رخدادها'],
  connections: ['⇄', 'اتصال‌های GPT', 'GPT CONNECTIONS', 'مدیریت اتصال‌های OAuth حساب شما'],
  settings: ['⚙', 'تنظیمات', 'GATEWAY SETTINGS', 'نشانی اتصال، محدودیت‌های اجرا و امنیت حساب'],
};
const state = { user: null, csrf: '', servers: [], jobs: [], users: [], grants: [], connections: [], settings: null, view: 'overview', jobFilter: 'all' };
let refreshing = false, toastTimer;
function toast(message, error = false) { const node = $('#toast'); node.textContent = message; node.classList.toggle('toast-error', error); node.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => node.hidden = true, 6000); }
async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, { credentials: 'same-origin', ...options, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf, ...options.headers } });
  const data = await response.json().catch(() => ({ error: 'پاسخ سرور معتبر نیست' }));
  if (!response.ok) {
    if (response.status === 401 && path !== '/login') { state.user = null; state.servers = []; state.jobs = []; state.users = []; state.grants = []; state.connections = []; state.settings = null; closeModal(); $('#shell').hidden = true; $('#login').hidden = false; }
    throw new Error(data.error + (data.fields?.length ? ` (${data.fields.map(field => field.path).join('، ')})` : ''));
  }
  return data;
}
const post = (path, body = {}) => api(path, { method: 'POST', body: JSON.stringify(body) });
const badge = status => `<span class="badge ${['succeeded'].includes(status) ? 'good' : ['pending', 'queued', 'cancelling', 'expired'].includes(status) ? 'pending' : ['failed', 'connection_error', 'timeout', 'interrupted', 'rejected', 'output_limit'].includes(status) ? 'bad' : status === 'running' ? 'blue' : ''}">${h(statusNames[status] || status)}</span>`;
const empty = (title, text, button = '', compact = false) => `<div class="empty ${compact ? 'compact' : ''}"><div class="empty-icon">◌</div><h3>${h(title)}</h3><p>${h(text)}</p>${button}</div>`;
function openModal(title, html) { $('#modal-title').textContent = title; $('#modal-content').innerHTML = html; if (!$('#modal').open) $('#modal').showModal(); }
function closeModal() { $('#modal').close(); }
$('#close-modal').addEventListener('click', closeModal);
$('#modal').addEventListener('close', () => { if (!$('#modal').open) $('#modal-content').replaceChildren(); });
$('#modal').addEventListener('click', event => { if (event.target === $('#modal') && event.clientX < $('#modal').getBoundingClientRect().left) closeModal(); });
function formHandler(form, callback) {
  form.addEventListener('submit', async event => {
    event.preventDefault(); const buttons = [...form.querySelectorAll('button[type=submit]')]; buttons.forEach(b => b.disabled = true);
    const error = form.querySelector('.error'); if (error) error.textContent = '';
    try { await callback(new FormData(form)); } catch (err) { if (error) error.textContent = err.message; else toast(err.message, true); }
    finally { buttons.forEach(b => b.disabled = false); }
  });
}
function afterLogin() {
  const target = new URLSearchParams(location.search).get('returnTo');
  if (target?.startsWith('/oauth/authorize?')) { const url = new URL(target, location.origin); if (url.origin === location.origin && url.pathname === '/oauth/authorize') { location.assign(url.href); return true; } }
  return false;
}
formHandler($('#login-form'), async form => {
  const result = await post('/login', Object.fromEntries(form)); state.user = result.user; state.csrf = result.csrf;
  $('#login-form').reset(); if (!afterLogin()) await boot();
});
async function boot() {
  try {
    const result = await api('/session'); state.user = result.user; state.csrf = result.csrf || '';
    $('#loading').hidden = true; $('#login').hidden = !!state.user; $('#shell').hidden = !state.user;
    if (!state.user) { state.servers = []; state.jobs = []; state.users = []; state.grants = []; state.connections = []; state.settings = null; $('#content').replaceChildren(); $('#otp-label').hidden = false; $('#login-form').elements.otp.required = result.requireMfa !== false; return; }
    if (afterLogin()) return;
    $('#account-name').textContent = state.user.username; $('#account-role').textContent = roles[state.user.role]; $('#avatar').textContent = state.user.username[0].toUpperCase();
    await refresh();
  } catch (error) { $('#loading').textContent = 'ارتباط با سرور برقرار نشد؛ صفحه را تازه کنید.'; toast(error.message, true); }
}
async function refresh() {
  if (refreshing || !state.user) return; refreshing = true;
  try {
    const previous = JSON.stringify([state.servers, state.jobs, state.connections, state.users, state.grants, state.settings]);
    const data = await Promise.all([api('/servers'), api('/jobs'), api('/connections'), ...(state.user.role === 'admin' ? [api('/admin/users'), api('/admin/grants'), api('/admin/settings')] : [])]);
    state.servers = data[0].servers; state.jobs = data[1].jobs; state.connections = data[2].connections;
    if (state.user.role === 'admin') { state.users = data[3].users; state.grants = data[4].grants; state.settings = data[5]; }
    $('#sync-time').textContent = `به‌روزرسانی ${new Date().toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' })}`;
    const current = JSON.stringify([state.servers, state.jobs, state.connections, state.users, state.grants, state.settings]);
    if (previous !== current || !$('#content').childNodes.length || state.view !== (location.hash.slice(1) || 'overview')) await render();
  } catch (error) { toast(error.message, true); } finally { refreshing = false; }
}
function allowedPages() { return Object.keys(pages).filter(key => state.user.role === 'admin' || !['users', 'grants', 'audit'].includes(key)); }
async function render() {
  state.view = location.hash.slice(1) || 'overview'; if (!allowedPages().includes(state.view)) state.view = 'overview';
  const page = pages[state.view], pending = state.jobs.filter(job => job.status === 'pending').length;
  $('#navigation').innerHTML = allowedPages().map(key => `<a href="#${key}" class="nav-item ${state.view === key ? 'active' : ''}"><span class="nav-icon">${pages[key][0]}</span>${pages[key][1]}${key === 'jobs' && pending ? `<span class="nav-badge">${fa(pending)}</span>` : ''}</a>`).join('');
  $('#breadcrumb').textContent = page[1]; $('#page-title').textContent = page[1]; $('#page-kicker').textContent = page[2]; $('#page-description').textContent = page[3];
  $('#page-actions').innerHTML = ['overview', 'servers'].includes(state.view) && state.user.role === 'admin' ? '<button data-action="add-server">＋ افزودن سرور</button>' : state.view === 'users' ? '<button data-action="add-user">＋ کاربر جدید</button>' : state.view === 'jobs' ? '<button data-action="new-job">＋ درخواست اجرا</button>' : '';
  const content = $('#content');
  if (state.view === 'overview') content.innerHTML = overview();
  if (state.view === 'servers') content.innerHTML = serversView();
  if (state.view === 'jobs') { content.innerHTML = `<div class="tab-filter"><select id="job-filter" aria-label="فیلتر وضعیت"><option value="all">همهٔ وضعیت‌ها</option>${Object.entries(statusNames).map(([key, label]) => `<option value="${key}" ${state.jobFilter === key ? 'selected' : ''}>${label}</option>`).join('')}</select><span class="muted small">حداکثر ۱۰۰ کار اخیر</span></div>${jobsTable(state.jobs.filter(job => state.jobFilter === 'all' || job.status === state.jobFilter))}`; $('#job-filter').addEventListener('change', event => { state.jobFilter = event.target.value; void render(); }); }
  if (state.view === 'users') content.innerHTML = usersView();
  if (state.view === 'grants') { content.innerHTML = grantsView(); if (state.grantUser) $('#grant-form').elements.userId.value = state.grantUser; formHandler($('#grant-form'), async form => { await api('/admin/grants', { method: 'PUT', body: JSON.stringify({ userId: form.get('userId'), serverId: form.get('serverId'), diagnostics: form.has('diagnostics'), execute: form.has('execute') }) }); toast('مجوز ذخیره شد'); await refresh(); }); $('#grant-form').addEventListener('change', event => { state.grantUser = $('#grant-form').elements.userId.value; loadGrant(event); }); loadGrant(); }
  if (state.view === 'connections') content.innerHTML = connectionsView();
  if (state.view === 'settings') { content.innerHTML = settingsView(); formHandler($('#password-form'), async form => { if (form.get('password') !== form.get('confirm')) throw new Error('تکرار رمز یکسان نیست'); await post('/password', { currentPassword: form.get('currentPassword'), password: form.get('password') }); toast('رمز تغییر کرد؛ دوباره وارد شوید'); await boot(); }); }
  if (state.view === 'audit') {
    content.innerHTML = '<p class="muted">در حال بررسی گزارش…</p>';
    try { const data = await api('/admin/audit'); if (state.view === 'audit') content.innerHTML = auditView(data); } catch (error) { content.textContent = error.message; }
  }
}
function overview() {
  const counts = [
    ['سرورهای مجاز', state.servers.length, 'تعریف‌شده در درگاه', '▤'],
    ['کارهای در حال اجرا', state.jobs.filter(j => j.status === 'running').length, 'از میان ۱۰۰ کار اخیر', '↗'],
    ['در انتظار تأیید', state.jobs.filter(j => j.status === 'pending').length, 'نیازمند بررسی مدیر', '◷'],
    ['اتصال‌های GPT شما', state.connections.length, 'مجوزهای OAuth معتبر', '⇄'],
  ];
  return `<div class="stats">${counts.map(([title, count, foot, icon], index) => `<div class="stat ${index === 2 && count ? 'highlight' : ''}"><span class="stat-title">${title}</span><span class="stat-icon">${icon}</span><strong class="stat-number">${fa(count)}</strong><span class="stat-foot">${foot}</span></div>`).join('')}</div><div class="section-heading"><h2>سرورهای شما</h2><button class="secondary small-button" data-action="navigate" data-id="servers">مشاهدهٔ همه ←</button></div>${state.servers.length ? `<div class="server-grid">${state.servers.slice(0, 3).map(serverCard).join('')}</div>` : empty('اولین سرور را متصل کنید', 'پس از تعریف سرور و مجوزها، دسترسی GPT از همین درگاه برقرار می‌شود.', state.user.role === 'admin' ? '<button data-action="add-server">تعریف اولین سرور</button>' : '')}<div class="policy-banner"><span class="symbol">⌘</span><div><b>هر دستور، با یک تصمیم مشخص</b><p>دستور آزاد پس از تأیید مدیر اجرا می‌شود. اطلاعات SSH در درگاه می‌ماند و خروجی کار به حساب مجاز بازمی‌گردد.</p></div></div><div class="section-heading"><h2>فعالیت‌های اخیر</h2><button class="secondary small-button" data-action="navigate" data-id="jobs">همهٔ کارها ←</button></div>${jobsTable(state.jobs.slice(0, 5))}`;
}
function serverCard(server) {
  return `<article class="server-card"><div class="server-card-top"><span class="server-symbol">▤</span><div><h3>${h(server.name)}</h3><span class="muted small">${server.enabled ? 'تعریف‌شده / اتصال بررسی نشده' : 'دسترسی غیرفعال'}</span></div></div><div class="server-meta"><span>${server.address ? 'مقصد SSH' : 'دسترسی مجاز'}</span><strong class="ltr">${server.address ? h(`${server.address}:${server.port}`) : 'SSH VIA GATEWAY'}</strong></div><div class="actions"><span class="badge ${server.enabled ? 'good' : ''}">${server.enabled ? 'فعال در درگاه' : 'غیرفعال'}</span><div>${server.enabled ? `<button class="secondary" data-action="server-job" data-id="${server.id}">اجرای کار ←</button>` : ''}${state.user.role === 'admin' ? `<button class="icon-button" title="ویرایش سرور" aria-label="ویرایش ${h(server.name)}" data-action="edit-server" data-id="${server.id}">⋯</button>` : ''}</div></div></article>`;
}
function serversView() { return state.servers.length ? `<div class="server-grid">${state.servers.map(serverCard).join('')}</div>` : empty('هنوز سروری در دسترس نیست', 'مدیر باید سرور را اضافه کند و دسترسی حساب را مشخص کند.'); }
function jobsTable(jobs) {
  return `<div class="panel">${jobs.length ? `<div class="table-wrap"><table><thead><tr><th>کار / سرور</th><th>دستور</th><th>درخواست‌کننده</th><th>وضعیت</th><th>زمان درخواست</th><th></th></tr></thead><tbody>${jobs.map(job => `<tr><td><b>${h(job.serverName)}</b><div class="muted">${job.kind === 'command' ? 'دستور آزاد' : 'عیب‌یابی'}</div></td><td class="command-cell" title="${h(job.command)}">${h(job.command)}</td><td>${h(job.username)}</td><td>${badge(job.status)}</td><td class="muted">${h(date(job.createdAt))}</td><td><button class="secondary" data-action="job-detail" data-id="${job.id}">${job.status === 'pending' && state.user.role === 'admin' ? 'بررسی و تأیید' : 'جزئیات'}</button></td></tr>`).join('')}</tbody></table></div>` : empty('هنوز کاری ثبت نشده است', 'برای بررسی اتصال، یک عیب‌یابی از بخش سرورها اجرا کنید.', '', true)}</div>`;
}
function usersView() {
  return `<div class="user-grid">${state.users.map(user => `<article class="user-card"><div class="account"><span class="avatar">${h(user.username[0].toUpperCase())}</span><div><b>${h(user.username)}</b><small>${roles[user.role]}</small></div></div><span class="badge ${user.enabled ? 'good' : ''}">${user.enabled ? 'حساب فعال' : 'حساب غیرفعال'}</span> <span class="badge">${user.mfaEnabled ? 'تأیید دو مرحله‌ای' : 'بدون MFA'}</span><div class="actions"><button class="secondary small-button" data-action="edit-user" data-id="${user.id}">مدیریت حساب</button><button class="secondary small-button" data-action="user-grants" data-id="${user.id}">مجوزها ←</button></div></article>`).join('')}</div>`;
}
function grantsView() {
  return `<div class="settings-list"><div class="panel panel-pad"><h2>دسترسی کاربر به سرور</h2><form id="grant-form"><label>کاربر<select name="userId">${state.users.map(user => `<option value="${user.id}">${h(user.username)} / ${roles[user.role]}</option>`).join('')}</select></label><label>سرور<select name="serverId">${state.servers.map(server => `<option value="${server.id}">${h(server.name)}</option>`).join('')}</select></label><label><input type="checkbox" name="diagnostics">اجرای عیب‌یابی‌های ثابت</label><label><input type="checkbox" name="execute">درخواست دستور آزاد با تأیید مدیر</label><p class="form-note">مدیر به همهٔ سرورها دسترسی دارد. ناظر فقط عیب‌یابی‌های مجاز را اجرا می‌کند. لغو مجوز، کارهای در صف و در حال اجرا را متوقف می‌کند.</p><p class="error" role="alert"></p><button type="submit" class="full" ${!state.servers.length ? 'disabled' : ''}>ذخیرهٔ دسترسی</button></form></div><div class="panel panel-pad"><h2>مجوزهای ثبت‌شده</h2>${state.grants.length ? state.grants.map(grant => `<div class="settings-row"><span>${h(state.users.find(u => u.id === grant.userId)?.username)} ← ${h(state.servers.find(s => s.id === grant.serverId)?.name)}</span><b>${grant.diagnostics ? 'عیب‌یابی' : ''}${grant.execute ? ' / دستور با تأیید' : ''}${!grant.diagnostics && !grant.execute ? 'بدون دسترسی' : ''}</b></div>`).join('') : '<p class="muted small">هنوز مجوزی برای کاربران ثبت نشده است.</p>'}</div></div>`;
}
function loadGrant(event) {
  if (event?.target?.type === 'checkbox') return;
  const form = $('#grant-form'); if (!form) return;
  const grant = state.grants.find(g => g.userId === form.elements.userId.value && g.serverId === form.elements.serverId.value);
  form.elements.diagnostics.checked = !!grant?.diagnostics; form.elements.execute.checked = !!grant?.execute;
}
function connectionsView() {
  return `<div class="policy-banner"><span class="symbol">⇄</span><div><b>ورود در مرورگر؛ دسترسی با OAuth</b><p>در تنظیمات اتصال GPT نشانی MCP را وارد کنید و با حساب همین پنل وارد شوید. رمز SSH را در گفتگو ارسال نکنید.</p></div></div><div class="panel">${state.connections.length ? state.connections.map(connection => `<div class="connection"><div><h3>${h(connection.clientName)}</h3><p class="muted">اعتبار تا ${h(date(connection.expiresAt))}</p></div><button class="danger small-button" data-action="revoke" data-id="${connection.id}">لغو اتصال</button></div>`).join('') : empty('اتصال فعالی ثبت نشده است', 'پس از تکمیل ورود OAuth در GPT، اتصال در این بخش نمایش داده می‌شود.', '', true)}</div>`;
}
function settingsView() {
  const settings = state.settings;
  return `<div class="settings-list"><div class="panel panel-pad"><h2>اتصال به GPT</h2><p class="muted small">نشانی سرور MCP</p><code class="settings-url ltr">${h(settings?.mcpUrl || `${location.origin}/mcp`)}</code><button class="secondary small-button" data-action="copy-url">کپی نشانی اتصال</button><p class="form-note">در Custom MCP همین نشانی را وارد کنید و یک بار در مرورگر وارد شوید. Client ID یا Secret دستی لازم نیست؛ اتصال در استفادهٔ عادی خودکار تمدید می‌شود.</p>${settings ? `<div class="settings-row"><span>مهلت عدم فعالیت اتصال GPT</span><b>${fa(settings.refreshIdleDays)} روز، با تمدید خودکار</b></div><div class="settings-row"><span>مهلت اجرای هر کار</span><b>${fa(settings.timeoutSeconds)} ثانیه</b></div><div class="settings-row"><span>سقف خروجی</span><b>${fa(settings.outputLimitBytes / 1024)} KiB</b></div><div class="settings-row"><span>کار هم‌زمان</span><b>${fa(settings.concurrency)}</b></div><div class="settings-row"><span>نگه‌داری متن و خروجی کار</span><b>${fa(settings.retentionDays)} روز</b></div><p class="form-note">پارامترهای عملیاتی از تنظیمات سرور واسط تغییر می‌کنند.</p>` : ''}</div><div class="panel panel-pad"><h2>تغییر رمز حساب</h2><form id="password-form"><label>رمز فعلی<input type="password" name="currentPassword" dir="ltr" autocomplete="current-password" required maxlength="256"></label><label>رمز جدید<input type="password" name="password" dir="ltr" autocomplete="new-password" required minlength="14" maxlength="256"></label><label>تکرار رمز جدید<input type="password" name="confirm" dir="ltr" autocomplete="new-password" required minlength="14" maxlength="256"></label><p class="form-note">با تغییر رمز، تمام نشست‌ها و اتصال‌های OAuth این حساب بی‌اعتبار می‌شوند.</p><p class="error" role="alert"></p><button type="submit" class="full">تغییر رمز و خروج</button></form></div></div>`;
}
function auditView(data) {
  return `<div class="policy-banner"><div><b>${data.integrity.valid ? 'زنجیرهٔ امضای رخدادها معتبر است' : 'امضای رخدادها معتبر نیست؛ بررسی لازم است'}</b><p>${fa(data.integrity.checked)} رخداد بررسی شد. ۲۰۰ رخداد آخر نمایش داده می‌شود.</p></div></div><div class="panel table-wrap"><table><thead><tr><th>زمان</th><th>عامل</th><th>رخداد</th><th>منبع</th></tr></thead><tbody>${data.events.map(event => `<tr><td>${h(date(event.at))}</td><td>${h(state.users.find(u => u.id === event.actor)?.username || event.actor)}</td><td class="ltr">${h(event.action)}</td><td class="ltr small">${h(event.resource)}</td></tr>`).join('')}</tbody></table></div>`;
}
function serverForm(id) {
  const server = state.servers.find(item => item.id === id);
  openModal(server ? 'ویرایش سرور' : 'افزودن سرور', `<form id="server-form"><div class="grid-two"><label>نام سرور<input name="name" value="${h(server?.name)}" required maxlength="80" placeholder="Production API"></label><label>نشانی IP<input name="address" value="${h(server?.address)}" dir="ltr" required maxlength="80" placeholder="10.20.0.10"></label><label>پورت SSH<input name="port" type="number" min="1" max="65535" value="${server?.port || 22}" dir="ltr" required></label><label>کاربر SSH<input name="username" value="${h(server?.username || 'gptops')}" dir="ltr" required pattern="[a-z_][a-z0-9_-]{0,31}" maxlength="32"></label></div><label>اثر انگشت کلید میزبان<input name="fingerprint" value="${h(server?.fingerprint)}" dir="ltr" required placeholder="SHA256:…" pattern="SHA256:[A-Za-z0-9+/]{43}"></label><p class="form-note">اثر انگشت را از کنسول معتبر خود سرور دریافت کنید. پذیرش خودکار کلید میزبان انجام نمی‌شود.</p><label>روش ورود<select name="credentialType">${server ? '<option value="">بدون تغییر اطلاعات محرمانه</option>' : ''}<option value="key">کلید خصوصی SSH</option><option value="password">رمز عبور SSH</option></select></label><div id="key-fields"><label>کلید خصوصی<textarea name="privateKey" dir="ltr" spellcheck="false" autocomplete="off" maxlength="32768" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label><label>عبارت عبور کلید (اختیاری)<input type="password" name="passphrase" dir="ltr" autocomplete="new-password" maxlength="4096"></label></div><div id="password-fields" hidden><label>رمز SSH<input type="password" name="sshPassword" dir="ltr" autocomplete="new-password" maxlength="4096"></label></div>${server ? `<label><input type="checkbox" name="enabled" ${server.enabled ? 'checked' : ''}>دسترسی به سرور فعال باشد</label>` : ''}<p class="form-note">از کاربر اختصاصی بدون دسترسی root و مجوزهای محدود روی لینوکس استفاده کنید. اطلاعات محرمانه پس از ذخیره به مرورگر برنمی‌گردد.</p><p class="error" role="alert"></p><div class="actions"><button class="secondary" type="button" data-action="close">انصراف</button><button type="submit">ذخیرهٔ سرور</button></div></form>`);
  const form = $('#server-form');
  const update = () => { $('#key-fields').hidden = form.elements.credentialType.value !== 'key'; $('#password-fields').hidden = form.elements.credentialType.value !== 'password'; };
  form.elements.credentialType.addEventListener('change', update); update();
  formHandler(form, async data => {
    const type = data.get('credentialType'), body = { name: data.get('name'), address: data.get('address'), port: Number(data.get('port')), username: data.get('username'), fingerprint: data.get('fingerprint') };
    if (type === 'key') body.credential = { type, privateKey: data.get('privateKey'), ...(data.get('passphrase') ? { passphrase: data.get('passphrase') } : {}) };
    if (type === 'password') body.credential = { type, password: data.get('sshPassword') };
    if (server) { body.enabled = data.has('enabled'); body.revision = server.revision; }
    await api(server ? `/admin/servers/${server.id}` : '/admin/servers', { method: server ? 'PATCH' : 'POST', body: JSON.stringify(body) });
    form.reset(); closeModal(); toast('سرور ذخیره شد'); await refresh();
  });
}
function jobForm(serverId) {
  const servers = state.servers.filter(s => s.enabled && (s.permissions.diagnostics || s.permissions.execute));
  if (!servers.length) return toast('سرور مجازی برای اجرای کار در دسترس نیست', true);
  openModal('درخواست اجرای کار', `<form id="job-form"><label>سرور<select name="serverId">${servers.map(server => `<option value="${server.id}" ${server.id === serverId ? 'selected' : ''}>${h(server.name)}</option>`).join('')}</select></label><label>نوع کار<select name="kind"><option value="diagnostic">عیب‌یابی ثابت</option><option value="command">دستور آزاد با تأیید مدیر</option></select></label><div id="diagnostic-field"><label>عیب‌یابی<select name="diagnostic">${Object.entries(diagnostics).map(([key, name]) => `<option value="${key}">${name}</option>`).join('')}</select></label></div><div id="command-field" hidden><label>متن دقیق دستور<textarea name="command" dir="ltr" spellcheck="false" maxlength="16384" placeholder="systemctl status nginx --no-pager"></textarea></label><p class="form-note">رمز و توکن را در دستور وارد نکنید. خروجی این کار برای حساب درخواست‌کننده و GPT قابل مشاهده خواهد بود.</p></div><label>هدف اجرای کار<textarea name="reason" required minlength="5" maxlength="1000" placeholder="بررسی وضعیت سرویس برای عیب‌یابی"></textarea></label><p class="error" role="alert"></p><div class="actions"><button type="submit">ثبت درخواست</button></div></form>`);
  const form = $('#job-form'), requestKey = crypto.randomUUID();
  const update = () => {
    const server = servers.find(s => s.id === form.elements.serverId.value), kind = form.elements.kind;
    kind.options[0].disabled = !server.permissions.diagnostics; kind.options[1].disabled = !server.permissions.execute;
    if (kind.selectedOptions[0].disabled) kind.value = server.permissions.diagnostics ? 'diagnostic' : 'command';
    $('#diagnostic-field').hidden = kind.value !== 'diagnostic'; $('#command-field').hidden = kind.value !== 'command'; form.elements.command.required = kind.value === 'command';
  };
  form.elements.kind.addEventListener('change', update); form.elements.serverId.addEventListener('change', update); update();
  formHandler(form, async data => {
    const body = { serverId: data.get('serverId'), kind: data.get('kind'), reason: data.get('reason'), requestKey };
    if (body.kind === 'command') body.command = data.get('command'); else body.diagnostic = data.get('diagnostic');
    const job = await post('/jobs', body); closeModal(); toast(job.status === 'pending' ? 'درخواست در صف تأیید مدیر قرار گرفت' : 'عیب‌یابی در صف اجرا قرار گرفت'); await refresh(); await jobDetail(job.id);
  });
}
async function jobDetail(id) {
  const job = await api(`/jobs/${id}`), server = state.servers.find(s => s.id === job.serverId);
  const result = job.result;
  openModal('جزئیات اجرای کار', `<div class="detail-grid"><p><span>سرور</span>${h(job.serverName)}</p><p><span>وضعیت</span>${badge(job.status)}</p><p><span>درخواست‌کننده</span>${h(job.username)}</p><p><span>زمان درخواست</span>${h(date(job.createdAt))}</p>${server?.address ? `<p><span>مقصد</span><code>${h(server.username)}@${h(server.address)}:${server.port}</code></p>` : ''}<p><span>مهلت شروع</span>${h(date(job.expiresAt))}</p></div><p class="small muted">هدف اجرا</p><p>${h(job.reason)}</p><p class="small muted">متن دقیق دستور</p><pre>${h(job.command)}</pre>${job.status === 'pending' ? '<div class="notice">با تأیید، همین دستور روی سرور بالا اجرا می‌شود. پیش از تأیید، اثر دستور و احتمال نمایش اطلاعات محرمانه در خروجی را بررسی کنید.</div>' : ''}${result ? `<div class="detail-grid"><p><span>کد خروج</span>${h(result.exitCode ?? 'نامشخص')}</p><p><span>وضعیت مقصد</span>${result.remoteState === 'finished' ? 'فرایند پایان یافته' : 'نامشخص / نیازمند بررسی'}</p></div>${result.truncated ? '<div class="notice">خروجی به سقف مجاز رسید و اتصال متوقف شد؛ خروجی کامل نیست.</div>' : ''}<p class="small muted">stdout</p><pre>${h(result.stdout || 'بدون خروجی')}</pre><p class="small muted">stderr</p><pre>${h(result.stderr || 'بدون خروجی')}</pre>` : ''}${job.status === 'interrupted' ? '<div class="notice">درگاه هنگام اجرای کار قطع شده است. وضعیت مقصد را پیش از اجرای دوباره بررسی کنید.</div>' : ''}${job.message ? `<div class="notice">${h(job.message)}</div>` : ''}<div class="actions">${job.status === 'pending' && state.user.role === 'admin' ? `<button data-action="approve" data-id="${job.id}" data-hash="${job.commandHash}">تأیید و اجرای همین دستور</button><button class="danger" data-action="reject" data-id="${job.id}">رد درخواست</button>` : ''}${['pending', 'queued', 'running', 'cancelling'].includes(job.status) ? `<button class="secondary" data-action="cancel-job" data-id="${job.id}">توقف کار</button>` : ''}<button class="secondary" data-action="job-detail" data-id="${job.id}">تازه‌سازی وضعیت</button></div>`);
}
function userForm(id) {
  const user = state.users.find(u => u.id === id);
  openModal(user ? 'مدیریت حساب' : 'افزودن کاربر', `<form id="user-form">${user ? `<p>${h(user.username)}</p>` : '<label>نام کاربری<input name="username" dir="ltr" required pattern="[a-zA-Z0-9_.@-]{3,80}" maxlength="80" autocomplete="off"></label>'}<label>${user ? 'رمز جدید (برای حفظ رمز خالی بگذارید)' : 'رمز اولیه'}<input name="password" type="password" dir="ltr" minlength="14" maxlength="256" autocomplete="new-password" ${user ? '' : 'required'}></label><label>نقش<select name="role">${Object.entries(roles).map(([key, role]) => `<option value="${key}" ${(user?.role || 'operator') === key ? 'selected' : ''}>${role}</option>`).join('')}</select></label>${user ? `<label><input name="enabled" type="checkbox" ${user.enabled ? 'checked' : ''}>حساب فعال باشد</label><label><input name="resetMfa" type="checkbox">صدور کلید جدید تأیید دو مرحله‌ای</label><p class="form-note">ذخیرهٔ تغییرات، نشست‌ها و توکن‌های قبلی این حساب را بی‌اعتبار می‌کند.</p>` : '<p class="form-note">کلید تأیید دو مرحله‌ای پس از ساخت حساب یک بار نمایش داده می‌شود. آن را امن به صاحب حساب تحویل دهید.</p>'}<p class="error" role="alert"></p><div class="actions"><button type="submit">${user ? 'ذخیرهٔ تغییرات' : 'ساخت حساب'}</button></div></form>`);
  formHandler($('#user-form'), async data => {
    const body = { role: data.get('role') }; if (data.get('password')) body.password = data.get('password');
    if (user) { body.enabled = data.has('enabled'); body.resetMfa = data.has('resetMfa'); } else body.username = data.get('username');
    const result = await api(user ? `/admin/users/${user.id}` : '/admin/users', { method: user ? 'PATCH' : 'POST', body: JSON.stringify(body) });
    if (result.mfaSecret) openModal('راه‌اندازی تأیید دو مرحله‌ای', `<div class="notice">این کلید فقط یک بار نمایش داده می‌شود. آن را در برنامهٔ Authenticator صاحب حساب اضافه کنید.</div><p>حساب: <b>${h(result.user.username)}</b></p><code class="secret ltr">${h(result.mfaSecret)}</code><p class="small muted">TOTP / ۶ رقم / بازهٔ ۳۰ ثانیه. از ارسال این کلید در گفتگو با GPT خودداری کنید.</p><div class="actions"><button data-action="close">کلید را امن ذخیره کردم</button></div>`);
    else closeModal();
    toast('حساب ذخیره شد');
    if (user?.id === state.user.id) {
      if (result.mfaSecret) $('#modal').addEventListener('close', () => void boot(), { once: true });
      else await boot();
    } else await refresh();
  });
}
document.addEventListener('click', async event => {
  const button = event.target.closest('[data-action]'); if (!button || button.disabled) return;
  const { action, id } = button.dataset;
  try {
    if (action === 'navigate') location.hash = id;
    if (action === 'close') closeModal();
    if (action === 'add-server') serverForm();
    if (action === 'edit-server') serverForm(id);
    if (action === 'new-job' || action === 'server-job') jobForm(id);
    if (action === 'job-detail') await jobDetail(id);
    if (['approve', 'reject', 'cancel-job'].includes(action)) {
      button.disabled = true;
      await post(`/jobs/${id}/${action === 'cancel-job' ? 'cancel' : action}`, action === 'approve' ? { commandHash: button.dataset.hash } : {});
      toast(action === 'approve' ? 'کار تأیید و در صف اجرا قرار گرفت' : 'درخواست ثبت شد'); await refresh(); await jobDetail(id);
    }
    if (action === 'add-user') userForm();
    if (action === 'edit-user') userForm(id);
    if (action === 'user-grants') { state.grantUser = id; if (location.hash === '#grants') await render(); else location.hash = 'grants'; }
    if (action === 'revoke') { await api(`/connections/${id}`, { method: 'DELETE' }); toast('اتصال لغو شد'); await refresh(); }
    if (action === 'copy-url') { await navigator.clipboard.writeText(state.settings?.mcpUrl || `${location.origin}/mcp`); toast('نشانی اتصال کپی شد'); }
  } catch (error) { toast(error.message, true); } finally { button.disabled = false; }
});
$('#logout').addEventListener('click', async () => { try { await post('/logout'); closeModal(); await boot(); } catch (error) { toast(error.message, true); } });
$('#refresh').addEventListener('click', () => void refresh());
window.addEventListener('hashchange', () => { if (state.user) void render(); });
setInterval(() => { if (state.user && !document.hidden && !$('#modal').open && ['overview', 'jobs', 'servers'].includes(state.view)) void refresh(); }, 5000);
void boot();
