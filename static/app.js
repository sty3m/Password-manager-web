const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const res = await fetch(path, { credentials: "same-origin", headers: { "Content-Type": "application/json" }, ...options });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
function showMessage(el, text, type) { el.textContent = text; el.className = "form-message" + (type ? " " + type : ""); }
function showAuthView() { $("auth-view").classList.remove("hidden"); $("app-view").classList.add("hidden"); }
function showAppView(username) { $("auth-view").classList.add("hidden"); $("app-view").classList.remove("hidden"); $("whoami").textContent = username; loadServices(); }

document.querySelectorAll(".tab-btn").forEach(btn => btn.addEventListener("click", () => {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active")); btn.classList.add("active");
  const tab = btn.dataset.tab; $("login-form").classList.toggle("hidden", tab !== "login"); $("register-form").classList.toggle("hidden", tab !== "register");
}));

$("login-form").addEventListener("submit", async e => {
  e.preventDefault(); const msg = $("login-message"); showMessage(msg, "", "");
  try { const data = await api("/api/login", { method: "POST", body: JSON.stringify({ username: $("login-username").value, master_password: $("login-password").value }) }); $("login-password").value = ""; showAppView(data.username); }
  catch (err) { showMessage(msg, err.message, "error"); }
});

$("register-form").addEventListener("submit", async e => {
  e.preventDefault(); const msg = $("register-message"); showMessage(msg, "", "");
  const pw = $("register-password").value;
  if (pw !== $("register-password-confirm").value) { showMessage(msg, "Passwords do not match.", "error"); return; }
  try { await api("/api/register", { method: "POST", body: JSON.stringify({ username: $("register-username").value, master_password: pw }) }); showMessage(msg, "Account created. You can sign in now.", "success"); $("register-form").reset(); document.querySelector('.tab-btn[data-tab="login"]').click(); }
  catch (err) { showMessage(msg, err.message, "error"); }
});

$("logout-btn").addEventListener("click", async () => { await api("/api/logout", { method: "POST" }).catch(() => {}); showAuthView(); });
let currentService = null;
async function loadServices() {
  const data = await api("/api/entries"); const list = $("service-list"); list.innerHTML = ""; $("empty-state").classList.toggle("hidden", data.services.length > 0);
  data.services.forEach(service => { const li = document.createElement("li"); li.textContent = service; li.dataset.service = service; if (service === currentService) li.classList.add("active"); li.addEventListener("click", () => selectService(service)); list.appendChild(li); });
}
async function selectService(service) {
  currentService = service; document.querySelectorAll("#service-list li").forEach(li => li.classList.toggle("active", li.dataset.service === service)); hideEntryForm(); $("no-selection").classList.add("hidden");
  const entry = await api(`/api/entries/${encodeURIComponent(service)}`); $("detail-service").textContent = entry.service; $("detail-username").textContent = entry.username || "(none)"; $("detail-password").textContent = entry.password; $("detail-password").classList.add("masked"); $("reveal-password-btn").textContent = "Show"; $("detail-notes").textContent = entry.notes || "(none)"; $("entry-detail").classList.remove("hidden");
}
$("reveal-password-btn").addEventListener("click", () => { const el = $("detail-password"); const revealed = !el.classList.contains("masked"); el.classList.toggle("masked", revealed); $("reveal-password-btn").textContent = revealed ? "Show" : "Hide"; });
document.querySelectorAll(".copy-btn").forEach(btn => btn.addEventListener("click", async () => { try { await navigator.clipboard.writeText($(btn.dataset.copyTarget).textContent); const original = btn.textContent; btn.textContent = "Copied!"; setTimeout(() => btn.textContent = original, 1200); } catch (e) {} }));
$("delete-entry-btn").addEventListener("click", async () => { if (!currentService || !confirm(`Delete the entry for "${currentService}"? This cannot be undone.`)) return; await api(`/api/entries/${encodeURIComponent(currentService)}`, { method: "DELETE" }); currentService = null; $("entry-detail").classList.add("hidden"); $("no-selection").classList.remove("hidden"); loadServices(); });
function hideEntryForm() { $("entry-form-card").classList.add("hidden"); }
$("new-entry-btn").addEventListener("click", () => { $("entry-detail").classList.add("hidden"); $("no-selection").classList.add("hidden"); $("entry-form").reset(); $("generator-options").classList.add("hidden"); showMessage($("entry-form-message"), "", ""); $("entry-form-card").classList.remove("hidden"); $("entry-service").focus(); });
$("cancel-entry-btn").addEventListener("click", () => { hideEntryForm(); if (currentService) $("entry-detail").classList.remove("hidden"); else $("no-selection").classList.remove("hidden"); });
$("generate-btn").addEventListener("click", () => { $("generator-options").classList.toggle("hidden"); });
$("gen-length").addEventListener("input", e => { $("gen-length-value").textContent = e.target.value; });
async function generateAndFillPassword() { const data = await api("/api/generate-password", { method: "POST", body: JSON.stringify({ length: parseInt($("gen-length").value,10), use_symbols: $("gen-symbols").checked }) }); $("entry-password").value = data.password; }
$("gen-length").addEventListener("change", generateAndFillPassword); $("gen-symbols").addEventListener("change", generateAndFillPassword);
$("entry-form").addEventListener("submit", async e => { e.preventDefault(); const msg = $("entry-form-message"); try { await api("/api/entries", { method: "POST", body: JSON.stringify({ service: $("entry-service").value, username: $("entry-username").value, password: $("entry-password").value, notes: $("entry-notes").value }) }); const saved = $("entry-service").value; hideEntryForm(); await loadServices(); selectService(saved); } catch (err) { showMessage(msg, err.message, "error"); } });
$("settings-btn").addEventListener("click", () => { $("settings-form").reset(); showMessage($("settings-message"), "", ""); $("settings-overlay").classList.remove("hidden"); });
$("settings-cancel-btn").addEventListener("click", () => $("settings-overlay").classList.add("hidden"));
$("settings-form").addEventListener("submit", async e => { e.preventDefault(); const msg=$("settings-message"); const pw=$("new-master-password").value; if(pw!==$("new-master-password-confirm").value){showMessage(msg,"Passwords do not match.","error");return;} try{await api("/api/change-master-password",{method:"POST",body:JSON.stringify({new_master_password:pw})});showMessage(msg,"Master password updated.","success");setTimeout(()=>$("settings-overlay").classList.add("hidden"),900);}catch(err){showMessage(msg,err.message,"error");} });
(async function boot(){try{const data=await api("/api/me");if(data.authenticated){showAppView(data.username);return;}}catch(e){}showAuthView();})();
