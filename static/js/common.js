/* VaultSense shared front-end code. All user/bot text is inserted with textContent, never innerHTML. */
(function () {
  const CFG = window.VS_CONFIG || {};
  const sb = (CFG.supabaseUrl && CFG.supabaseAnonKey && window.supabase)
    ? window.supabase.createClient(CFG.supabaseUrl, CFG.supabaseAnonKey) : null;

  const ICONS = {
    shield: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
    shieldSm: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/></svg>',
    terminal: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>',
    db: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/></svg>',
    bot: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><rect x="4" y="8" width="16" height="11" rx="2"/><path d="M12 4v4M9 13h.01M15 13h.01"/></svg>',
    send: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg>',
    spark: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5L18 18M6 18l2.5-2.5M15.5 8.5L18 6"/></svg>',
    play: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M7 4l13 8-13 8z"/></svg>',
    chev: '<svg class="chev" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 6l6 6-6 6"/></svg>',
    arrow: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M5 12h14M13 6l6 6-6 6"/></svg>'
  };

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "html") n.innerHTML = v;          // only ever used with the constant ICONS above
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat()) if (k != null && k !== false) n.append(k.nodeType ? k : document.createTextNode(String(k)));
    return n;
  }

  const RULES = {
    instruction_override: "Tried to override instructions", instruction_override_2: "Tried to override instructions",
    role_hijack: "Jailbreak / role change", prompt_extraction: "Tried to steal system prompt",
    fake_delimiter: "Fake system message", other_customers_data: "Asked for other customers' data",
    bulk_or_third_party_data: "Asked for other customers' data", exfil_markdown: "Data exfiltration attempt",
    exfil_send: "Data exfiltration attempt", hidden_unicode_tags: "Hidden or obfuscated text",
    zero_width_chars: "Hidden or obfuscated text", base64_payload: "Hidden or obfuscated text",
    spaced_letters: "Hidden or obfuscated text", unicode_lookalikes: "Hidden or obfuscated text",
    authority_claim: "Fake authority", credential_request: "Credential request", card_number: "Sensitive data in reply",
    ssn: "Sensitive data in reply", account_number: "Sensitive data in reply", canary_leak: "System prompt leak",
    prompt_fragment_leak: "System prompt leak", addressed_to_ai: "Document talking to the AI",
    bypass_verification: "Tried to skip verification", session_locked: "Locked session", action_command: "Money movement or account change",
    new_instructions: "Supplied new instructions", hide_from_user: "Asked to hide actions", secret_request: "Asked for system secrets",
    dual_persona: "Jailbreak / role change", fake_identity_fraud: "Fake identity", hypothetical_wrapper: "Fictional framing",
    encoding_request: "Decode-and-follow trick", urgency_pressure: "High-pressure urgency", unapproved_link: "Unapproved link",
    markdown_image: "Image exfiltration", claimed_action: "Claimed an action", other: "Other"
  };
  const WHY = {
    instruction_override: "The message tries to replace the bank assistant's trusted instructions with new ones.",
    instruction_override_2: "The message tries to replace the bank assistant's trusted instructions with new ones.",
    role_hijack: "The message tries to switch the assistant into an unrestricted role.",
    prompt_extraction: "The message tries to make the assistant reveal its hidden instructions.",
    fake_delimiter: "The message pretends to be a system message to gain extra authority.",
    other_customers_data: "The message asks for data belonging to other customers.",
    bulk_or_third_party_data: "The message asks for bulk data or someone else's account.",
    hidden_unicode_tags: "The message hides instructions in invisible characters.",
    base64_payload: "The message hides instructions in encoded text.",
    addressed_to_ai: "This document speaks directly to the AI, which normal documents never do.",
    authority_claim: "The message claims special authority to unlock restricted actions.",
    bypass_verification: "The message asks to skip identity or verification checks.",
    exfil_markdown: "The content tries to send data to an outside server through an image link.",
    exfil_send: "The content asks to send data to an outside address.",
    credential_request: "Banks never ask for passwords or one-time codes in chat.",
    canary_leak: "The reply contained the assistant's secret instructions, so it was stopped.",
    card_number: "A full card number was removed from the reply.",
    session_locked: "This session made repeated attack attempts and was locked for review."
  };
  const ruleName = r => r && r.startsWith("combo:") ? "Combined attack signals" : (RULES[r] || r || "Unknown");
  const why = rules => {
    for (const r of rules || []) if (WHY[r]) return WHY[r];
    return (rules && rules.length) ? "Signals: " + [...new Set(rules.map(ruleName))].join(", ") + "." : "Matched VaultSense's attack patterns.";
  };
  const decisionClass = d => ({ allow: "allow", review: "warn", redact: "warn", require_confirmation: "warn",
    human_review: "warn", block: "bad", deny: "bad", unguarded: "bad", off: "off" }[d] || "off");
  const chipLabel = t => ({ input: "Message", document: "Doc: " + (t.doc || ""), action: "Action: " + (t.action || ""), output: "Reply" }[t.layer] || t.layer);

  function guardChips(trace) {
    return el("div", { class: "chips" }, (trace || []).map(t => {
      const tip = [...(t.rules || []).map(ruleName), ...(t.reasons || [])].join("\n");
      return el("span", { class: "chip " + decisionClass(t.decision), title: tip || null }, chipLabel(t) + " → " + t.decision);
    }));
  }

  const money = n => "$" + Number(n || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const newId = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random()).replace(/-/g, "").slice(0, 24);

  async function session() { if (!sb) return null; const { data } = await sb.auth.getSession(); return data.session; }
  async function requireUser() {
    const s = await session();
    if (!s) { location.href = "/login?next=" + encodeURIComponent(location.pathname); return new Promise(() => {}); }
    return s;
  }
  async function isAdmin() {
    if (!sb) return false;
    try { const { data, error } = await sb.rpc("is_security_admin"); return !error && data === true; } catch (e) { return false; }
  }

  async function api(path, body) {
    const s = await session();
    const headers = { "Content-Type": "application/json" };
    if (s) headers.Authorization = "Bearer " + s.access_token;
    let r;
    try { r = await fetch(path, { method: "POST", headers, body: JSON.stringify(body) }); }
    catch (e) { throw new Error("Can't reach the VaultSense server. Check your connection and try again."); }
    let data = {};
    try { data = await r.json(); } catch (e) { /* non-JSON */ }
    if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : ("Request failed (" + r.status + ")"));
    return data;
  }

  async function header(active) {
    const host = document.getElementById("topbar");
    if (!host) return;
    const s = await session();
    const admin = s ? await isAdmin() : false;
    const link = (href, text) => el("a", { href, class: active === href ? "active" : null }, text);
    const health = el("span", { class: "dot wait" });
    const liveText = el("span", {}, "Checking engine…");
    host.replaceChildren(el("div", { class: "wrap" },
      el("a", { class: "brand", href: "/" },
        el("span", { class: "brand-mark", html: ICONS.shield }),
        el("span", {}, el("div", { class: "brand-name" }, "VaultSense"), el("div", { class: "brand-sub" }, "BY FIREWALL"))),
      s ? el("nav", { class: "nav" }, link("/dashboard", "Dashboard"), link("/assistant", "Assistant"), admin ? link("/security", "Security") : null) : null,
      el("div", { class: "spacer" }),
      el("div", { class: "live" }, health, liveText),
      s ? el("span", { class: "muted", style: "font-size:14px" }, s.user.email) : el("a", { class: "btn", href: "/login" }, "Log in"),
      s ? el("button", { class: "btn", onclick: async () => {
        try { await Promise.race([sb.auth.signOut({ scope: "local" }), new Promise(r => setTimeout(r, 1500))]); } catch (e) { /* still leave */ }
        location.href = "/"; } }, "Log out")
        : el("a", { class: "btn btn-primary", href: "/login?mode=signup" }, "Sign up")));
    try {
      const h = await (await fetch("/health")).json();
      health.className = "dot"; liveText.textContent = "Detection engine live";
      host.dataset.guard = h.guard_version || "";
    } catch (e) { health.className = "dot off"; liveText.textContent = "Engine offline"; }
    return { session: s, admin };
  }

  window.VS = { CFG, sb, el, ICONS, ruleName, why, decisionClass, guardChips, money, newId, session, requireUser, isAdmin, api, header };
})();
