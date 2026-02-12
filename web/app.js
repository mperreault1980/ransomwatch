/* ransomwatch — client-side IP lookup against CISA #StopRansomware IOCs */

let DB = null;

// Defanging: replace bracket/paren dot notations with real dots
function refang(text) {
    return text.replace(/\[\.\]|\[dot\]|\(dot\)|\(\.\)/gi, ".");
}

// Validate IPv4
function isValidIPv4(ip) {
    const parts = ip.split(".");
    if (parts.length !== 4) return false;
    return parts.every(p => {
        const n = Number(p);
        return /^\d{1,3}$/.test(p) && n >= 0 && n <= 255;
    });
}

// Search the loaded database for an IP
function searchIP(rawQuery) {
    const normalized = refang(rawQuery.trim());

    if (!isValidIPv4(normalized)) {
        return { query: rawQuery, normalized, error: "Invalid IPv4 address" };
    }

    const matches = DB.iocs
        .filter(ioc => ioc.type === "ipv4-addr" && ioc.value === normalized)
        .map(ioc => {
            const adv = DB.advisories[ioc.advisory_id] || {};
            return {
                advisory_id: ioc.advisory_id,
                title: adv.title || "Unknown",
                url: adv.url || "#",
                source: ioc.source,
                published: adv.published || null,
            };
        });

    // Deduplicate by advisory_id + source
    const seen = new Set();
    const unique = matches.filter(m => {
        const key = m.advisory_id + m.source;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    return {
        query: rawQuery,
        normalized,
        found: unique.length > 0,
        matches: unique,
    };
}

function stripPrefix(title) {
    return title.replace(/^#?StopRansomware:\s*/i, "");
}

// Render search results
function renderResults(result) {
    const el = document.getElementById("results");
    el.classList.remove("hidden", "match", "clean");

    if (result.error) {
        el.classList.add("match");
        el.innerHTML = `<h2>${escapeHtml(result.error)}</h2>
            <p class="normalized"><code>${escapeHtml(result.normalized)}</code></p>`;
        return;
    }

    const showNorm = result.query.trim() !== result.normalized;
    const normHtml = showNorm
        ? `<p class="normalized">${escapeHtml(result.query)} &rarr; <code>${escapeHtml(result.normalized)}</code></p>`
        : "";

    if (!result.found) {
        el.classList.add("clean");
        el.innerHTML = `<h2>No matches found</h2>${normHtml}
            <p><code>${escapeHtml(result.normalized)}</code> does not appear in any CISA #StopRansomware advisory.</p>`;
        return;
    }

    el.classList.add("match");

    const rows = result.matches.map(m => `
        <tr>
            <td><span class="badge">${escapeHtml(m.advisory_id)}</span></td>
            <td>${escapeHtml(stripPrefix(m.title))}</td>
            <td><span class="badge">${escapeHtml(m.source)}</span></td>
            <td><a href="${escapeHtml(m.url)}" target="_blank" rel="noopener">View</a></td>
        </tr>
    `).join("");

    el.innerHTML = `
        <h2>MATCH FOUND &mdash; ${result.matches.length} advisory(ies)</h2>
        ${normHtml}
        <p><code>${escapeHtml(result.normalized)}</code> appears in CISA ransomware threat intelligence.</p>
        <table class="match-table">
            <thead><tr><th>Advisory</th><th>Group / Campaign</th><th>Source</th><th>Link</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}

function escapeHtml(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
}

// Populate stats cards
function renderStats() {
    if (!DB) return;

    const ipCount = DB.iocs.filter(i => i.type === "ipv4-addr").length;
    const groups = new Set();
    Object.values(DB.advisories).forEach(a => {
        groups.add(stripPrefix(a.title));
    });

    document.getElementById("stat-advisories").textContent = DB.stats.advisory_count;
    document.getElementById("stat-iocs").textContent = DB.stats.ioc_count;
    document.getElementById("stat-ips").textContent = ipCount;
    document.getElementById("stat-groups").textContent = groups.size;
}

// Populate groups list
function renderGroups() {
    if (!DB) return;

    const entries = Object.entries(DB.advisories)
        .map(([id, a]) => ({ id, name: stripPrefix(a.title), url: a.url }))
        .sort((a, b) => a.name.localeCompare(b.name));

    const html = entries.map(g => `
        <div class="group-item">
            <a href="${escapeHtml(g.url)}" target="_blank" rel="noopener">${escapeHtml(g.name)}</a>
            <div class="group-id">${escapeHtml(g.id)}</div>
        </div>
    `).join("");

    document.getElementById("groups-list").innerHTML = html;
}

// Init
async function init() {
    try {
        const resp = await fetch("data.json");
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        DB = await resp.json();
    } catch (e) {
        document.getElementById("results").classList.remove("hidden");
        document.getElementById("results").classList.add("match");
        document.getElementById("results").innerHTML =
            `<h2>Failed to load data</h2><p>Could not fetch IOC database. Run the build step first.</p>`;
        return;
    }

    renderStats();
    renderGroups();

    document.getElementById("search-form").addEventListener("submit", (e) => {
        e.preventDefault();
        const query = document.getElementById("ip-input").value;
        if (!query.trim()) return;
        const result = searchIP(query);
        renderResults(result);
    });

    // Support ?ip= query parameter for direct linking
    const params = new URLSearchParams(window.location.search);
    const prefilledIP = params.get("ip");
    if (prefilledIP) {
        document.getElementById("ip-input").value = prefilledIP;
        renderResults(searchIP(prefilledIP));
    }
}

init();
