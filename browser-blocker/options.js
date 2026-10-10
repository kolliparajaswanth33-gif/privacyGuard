const area = document.querySelector("#allowlist");
const blockedArea = document.querySelector("#blocklist");
const message = document.querySelector("#message");
chrome.storage.local.get({ allowlist: [], blocklist: [] }).then(({ allowlist, blocklist }) => {
  area.value = allowlist.join("\n");
  blockedArea.value = blocklist.join("\n");
});

function readDomains(text, label) {
  const domains = [];
  for (const line of text.split(/\r?\n/)) {
    const raw = line.trim().toLowerCase();
    if (!raw) continue;
    let parsed;
    try { parsed = new URL(raw.includes("://") ? raw : `https://${raw}`); }
    catch { throw new Error(`Invalid ${label} domain: ${raw}`); }
    if (!parsed.hostname || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.hostname.includes("*") || parsed.hostname.includes(" ")) {
      throw new Error(`Enter a plain domain without a path: ${raw}`);
    }
    domains.push(parsed.hostname.toLowerCase().replace(/\.$/, ""));
  }
  return [...new Set(domains)];
}

document.querySelector("#save").addEventListener("click", async () => {
  try {
    const allowlist = readDomains(area.value, "allowed");
    const blocklist = readDomains(blockedArea.value, "blocked");
    await chrome.storage.local.set({ allowlist, blocklist });
    message.textContent = "Saved on this browser.";
  } catch (error) { message.textContent = error.message; }
});
