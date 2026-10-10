const BETTING_TERMS = ["bet", "betting", "xbet", "casino", "gambling", "poker", "sportsbook", "bookmaker", "wager", "rummy"];
const LIST_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt";
const DB_NAME = "privacyguard-domain-lists";
let cachedDomainSet = null;

function openListDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore("lists");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function readListRecord() {
  return openListDb().then((db) => new Promise((resolve, reject) => {
    const request = db.transaction("lists", "readonly").objectStore("lists").get("gambling");
    request.onsuccess = () => { db.close(); resolve(request.result || null); };
    request.onerror = () => { db.close(); reject(request.error); };
  }));
}

function saveListRecord(record) {
  return openListDb().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction("lists", "readwrite");
    tx.objectStore("lists").put(record, "gambling");
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  }));
}

function parseDomainList(text) {
  const domains = new Set();
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    if (line.startsWith("||")) line = line.slice(2).replace(/\^.*$/, "");
    if (/^\d{1,3}(?:\.\d{1,3}){3}\s+/.test(line)) line = line.split(/\s+/).pop();
    line = line.replace(/^\*\./, "").toLowerCase().replace(/\.$/, "");
    if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(line)) domains.add(line);
  }
  return domains;
}

async function getBlocklist() {
  if (cachedDomainSet) return cachedDomainSet;
  const record = await readListRecord().catch(() => null);
  cachedDomainSet = record?.text ? parseDomainList(record.text) : new Set();
  return cachedDomainSet;
}

async function listStatus() {
  const record = await readListRecord().catch(() => null);
  return { loaded: Boolean(record?.text), count: record?.count || 0, updatedAt: record?.updatedAt || null };
}

async function updateBlocklist() {
  const response = await fetch(LIST_URL, { cache: "no-store", credentials: "omit" });
  if (!response.ok) throw new Error(`List download failed (HTTP ${response.status}).`);
  const text = await response.text();
  const domains = parseDomainList(text);
  if (domains.size < 10000) throw new Error("The downloaded list looked incomplete, so the saved list was left unchanged.");
  const record = { text, count: domains.size, updatedAt: Date.now(), source: LIST_URL };
  await saveListRecord(record);
  cachedDomainSet = domains;
  return { loaded: true, count: domains.size, updatedAt: record.updatedAt };
}

function matchesList(host, domains) {
  let candidate = host;
  while (candidate.includes(".")) {
    if (domains.has(candidate)) return true;
    candidate = candidate.slice(candidate.indexOf(".") + 1);
  }
  return domains.has(candidate);
}

async function settings() {
  return chrome.storage.local.get({ enabled: true, allowlist: [], blocklist: [] });
}

function allowed(host, allowlist) {
  return allowlist.some((entry) => host === entry || host.endsWith(`.${entry}`));
}

function explicitlyBlocked(host, blocklist) {
  return blocklist.some((entry) => host === entry || host.endsWith(`.${entry}`));
}

function matchedTerms(host) {
  const labels = host.toLowerCase().split(".");
  const tokens = labels.flatMap((label) => label.split(/[^a-z]+/).filter(Boolean));
  return BETTING_TERMS.filter((term) => tokens.includes(term));
}

async function intercept(details) {
  if (details.frameId !== 0 || details.tabId < 0) return;
  let target;
  try { target = new URL(details.url); } catch { return; }
  if (target.protocol !== "http:" && target.protocol !== "https:") return;

  const host = target.hostname.toLowerCase().replace(/\.$/, "");
  const current = await settings();
  if (!current.enabled || allowed(host, current.allowlist)) return;

  const oneTimeKey = `allow-once:${details.tabId}:${host}`;
  const oneTime = await chrome.storage.session.get(oneTimeKey);
  if (oneTime[oneTimeKey]) {
    await chrome.storage.session.remove(oneTimeKey);
    return;
  }

  const terms = matchedTerms(host);
  const domains = await getBlocklist();
  if (matchesList(host, domains)) terms.push("Maintained gambling-domain list");
  if (explicitlyBlocked(host, current.blocklist) && !terms.includes("Your block list")) terms.push("Your block list");
  if (!terms.length) return;
  const query = new URLSearchParams({ host, url: details.url, terms: terms.join(", ") });
  await chrome.tabs.update(details.tabId, { url: `${chrome.runtime.getURL("blocked.html")}?${query}` });
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => { void intercept(details); });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "list-status") {
    void listStatus().then(sendResponse).catch((error) => sendResponse({ error: error.message }));
    return true;
  }
  if (message?.type === "update-list") {
    void updateBlocklist().then(sendResponse).catch((error) => sendResponse({ error: error.message }));
    return true;
  }
  if (message?.type !== "allow-once" || !sender.tab || !Number.isInteger(sender.tab.id)) return;
  let target;
  try { target = new URL(message.url); } catch { return; }
  if (target.protocol !== "http:" && target.protocol !== "https:") return;
  const host = target.hostname.toLowerCase().replace(/\.$/, "");
  void chrome.storage.session.set({ [`allow-once:${sender.tab.id}:${host}`]: true })
    .then(() => chrome.tabs.update(sender.tab.id, { url: target.href }));
});

chrome.runtime.onInstalled.addListener(() => {
  void chrome.storage.local.get({ enabled: true, allowlist: [], blocklist: [] }).then((value) => chrome.storage.local.set(value));
});
