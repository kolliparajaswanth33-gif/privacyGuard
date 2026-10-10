const params = new URLSearchParams(location.search);
const host = params.get("host") || "Unknown";
const targetUrl = params.get("url") || "";
document.querySelector("#host").textContent = host;
document.querySelector("#terms").textContent = params.get("terms") || "—";
document.querySelector("#back").addEventListener("click", () => history.back());
document.querySelector("#allow").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "allow-once", url: targetUrl });
});
document.querySelector("#settings").addEventListener("click", (event) => {
  event.preventDefault();
  chrome.runtime.openOptionsPage();
});
