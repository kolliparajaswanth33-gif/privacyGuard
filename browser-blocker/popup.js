const enabled = document.querySelector("#enabled");
const status = document.querySelector("#status");
const listStatus = document.querySelector("#list-status");
const updateButton = document.querySelector("#update-list");

function showListStatus(data) {
  if (data.error) { listStatus.textContent = data.error; return; }
  if (!data.loaded) { listStatus.textContent = "Not downloaded yet. Keyword checks are active."; return; }
  const updated = data.updatedAt ? new Date(data.updatedAt).toLocaleString() : "unknown time";
  listStatus.textContent = `${Number(data.count).toLocaleString()} domains · updated ${updated}`;
}

chrome.storage.local.get({ enabled: true }).then(({ enabled: value }) => {
  enabled.checked = value;
  status.textContent = value ? "Blocker is on" : "Blocker is paused";
});
chrome.runtime.sendMessage({ type: "list-status" }).then(showListStatus).catch(() => { listStatus.textContent = "List status unavailable."; });
enabled.addEventListener("change", async () => {
  await chrome.storage.local.set({ enabled: enabled.checked });
  status.textContent = enabled.checked ? "Blocker is on" : "Blocker is paused";
});
updateButton.addEventListener("click", async () => {
  updateButton.disabled = true;
  updateButton.textContent = "Downloading list…";
  listStatus.textContent = "Downloading and checking the domain list…";
  try {
    const result = await chrome.runtime.sendMessage({ type: "update-list" });
    showListStatus(result);
  } catch (error) { listStatus.textContent = error.message || "Could not update the list."; }
  finally { updateButton.disabled = false; updateButton.textContent = "Update list"; }
});
document.querySelector("#manage").addEventListener("click", () => chrome.runtime.openOptionsPage());
