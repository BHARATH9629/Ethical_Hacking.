const feedEl = document.getElementById("feed");
const statusEl = document.getElementById("conn-status");
const MAX_FEED_ROWS = 50;

const RESOURCE_TO_NODE = {
  "public-conf-bucket-demo": "node-public-bucket",
  "internal-customer-data": "node-internal-bucket",
  "CustomerPII": "node-dynamodb",
  "iam": "node-iam",
  "data": "node-internal-bucket",
};

function severityClass(sev) {
  return `sev-${sev || "INFO"}`;
}

function flashNode(resource, severity) {
  if (!resource) return;
  let nodeId = null;
  for (const key of Object.keys(RESOURCE_TO_NODE)) {
    if (resource.includes(key)) {
      nodeId = RESOURCE_TO_NODE[key];
      break;
    }
  }
  if (!nodeId) return;
  const node = document.getElementById(nodeId);
  if (!node) return;
  const flashClass = `flash-${(severity || "info").toLowerCase()}`;
  node.classList.add(flashClass);
  setTimeout(() => node.classList.remove(flashClass), 2500);
}

function addFeedItem(item) {
  const li = document.createElement("li");
  li.className = severityClass(item.severity);

  const time = new Date((item.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString();

  if (item.kind === "alert") {
    li.innerHTML = `<strong>[${item.severity}] ${item.type}</strong> — ${item.message}
      <span class="meta">${time}</span>`;
  } else {
    li.innerHTML = `${item.service}:${item.action} <span class="meta">${item.access_key || "anonymous"} · ${item.resource || ""} · ${time}</span>`;
  }

  feedEl.prepend(li);
  while (feedEl.children.length > MAX_FEED_ROWS) {
    feedEl.removeChild(feedEl.lastChild);
  }

  if (item.kind === "alert") {
    flashNode(item.resource, item.severity);
  }
}

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    statusEl.textContent = "connected";
    statusEl.className = "status connected";
  };
  ws.onclose = () => {
    statusEl.textContent = "disconnected";
    statusEl.className = "status disconnected";
    setTimeout(connect, 2000);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (msg) => {
    try {
      addFeedItem(JSON.parse(msg.data));
    } catch (e) {
      console.error("bad message", e);
    }
  };
}

async function loadHistory() {
  try {
    const res = await fetch("/history");
    const alerts = await res.json();
    for (const a of alerts) addFeedItem(a);
  } catch (e) {
    console.error("history load failed", e);
  }
}

loadHistory();
connect();
