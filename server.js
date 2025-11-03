import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const WEBHOOK_PATH = "/webhooks/neynar";

// --- Telegram helper ---
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
async function sendTG(text) {
  if (!TG_TOKEN || !TG_CHAT_ID) return;
  const url = `https://api.telegram.org/bot${TG_TOKEN}/sendMessage`;
  const body = { chat_id: TG_CHAT_ID, text, parse_mode: "HTML", disable_web_page_preview: true };
  try {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!r.ok) console.error("Telegram error", await r.text());
  } catch (e) {
    console.error("Telegram fetch failed", e);
  }
}

// --- Neynar helpers ---
const NEYNAR_SECRET = process.env.NEYNAR_WEBHOOK_SECRET || ""; // optional for now
const NEYNAR_API_KEY = process.env.NEYNAR_API_KEY || "";
const TRACK_FIDS = String(process.env.TRACK_FIDS || "3")
  .split(",")
  .map((s) => Number(s.trim()))
  .filter((n) => Number.isFinite(n));

console.log("TRACK_FIDS parsed =", TRACK_FIDS);

// Cache nhẹ map FID -> username để enrich tin nhắn
const userCache = new Map(); // fid -> { username, display_name, ts }
const CACHE_TTL_MS = 10 * 60 * 1000;
async function fetchUsersByFids(fids = []) {
  if (!fids.length) return {};
  const need = [];
  const now = Date.now();
  for (const fid of fids) {
    const c = userCache.get(fid);
    if (!c || now - c.ts > CACHE_TTL_MS) need.push(fid);
  }
  if (need.length) {
    try {
      const url = new URL("https://api.neynar.com/v2/farcaster/user/bulk/");
      url.searchParams.set("fids", need.join(","));
      const r = await fetch(url, { headers: { "x-api-key": NEYNAR_API_KEY } });
      if (r.ok) {
        const js = await r.json();
        const arr = js.users || js.result || js.data || [];
        for (const u of arr) userCache.set(Number(u.fid), { username: u.username, display_name: u.display_name, ts: now });
      } else {
        console.error("bulk users failed", await r.text());
      }
    } catch (e) { console.error("bulk users error", e); }
  }
  const out = {};
  for (const fid of fids) {
    const c = userCache.get(fid);
    out[fid] = c ? c : { username: `fid:${fid}`, display_name: `fid:${fid}` };
  }
  return out;
}

// Express cần RAW body cho verify
app.use(WEBHOOK_PATH, express.raw({ type: "application/json" }));

function verifySignature(req) {
  const signature = req.header("X-Neynar-Signature");
  if (!signature || !NEYNAR_SECRET) return true; // allow if no secret configured
  const payload = req.body; // Buffer
  const h = crypto.createHmac("sha512", NEYNAR_SECRET).update(payload).digest("hex");
  return h === signature;
}

// idempotency chống trùng (sản xuất nên dùng Redis/DB)
const seen = new Set();
function seenBefore(id) {
  if (!id) return false;
  if (seen.has(id)) return true;
  seen.add(id);
  if (seen.size > 5000) {
    const first = seen.values().next().value; seen.delete(first);
  }
  return false;
}

app.post(WEBHOOK_PATH, async (req, res) => {
  try {
    if (!verifySignature(req)) return res.status(401).send("invalid signature");
    const evt = JSON.parse(req.body.toString("utf8"));

    // expected: { id, type: "follow.created"|"follow.deleted", data: { actor_fid, target_fid, timestamp } }
    if (seenBefore(evt.id)) return res.send("ok");

    if (evt?.type === "follow.created" || evt?.type === "follow.deleted") {
      const { actor_fid, target_fid } = evt.data || {};
      // Chỉ quan tâm outbound của các FID mình theo dõi
      if (!TRACK_FIDS.includes(Number(actor_fid))) return res.send("ok");

      const map = await fetchUsersByFids([actor_fid, target_fid]);
      const actor = map[actor_fid] || {};
      const target = map[target_fid] || {};

      const action = evt.type === "follow.created" ? "FOLLOW" : "UNFOLLOW";
      const msg = [
        `🔔 <b>${action}</b>`,
        `👤 <b>${actor.display_name || actor.username || actor_fid}</b> (@${actor.username || "?"})`,
        `${action === "FOLLOW" ? "➡️" : "↩️"} <b>${target.display_name || target.username || target_fid}</b> (@${target.username || "?"})`,
        `FID: ${actor_fid} → ${target_fid}`,
        evt.timestamp ? `⏱ ${new Date(evt.timestamp).toISOString()}` : null
      ].filter(Boolean).join("\n");

      await sendTG(msg);
    }

    res.send("ok");
  } catch (e) {
    console.error("handler error", e);
    res.status(500).send("error");
  }
});

app.get("/health", (_, res) => res.send("ok"));

app.get("/", (_, res) => res.send("Farcaster Follow Notifier is running"));

app.listen(PORT, () => console.log(`Listening on :${PORT}`));
