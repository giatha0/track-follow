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
  const body = {
    chat_id: TG_CHAT_ID,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
  };
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) console.error("Telegram error", await r.text());
  } catch (e) {
    console.error("Telegram fetch failed", e);
  }
}

// --- Neynar helpers ---
const NEYNAR_SECRET = process.env.NEYNAR_WEBHOOK_SECRET || "";
const NEYNAR_API_KEY = process.env.NEYNAR_API_KEY;

// Cache nhẹ map FID -> username/display_name
const userCache = new Map();
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
        for (const u of arr)
          userCache.set(Number(u.fid), {
            username: u.username,
            display_name: u.display_name,
            ts: now,
          });
      } else {
        console.error("bulk users failed", await r.text());
      }
    } catch (e) {
      console.error("bulk users error", e);
    }
  }
  const out = {};
  for (const fid of fids) {
    const c = userCache.get(fid);
    out[fid] = c
      ? c
      : { username: `fid:${fid}`, display_name: `fid:${fid}` };
  }
  return out;
}

// Express cần RAW body để verify HMAC
app.use(WEBHOOK_PATH, express.raw({ type: "application/json" }));

function verifySignature(req) {
  const signature = req.header("X-Neynar-Signature");
  if (!signature || !NEYNAR_SECRET) return true;
  const payload = req.body;
  const h = crypto.createHmac("sha512", NEYNAR_SECRET).update(payload).digest("hex");
  return h === signature;
}

// idempotency chống trùng
const seen = new Set();
function seenBefore(id) {
  if (!id) return false;
  if (seen.has(id)) return true;
  seen.add(id);
  if (seen.size > 5000) {
    const first = seen.values().next().value;
    seen.delete(first);
  }
  return false;
}

// --- Helper: rút thông tin follow/unfollow từ payload Neynar ---
function extractFollow(evt) {
  const d = evt?.data || {};
  const actor_fid = Number(
    d.actor_fid ?? d.user?.fid ?? d.user_fid ?? d.follower_fid ?? d.from_fid
  );
  const target_fid = Number(
    d.target_fid ?? d.target_user?.fid ?? d.followed_fid ?? d.to_fid
  );

  const actor_username =
    d.user?.username ?? d.actor?.username ?? d.user_username ?? undefined;
  const target_username =
    d.target_user?.username ?? d.target?.username ?? d.target_username ?? undefined;

  const ts =
    d.timestamp ??
    d.event_timestamp ??
    evt.created_at ??
    Date.now();

  return { actor_fid, target_fid, actor_username, target_username, ts };
}

// --- Helper: format ngày + giờ UTC+7 ---
function formatDateTimeUTC7(ts) {
  const t = typeof ts === "number" ? ts : Date.parse(ts);
  const d = new Date(t);
  const offsetMs = 7 * 60 * 60 * 1000;
  const local = new Date(d.getTime() + offsetMs);
  const day = String(local.getUTCDate()).padStart(2, "0");
  const month = String(local.getUTCMonth() + 1).padStart(2, "0");
  const hours = String(local.getUTCHours()).padStart(2, "0");
  const minutes = String(local.getUTCMinutes()).padStart(2, "0");
  return `${day}/${month} ${hours}:${minutes}`;
}

// --- Main webhook handler ---
app.post(WEBHOOK_PATH, async (req, res) => {
  try {
    if (!verifySignature(req))
      return res.status(401).send("invalid signature");

    const evt = JSON.parse(req.body.toString("utf8"));
    if (seenBefore(evt.id)) return res.send("ok");

    if (evt?.type === "follow.created" || evt?.type === "follow.deleted") {
      const { actor_fid, target_fid, actor_username, target_username, ts } =
        extractFollow(evt);

      if (!actor_fid || !target_fid) {
        await sendTG(
          `⚠️ Không đọc được FID từ payload.\n<pre>${JSON.stringify(
            evt
          ).slice(0, 1000)}</pre>`
        );
        return res.send("ok");
      }

      let aUser = actor_username;
      let tUser = target_username;
      if (!aUser || !tUser) {
        const map = await fetchUsersByFids([actor_fid, target_fid]);
        aUser = aUser ?? map[actor_fid]?.username ?? String(actor_fid);
        tUser = tUser ?? map[target_fid]?.username ?? String(target_fid);
      }

      const verbUpper = evt.type === "follow.created" ? "FOLLOWED" : "UNFOLLOWED";
      const aLink = `<a href="https://farcaster.xyz/${aUser}">${aUser}</a>`;
      const tLink = `<a href="https://farcaster.xyz/${tUser}">${tUser}</a>`;
      const timeStr = formatDateTimeUTC7(ts);

      const lines = [
        `${aLink} <b>${verbUpper}</b> ${tLink}`,
        timeStr,
      ];
      await sendTG(lines.join("\n"));
    }

    res.send("ok");
  } catch (e) {
    console.error("handler error", e);
    res.status(500).send("error");
  }
});

// Health check
app.get("/health", (_, res) => res.send("ok"));
app.get("/", (_, res) => res.send("Farcaster Follow Notifier is running"));

app.listen(PORT, () => console.log(`Listening on :${PORT}`));