import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const WEBHOOK_PATH = "/webhooks/neynar";

// --- Telegram helper ---
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
// Backward compatible: default follow/unfollow channel = TELEGRAM_CHAT_ID
const TG_CHAT_ID_FOLLOW = process.env.TELEGRAM_CHAT_ID;
// Separate channel for other activities (user.updated, cast.created)
const TG_CHAT_ID_ACTIVITY = process.env.TELEGRAM_CHAT_ID_ACTIVITY || TG_CHAT_ID_FOLLOW;
const TG_CHAT_ID_TRADE = process.env.TELEGRAM_CHAT_ID_TRADE;
async function sendTG(text, chatId = TG_CHAT_ID_FOLLOW) {
  if (!TG_TOKEN || !chatId) return;
  const url = `https://api.telegram.org/bot${TG_TOKEN}/sendMessage`;
  const body = {
    chat_id: chatId,
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
// Keep last seen full profile snapshot for diff (in-memory)
const lastProfile = new Map(); // fid -> { username, display_name, bio, pfp_url, location, website }
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
            bio: u.bio || u.profile?.bio || u.about_me,
            pfp_url: u.pfp_url || u.pfp?.url,
            location: u.location || u.profile?.location,
            website: u.website || u.profile?.url || u.profile?.website,
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

// --- Helper: rút thông tin user.updated ---
function extractUserUpdated(evt) {
  const d = evt?.data || {};
  const fid = Number(d.user?.fid ?? d.fid ?? d.actor_fid ?? d.user_fid);
  const username = d.user?.username;
  const ts = d.timestamp ?? d.event_timestamp ?? evt.created_at ?? Date.now();

  // Possible shapes from Neynar
  const changesObj = d.changes || d.diff || d.updated || {};
  const updatedFields = d.updated_fields || d.fields || null; // array of keys
  const before = d.previous_user || d.before || d.old_user || d.old || {};
  const after = d.user || d.after || d.new_user || d.new || {};

  return { fid, username, ts, changesObj, updatedFields, before, after };
}

// --- Helper: rút thông tin cast.created ---
function extractCastCreated(evt) {
  const d = evt?.data || {};
  const c = d.cast || d.message || d;
  const fid = Number(c.author?.fid ?? c.user?.fid ?? c.fid ?? d.user?.fid);
  const username = c.author?.username ?? d.user?.username;
  const text = c.text ?? c.content ?? d.text;
  // permalink id/hash for the cast
  const castHash = c.hash ?? c.merkle_root ?? c.cast_hash ?? c.id ?? c.hash_hex;
  // detect root: consider only *cast-hash* style parents; channel parent URLs should still be treated as root
  const parentCastHash = c.parent_hash ?? c.parentHash ?? c.parent?.hash ?? c.parent_merkle_root ?? c.replyParentMerkleRoot ?? c.rootParentHash;
  const channelParentUrl = c.parent_url ?? c.parentUri ?? c.channel?.url; // informational, does not affect isRoot
  const isRoot = !parentCastHash; // replies/quotes have a parent cast hash; channel posts usually don't
  const ts = d.timestamp ?? d.event_timestamp ?? evt.created_at ?? Date.now();
  return { fid, username, text, castHash, isRoot, ts };
}

// --- Helper: rút thông tin trade.created ---
// --- Helper: rút thông tin trade.created (FIX theo payload thực tế Neynar) ---
function extractTradeCreated(evt) {
  const d = evt?.data || {};

  // trader
  const traderFid = Number(d.trader?.fid);
  const username = d.trader?.username;

  // transaction
  const tx = d.transaction || {};
  const txHash = tx.hash;
  const chain = tx.network?.name ?? "unknown";

  // net transfer
  const net = tx.net_transfer || {};
  const send = net.sending_fungible;
  const recv = net.receiving_fungible;

  const tokenIn = send?.token?.symbol;
  const tokenOut = recv?.token?.symbol;

  // USDC amount (Neynar cho sẵn in_usd)
  let amountUsdc = null;
  if (send?.balance?.in_usd != null) {
    amountUsdc = Number(send.balance.in_usd);
  }

  // created_at của Neynar là seconds
  const ts = evt.created_at
    ? Number(evt.created_at) * 1000
    : Date.now();

  return {
    traderFid,
    username,
    amountUsdc,
    tokenIn,
    tokenOut,
    txHash,
    chain,
    ts,
  };
}

function safeText(s, max = 400) {
  if (!s) return "";
  const t = String(s).replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return t.length > max ? t.slice(0, max) + "…" : t;
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
      await sendTG(lines.join("\n"), TG_CHAT_ID_FOLLOW);
    }
    else if (evt?.type === "user.updated") {
      const { fid, username, ts, changesObj, updatedFields, before, after } = extractUserUpdated(evt);
      let u = username;
      if (!u && fid) {
        const map = await fetchUsersByFids([fid]);
        u = map[fid]?.username ?? String(fid);
      }
      const uLink = `<a href="https://farcaster.xyz/${u}">${u}</a>`;
      const timeStr = formatDateTimeUTC7(ts);

      // Build human-readable change lines using before/after when available,
      // otherwise use lastProfile + current fetched data
      const changeLines = [];
      const addChange = (k, oldV, newV) => {
        if (oldV === newV) return;
        const key = k.replace(/_/g, " ").toUpperCase();
        const beforeStr = oldV != null && String(oldV).length ? safeText(oldV, 160) : "(empty)";
        const afterStr  = newV != null && String(newV).length ? safeText(newV, 160) : "(empty)";
        changeLines.push(`${key}: ${beforeStr} → ${afterStr}`);
      };

      // Prefer explicit before/after from payload
      let oldObj = before && Object.keys(before).length ? before : null;
      let newObj = after && Object.keys(after).length ? after : null;

      // If payload doesn't include before, try lastProfile
      if (!oldObj && fid) oldObj = lastProfile.get(fid) || null;

      // If payload doesn't include after, fetch now OR use cache
      if (!newObj) {
        const map = await fetchUsersByFids([fid]);
        newObj = {
          username: map[fid]?.username,
          display_name: map[fid]?.display_name,
          bio: map[fid]?.bio,
          pfp_url: map[fid]?.pfp_url,
          location: map[fid]?.location,
          website: map[fid]?.website,
        };
      }

      // Fields to show
      const keysToCheck = ["username", "display_name", "bio", "pfp_url", "location", "website"];

      // If we have either old or new, compute diffs
      if (oldObj || newObj) {
        for (const key of keysToCheck) {
          const ov = oldObj?.[key];
          const nv = newObj?.[key];
          if (ov !== undefined || nv !== undefined) addChange(key, ov, nv);
        }
      }

      // If still empty and we only got a list of updated fields, show current values
      if (changeLines.length === 0 && Array.isArray(updatedFields) && updatedFields.length) {
        for (const k of updatedFields) {
          const key = String(k);
          const v = newObj?.[key];
          const val = v != null ? safeText(v, 160) : "(empty)";
          changeLines.push(`${key.toUpperCase()}: ${val}`);
        }
      }

      // Update lastProfile snapshot for next time
      if (fid && newObj) {
        lastProfile.set(fid, {
          username: newObj.username,
          display_name: newObj.display_name,
          bio: newObj.bio,
          pfp_url: newObj.pfp_url,
          location: newObj.location,
          website: newObj.website,
        });
      }

      // If still empty, show a generic hint
      if (changeLines.length === 0) {
        changeLines.push("(profile fields updated)");
      }

      const lines = [
        `${uLink} <b>UPDATED PROFILE</b>`,
        ...changeLines,
        timeStr,
      ].filter(Boolean);
      await sendTG(lines.join("\n"), TG_CHAT_ID_ACTIVITY);
    }
    else if (evt?.type === "cast.created") {
      const { fid, username, text, castHash, isRoot, ts } = extractCastCreated(evt);
      if (!isRoot) { return res.send("ok"); }
      let u = username;
      if (!u && fid) {
        const map = await fetchUsersByFids([fid]);
        u = map[fid]?.username ?? String(fid);
      }
      const uLink = `<a href="https://farcaster.xyz/${u}">${u}</a>`;
      const timeStr = formatDateTimeUTC7(ts);
      const preview = safeText(text, 500);
      const castId = castHash ? String(castHash) : "";
      const castLink = castId ? `https://farcaster.xyz/${u}/${castId}` : null;
      const lines = [
        `${uLink} <b>CASTED</b>`,
        preview,
        castLink,
        timeStr,
      ].filter(Boolean);
      await sendTG(lines.join("\n"), TG_CHAT_ID_ACTIVITY);
    }
    else if (evt?.type === "trade.created") {
      // DEBUG: log raw trade.created payload to inspect structure
      console.log("[trade.created raw]", JSON.stringify(evt, null, 2));
      const {
        traderFid,
        username,
        amountUsdc,
        tokenIn,
        tokenOut,
        txHash,
        chain,
        ts,
      } = extractTradeCreated(evt);

      console.log("[trade.created parsed]", {
        traderFid,
        username,
        amountUsdc,
        tokenIn,
        tokenOut,
        txHash,
        chain,
        ts,
      });
      if (!traderFid) return res.send("ok");

      let u = username;
      if (!u && traderFid) {
        const map = await fetchUsersByFids([traderFid]);
        u = map[traderFid]?.username ?? String(traderFid);
      }

      const uLink = `<a href="https://farcaster.xyz/${u}">${u}</a>`;
      const timeStr = formatDateTimeUTC7(ts);

      const txLink = txHash
        ? `<a href="https://basescan.org/tx/${txHash}">view tx</a>`
        : null;

      const lines = [
        `${uLink} <b>CREATED TRADE</b>`,
        tokenIn && tokenOut ? `${tokenIn} → ${tokenOut}` : null,
        amountUsdc != null ? `Amount: ${amountUsdc} USDC` : null,
        `Chain: ${chain}`,
        txLink,
        timeStr,
      ].filter(Boolean);

      await sendTG(lines.join("\n"), TG_CHAT_ID_TRADE);
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