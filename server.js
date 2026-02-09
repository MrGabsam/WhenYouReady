import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import Stripe from "stripe";
import sgMail from "@sendgrid/mail";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, "");

// ---------------- STRIPE INIT ----------------
const stripeKey = (process.env.STRIPE_SECRET_KEY || "").trim();
const stripe = stripeKey ? new Stripe(stripeKey) : null;

// ---------------- SENDGRID INIT ----------------
const SENDGRID_API_KEY = (process.env.SENDGRID_API_KEY || "").trim();
const FROM_EMAIL = (process.env.FROM_EMAIL || "").trim();

if (SENDGRID_API_KEY) sgMail.setApiKey(SENDGRID_API_KEY);

// ---------------- STORAGE (JSON DB) ----------------
const __dirname = process.cwd();
const DATA_DIR = path.join(__dirname, "data");
const messagesPath = path.join(DATA_DIR, "messages.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(messagesPath)) fs.writeFileSync(messagesPath, "[]", "utf-8");

function loadMessages() {
  return JSON.parse(fs.readFileSync(messagesPath, "utf-8"));
}
function saveMessages(m) {
  fs.writeFileSync(messagesPath, JSON.stringify(m, null, 2));
}
function findById(id) {
  return loadMessages().find((x) => x.id === id);
}
function findByToken(token) {
  return loadMessages().find((x) => x.token === token);
}
function updateById(id, patch) {
  const all = loadMessages();
  const idx = all.findIndex((x) => x.id === id);
  if (idx === -1) return null;
  all[idx] = { ...all[idx], ...patch };
  saveMessages(all);
  return all[idx];
}

// ---------------- CRYPTO (AES-256-GCM) ----------------
const ENC_SECRET = (process.env.ENCRYPTION_SECRET || "").trim();

function mustHaveSecret() {
  if (!ENC_SECRET || ENC_SECRET.length < 32) {
    throw new Error("ENCRYPTION_SECRET must be set (32+ chars).");
  }
}
function keyFromSecret() {
  return crypto.createHash("sha256").update(ENC_SECRET).digest();
}
function encryptJSON(obj) {
  const iv = crypto.randomBytes(12);
  const key = keyFromSecret();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), "utf-8");
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}
function decryptJSON(b64) {
  const raw = Buffer.from(b64, "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const enc = raw.subarray(28);
  const key = keyFromSecret();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return JSON.parse(dec.toString("utf-8"));
}

// ---------------- EMAIL HELPERS ----------------
async function sendEmail({ to, subject, html, text }) {
  if (!SENDGRID_API_KEY || !FROM_EMAIL) {
    console.log("\n--- EMAIL (SIMULATED) ---");
    console.log("To:", to);
    console.log("Subject:", subject);
    console.log(text);
    console.log("--- END EMAIL ---\n");
    return;
  }
  await sgMail.send({ to, from: FROM_EMAIL, subject, html, text });
}

function fmtDate(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

async function sendInitialVaultEmail(msg) {
  const unlockAt = fmtDate(msg.deliverAt);
  const vaultLink = `${APP_URL}/vault.html?token=${encodeURIComponent(msg.token)}`;

  const subject = "A vault was sealed for you — it opens on the chosen moment";
  const text =
    `Someone sealed a message for you on WhenYou’reReady.\n\n` +
    `Unlocks on: ${unlockAt}\n\n` +
    `Open the vault link:\n${vaultLink}\n\n` +
    `If you open early, you’ll see a locked vault + live countdown.`;

  const html = `
  <div style="font-family:Inter,Arial,sans-serif;max-width:560px">
    <h2 style="margin:0 0 8px">A vault was sealed for you.</h2>
    <p style="margin:0 0 10px"><b>Unlock date:</b> ${unlockAt}</p>
    <a href="${vaultLink}" style="display:inline-block;background:#6D5BFF;color:#fff;padding:12px 16px;border-radius:999px;text-decoration:none;font-weight:800">
      Open the vault
    </a>
    <p style="margin:14px 0 0;color:#333">If you open early, you’ll see a locked vault + live countdown.</p>
  </div>`;

  await sendEmail({ to: msg.recipientEmail, subject, html, text });
}

// ---------------- PRICING ----------------
function priceForPlan(plan) {
  // Stripe uses minor units (pence for GBP)
  const p = String(plan || "basic").toLowerCase();
  const plans = {
    basic: 299,   // £2.99
    premium: 499, // £4.99
    legacy: 799,  // £7.99
  };
  return plans[p] ?? plans.basic;
}

// ----------------- IMPORTANT MIDDLEWARE ORDER -----------------
// Stripe webhook needs RAW body; do NOT let express.json consume it first.
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!stripe) return res.status(500).send("Stripe not configured");

    const sig = req.headers["stripe-signature"];
    const whSecret = (process.env.STRIPE_WEBHOOK_SECRET || "").trim();
    if (!whSecret) return res.status(500).send("Stripe webhook secret missing");

    const event = stripe.webhooks.constructEvent(req.body, sig, whSecret);

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const messageId = session.metadata?.messageId;

      if (messageId) {
        const msg = updateById(messageId, {
          paid: true,
          paymentProvider: "stripe",
          stripeSessionId: session.id,
          paidAt: new Date().toISOString(),
        });

        if (msg && !msg.initialEmailSentAt) {
          await sendInitialVaultEmail(msg);
          updateById(messageId, { initialEmailSentAt: new Date().toISOString() });
        }
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error("Stripe webhook error:", err?.message || err);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

// After webhook route, parse JSON normally
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "50mb" }));
app.use(express.static("public"));

// ----------------- M-PESA (Daraja STK Push) -----------------
const MPESA_ENV = (process.env.MPESA_ENV || "sandbox").trim();
const MPESA_BASE =
  MPESA_ENV === "production" ? "https://api.safaricom.co.ke" : "https://sandbox.safaricom.co.ke";

const MPESA_CONSUMER_KEY = (process.env.MPESA_CONSUMER_KEY || "").trim();
const MPESA_CONSUMER_SECRET = (process.env.MPESA_CONSUMER_SECRET || "").trim();
const MPESA_SHORTCODE = (process.env.MPESA_SHORTCODE || "174379").trim();
const MPESA_PARTYB = (process.env.MPESA_PARTYB || MPESA_SHORTCODE).trim();
const MPESA_PASSKEY = (process.env.MPESA_PASSKEY || "").trim();
const MPESA_CALLBACK_URL = (process.env.MPESA_CALLBACK_URL || "").trim();
const MPESA_ACCOUNT_REF = (process.env.MPESA_ACCOUNT_REF || "WhenYoureReady").trim().slice(0, 12);
const MPESA_TRANSACTION_DESC = (process.env.MPESA_TRANSACTION_DESC || "Vault").trim().slice(0, 13);

function normalizeKenyanPhone(input) {
  const raw = String(input || "").replace(/\s+/g, "").replace(/^\+/, "");
  if (/^2547\d{8}$/.test(raw)) return raw;
  if (/^07\d{8}$/.test(raw)) return "254" + raw.slice(1);
  return null;
}

async function mpesaAccessToken() {
  if (!MPESA_CONSUMER_KEY || !MPESA_CONSUMER_SECRET) {
    throw new Error("M-Pesa consumer key/secret missing in .env");
  }
  const auth = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString("base64");
  const r = await fetch(`${MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${auth}` },
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d?.errorMessage || d?.error || "Failed to get M-Pesa token");
  return d.access_token;
}

function mpesaTimestamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return (
    d.getFullYear() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
}

function mpesaPassword(shortcode, passkey, timestamp) {
  return Buffer.from(`${shortcode}${passkey}${timestamp}`).toString("base64");
}

// ---------------- CREATE VAULT RECORD (before payment) ----------------
function createVaultRecord(body) {
  mustHaveSecret();

  const {
    recipientEmail,
    deliverAt,
    title,
    content,
    contentHTML,
    images,
    audioBase64,
    voiceStyle,
    theme,
    plan,
  } = body;

  if (!recipientEmail || !deliverAt || !title || !content) {
    throw new Error("Missing required fields (email, deliverAt, title, content)");
  }

  const deliverDate = new Date(deliverAt);
  if (isNaN(deliverDate.getTime())) throw new Error("Invalid deliverAt (must be ISO date)");

  const token = crypto.randomBytes(12).toString("hex");
  const id = crypto.randomBytes(10).toString("hex");

  const payload = encryptJSON({
    title: String(title).slice(0, 140),
    content: String(content).slice(0, 20000),
    contentHTML: String(contentHTML || "").slice(0, 50000),
    theme: (theme || "classic").slice(0, 20),
    voiceStyle: voiceStyle || null,
  });

  const chosen = String(plan || "basic").toLowerCase();

  const record = {
    id,
    token,
    recipientEmail: String(recipientEmail).trim(),
    deliverAt: deliverDate.toISOString(),
    payload,
    images: images || [],
    audioBase64: audioBase64 || null,
    plan: chosen,

    paid: false,
    paymentProvider: null,
    createdAt: new Date().toISOString(),
    paidAt: null,

    // email
    initialEmailSentAt: null,

    // mpesa
    mpesaCheckoutRequestID: null,
    mpesaMerchantRequestID: null,
    mpesaReceipt: null,
    mpesaPhone: null,
    mpesaResultCode: null,
    mpesaResultDesc: null,

    // stripe
    stripeSessionId: null,
  };

  const all = loadMessages();
  all.push(record);
  saveMessages(all);

  return record;
}

// ---------------- CHECKOUT (Stripe or M-Pesa) ----------------
app.post("/api/checkout", async (req, res) => {
  try {
    const paymentMethod = String(req.body.paymentMethod || "card").toLowerCase();

    const record = createVaultRecord(req.body);

    // CARD (Stripe)
    if (paymentMethod === "card") {
      if (!stripe) return res.status(500).json({ error: "Stripe not configured" });

      const amount = priceForPlan(record.plan);

      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "gbp",
              product_data: { name: `WhenYou’reReady — ${record.plan} vault` },
              unit_amount: amount,
            },
            quantity: 1,
          },
        ],
        success_url: `${APP_URL}/success.html?provider=stripe&session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${APP_URL}/?canceled=1`,
        metadata: { messageId: record.id },
      });

      updateById(record.id, { stripeSessionId: session.id, paymentProvider: "stripe" });
      return res.json({ provider: "stripe", url: session.url });
    }

    // M-PESA (STK Push)
    if (paymentMethod === "mpesa") {
      if (!MPESA_PASSKEY) return res.status(500).json({ error: "MPESA_PASSKEY missing in .env" });
      if (!MPESA_CALLBACK_URL) return res.status(500).json({ error: "MPESA_CALLBACK_URL missing in .env" });

      const phone = normalizeKenyanPhone(req.body.mpesaPhone);
      if (!phone) return res.status(400).json({ error: "Invalid M-Pesa phone (use 2547XXXXXXXX or 07XXXXXXXX)" });

      // Sandbox testing amounts (KES)
      const amountKes = record.plan === "legacy" ? 50 : record.plan === "premium" ? 20 : 10;

      const token = await mpesaAccessToken();
      const timestamp = mpesaTimestamp();
      const password = mpesaPassword(MPESA_SHORTCODE, MPESA_PASSKEY, timestamp);

      const stkBody = {
        BusinessShortCode: Number(MPESA_SHORTCODE),
        Password: password,
        Timestamp: timestamp,
        TransactionType: "CustomerPayBillOnline",
        Amount: amountKes,
        PartyA: phone,
        PartyB: Number(MPESA_PARTYB),
        PhoneNumber: phone,
        CallBackURL: MPESA_CALLBACK_URL,
        AccountReference: MPESA_ACCOUNT_REF,
        TransactionDesc: MPESA_TRANSACTION_DESC,
      };

      const r = await fetch(`${MPESA_BASE}/mpesa/stkpush/v1/processrequest`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(stkBody),
      });

      const d = await r.json();

      if (!r.ok || d.ResponseCode !== "0") {
        updateById(record.id, {
          paymentProvider: "mpesa",
          mpesaPhone: phone,
          mpesaResultDesc: d?.errorMessage || d?.ResponseDescription || "STK failed",
        });
        return res.status(400).json({
          error: d?.errorMessage || d?.ResponseDescription || "M-Pesa STK Push failed",
          raw: d,
        });
      }

      updateById(record.id, {
        paymentProvider: "mpesa",
        mpesaPhone: phone,
        mpesaMerchantRequestID: d.MerchantRequestID,
        mpesaCheckoutRequestID: d.CheckoutRequestID,
      });

      return res.json({
        provider: "mpesa",
        url: `${APP_URL}/success.html?provider=mpesa&message_id=${encodeURIComponent(record.id)}`,
        messageId: record.id,
        customerMessage: d.CustomerMessage,
      });
    }

    return res.status(400).json({ error: "Unsupported payment method" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || "Server error" });
  }
});

// ---------------- M-PESA CALLBACK ----------------
app.post("/api/mpesa/callback", async (req, res) => {
  try {
    const stk = req.body?.Body?.stkCallback;
    if (!stk) return res.status(400).json({ ok: false, error: "Invalid callback payload" });

    // Always 200 OK to Daraja
    res.json({ ok: true });

    const checkoutId = stk.CheckoutRequestID;
    const msg = loadMessages().find((m) => m.mpesaCheckoutRequestID === checkoutId);

    if (!msg) {
      console.warn("M-Pesa callback: message not found for CheckoutRequestID:", checkoutId);
      return;
    }

    const resultCode = Number(stk.ResultCode);
    const resultDesc = String(stk.ResultDesc || "");

    let receipt = null;
    let phone = msg.mpesaPhone || null;

    const items = stk.CallbackMetadata?.Item || [];
    for (const it of items) {
      if (it.Name === "MpesaReceiptNumber") receipt = it.Value;
      if (it.Name === "PhoneNumber") phone = String(it.Value);
    }

    const patch = {
      mpesaResultCode: resultCode,
      mpesaResultDesc: resultDesc,
      mpesaReceipt: receipt,
      mpesaPhone: phone,
    };

    if (resultCode === 0) {
      patch.paid = true;
      patch.paidAt = new Date().toISOString();

      const updated = updateById(msg.id, patch);

      if (updated && !updated.initialEmailSentAt) {
        await sendInitialVaultEmail(updated);
        updateById(msg.id, { initialEmailSentAt: new Date().toISOString() });
      }
    } else {
      updateById(msg.id, patch);
    }
  } catch (e) {
    console.error("M-Pesa callback error:", e);
  }
});

// ---------------- CONFIRM (Stripe session) ----------------
app.get("/api/confirm", async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: "Stripe not configured" });

    const sid = req.query.session_id;
    if (!sid) return res.status(400).json({ error: "session_id required" });

    const session = await stripe.checkout.sessions.retrieve(sid);
    const messageId = session.metadata?.messageId;
    const msg = messageId ? findById(messageId) : null;

    res.json({
      provider: "stripe",
      paid: session.payment_status === "paid",
      emailSent: Boolean(msg?.initialEmailSentAt),
      deliverAt: msg?.deliverAt || null,
    });
  } catch (e) {
    res.status(500).json({ error: e.message || "Server error" });
  }
});

// ---------------- PAYMENT STATUS (for M-Pesa success page polling) ----------------
app.get("/api/payment-status", (req, res) => {
  try {
    const id = req.query.message_id;
    if (!id) return res.status(400).json({ error: "message_id required" });

    const msg = findById(id);
    if (!msg) return res.status(404).json({ error: "NOT_FOUND" });

    res.json({
      provider: msg.paymentProvider,
      paid: Boolean(msg.paid),
      emailSent: Boolean(msg.initialEmailSentAt),
      deliverAt: msg.deliverAt || null,
      mpesa: {
        checkoutRequestID: msg.mpesaCheckoutRequestID,
        resultCode: msg.mpesaResultCode,
        resultDesc: msg.mpesaResultDesc,
        receipt: msg.mpesaReceipt,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message || "Server error" });
  }
});

// ---------------- VAULT (UNLOCK) ----------------
app.get("/api/vault", (req, res) => {
  try {
    mustHaveSecret();
    const token = req.query.token;
    if (!token) return res.status(400).json({ error: "token required" });

    const msg = findByToken(token);
    if (!msg) return res.status(404).json({ error: "NOT_FOUND" });

    const now = new Date();
    const unlockTime = new Date(msg.deliverAt);
    const decoded = decryptJSON(msg.payload);

    if (!msg.paid || now < unlockTime) {
      return res.status(403).json({
        error: "LOCKED",
        deliverAt: msg.deliverAt,
        theme: decoded.theme,
      });
    }

    return res.json({
      title: decoded.title,
      content: decoded.content,
      contentHTML: decoded.contentHTML,
      theme: decoded.theme,
      voiceStyle: decoded.voiceStyle,
      images: msg.images || [],
      audioBase64: msg.audioBase64 || null,
    });
  } catch (e) {
    res.status(500).json({ error: e.message || "Server error" });
  }
});

// ---------------- HEALTH ----------------
app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`WhenYou’reReady running at ${APP_URL}`);
});
