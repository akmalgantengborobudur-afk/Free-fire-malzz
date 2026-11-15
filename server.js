require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const { OAuth2Client } = require("google-auth-library");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const REDIRECT_URI = `${BASE_URL}/auth/google/callback`;
const oauth = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  REDIRECT_URI
);

app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(session({
  name: "ffcompanion.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 30 * 60 * 1000
  }
}));
app.use(express.static("public"));

app.get("/auth/google", (req, res) => {
  const state = crypto.randomBytes(24).toString("hex");
  req.session.oauthState = state;
  res.redirect(oauth.generateAuthUrl({
    access_type: "online",
    scope: ["openid", "email", "profile"],
    state,
    prompt: "select_account"
  }));
});

app.get("/auth/google/callback", async (req, res) => {
  try {
    if (!req.query.code || !req.query.state ||
        req.query.state !== req.session.oauthState) {
      return res.status(400).send("Login tidak valid. Silakan coba lagi.");
    }
    delete req.session.oauthState;
    const { tokens } = await oauth.getToken(String(req.query.code));
    if (!tokens.id_token) return res.status(401).send("ID token Google tidak tersedia.");
    const ticket = await oauth.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const user = ticket.getPayload();
    if (!user || !user.email) return res.status(401).send("Profil Google tidak valid.");

    // Tidak pernah meminta atau menerima password Google.
    req.session.profile = { email: user.email, name: user.name || "" };
    res.redirect("/");
  } catch (err) {
    console.error("OAuth error:", err.message);
    res.status(500).send("Login gagal. Periksa konfigurasi Google OAuth.");
  }
});

app.post("/notify", async (req, res) => {
  const profile = req.session.profile;
  if (!profile) return res.status(401).send("Login Google terlebih dahulu.");
  if (req.body.consent !== "yes") {
    return res.status(400).send("Persetujuan pengiriman WhatsApp diperlukan.");
  }

  const uid = String(req.body.uid || "").trim();
  const nickname = String(req.body.nickname || "").trim();
  if (!uid || !nickname || uid.length > 40 || nickname.length > 40) {
    return res.status(400).send("UID dan nickname wajib diisi (maks. 40 karakter).");
  }

  const { WHATSAPP_ACCESS_TOKEN, WHATSAPP_PHONE_NUMBER_ID, WHATSAPP_TO_NUMBER } = process.env;
  if (!WHATSAPP_ACCESS_TOKEN || !WHATSAPP_PHONE_NUMBER_ID || !WHATSAPP_TO_NUMBER) {
    return res.status(503).send("WhatsApp belum dikonfigurasi oleh pengelola.");
  }

  const message = [
    "Profil dikirim atas persetujuan pengguna.",
    `Nama Google: ${profile.name}`,
    `Email Google: ${profile.email}`,
    `UID Free Fire: ${uid}`,
    `Nickname: ${nickname}`
  ].join("\n");

  try {
    const response = await fetch(
      `https://graph.facebook.com/v21.0/${WHATSAPP_PHONE_NUMBER_ID}/messages`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${WHATSAPP_ACCESS_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          messaging_product: "whatsapp",
          recipient_type: "individual",
          to: WHATSAPP_TO_NUMBER.replace(/\D/g, ""),
          type: "text",
          text: { body: message }
        })
      }
    );
    if (!response.ok) {
      console.error("WhatsApp API error:", await response.text());
      return res.status(502).send("WhatsApp gagal mengirim. Periksa konfigurasi API.");
    }
    res.send("Notifikasi WhatsApp berhasil dikirim. Profil tidak disimpan aplikasi.");
  } catch (err) {
    console.error("WhatsApp request error:", err.message);
    res.status(502).send("Tidak dapat menghubungi WhatsApp saat ini.");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.listen(PORT, () => console.log(`Server berjalan di ${BASE_URL}`));
