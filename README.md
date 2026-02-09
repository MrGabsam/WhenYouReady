# WhenYou’reReady — Live Deployment (Minimum/Free Investment)

## What you get
- Stripe Checkout payment
- Email sent immediately with vault link (SendGrid)
- Vault link shows locked padlock + real-time countdown until unlock date
- AES-256-GCM encryption at rest (payload stored encrypted in data/messages.json)

## Local test (before going live)
1) Copy `.env.example` -> `.env`
2) Set ENCRYPTION_SECRET (32+ chars)
3) Add Stripe Test keys (from Stripe Dashboard)
4) Optional: SendGrid API key + verified FROM_EMAIL

Run:
```bash
npm install
npm start
```
Open http://localhost:3000

## Go live NOW (Render, lowest effort)
1) Create a GitHub repo and push this folder.
2) Render -> New -> Web Service -> Connect the repo.
3) Build command: `npm install`
4) Start command: `npm start`
5) Environment Variables in Render:
- PORT=10000
- APP_URL=https://YOUR-SERVICE.onrender.com
- ENCRYPTION_SECRET=... (same strong secret)
- STRIPE_SECRET_KEY=... (Live key when ready)
- STRIPE_WEBHOOK_SECRET=... (from webhook)
- SENDGRID_API_KEY=... (optional but required for real emails)
- FROM_EMAIL=... (verified sender)
- REMIND_AT_UNLOCK=false

## Stripe webhook (REQUIRED for email delivery after payment)
Stripe Dashboard -> Developers -> Webhooks -> Add endpoint
- Endpoint URL: https://YOUR-SERVICE.onrender.com/api/stripe/webhook
- Events: checkout.session.completed
Copy the Signing secret into STRIPE_WEBHOOK_SECRET in Render.

## SendGrid setup (Free tier)
- Create API key
- Verify sender email/domain
- Put SENDGRID_API_KEY + FROM_EMAIL in Render

If SendGrid is not configured, the server will still "send" emails by printing them in logs (good for testing).
