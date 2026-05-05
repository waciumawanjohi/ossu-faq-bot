# Code Review: ossu-faq-bot

This document reviews the Discord FAQ bot codebase, covering security vulnerabilities, anti-patterns, and manual verification steps.

---

## 1. Critical / High Vulnerabilities

### 1.1 Global Rate Limiting Enables Denial-of-Service

**File:** `src/index.ts`, line 19  
**Severity:** High

```ts
const { success } = await c.env.DEFAULT_RATE_LIMIT.limit({ key: 'default' })
```

All requests — regardless of which Discord user or IP address originates them — share the single bucket keyed on `'default'`. The current limit is **5 requests per 60 seconds** across the entire bot. A single user sending 5 rapid interactions will exhaust that quota and cause the bot to return `429 Rate Limited` to every other user in the guild for the remainder of that 60-second window.

**Recommendation:** Key the rate limit on a per-client identifier. The Discord interaction payload exposes `interaction.member.user.id` (guild context) or `interaction.user.id` (DM context). Alternatively, use the Cloudflare Worker's incoming request IP via `c.req.raw.headers.get('cf-connecting-ip')`. Either choice scopes the limit to an individual caller and prevents one user from blocking everyone else.

---

### 1.2 `DISCORD_GUILD_ID` Is Not Validated Before Use

**File:** `src/register.ts`, lines 12 and 37  
**Severity:** High

```ts
const guildId = process.env['DISCORD_GUILD_ID']   // never validated

// …later…
const url = `https://discord.com/api/v10/applications/${applicationId}/guilds/${guildId}/commands`
```

`token` and `applicationId` both have explicit guards that throw a clear `Error` when missing, but `guildId` has none. When `DISCORD_GUILD_ID` is absent from the environment the variable is `undefined`, and the URL silently becomes:

```
https://discord.com/api/v10/applications/<id>/guilds/undefined/commands
```

Discord returns an HTTP 404 whose body does not mention `undefined`, making the root cause hard to diagnose.

**Recommendation:** Add the same guard used for the other two variables:

```ts
if (!guildId) {
  throw new Error('The DISCORD_GUILD_ID environment variable is required.')
}
```

---

### 1.3 Request Body Read Twice — Signature Verification and Parsing Are Decoupled

**File:** `src/index.ts`, lines 81–92  
**Severity:** Medium-High

```ts
const body = await request.arrayBuffer()          // raw bytes — used to verify signature
// …
const json = (await request.json()) as APIInteraction  // separate parse — used for logic
```

Discord's Ed25519 signature is computed over the **raw request bytes**. The two reads (`.arrayBuffer()` for verification, `.json()` for parsing) are independent calls that return the same cached buffer only because Hono internally caches the body on first read.

If any middleware transforms or re-encodes the body between those two calls (e.g., a future middleware that normalises JSON whitespace), the bytes passed to `verifyKey` could differ from the JSON that drives the interaction logic. An attacker who can predict how a transformation changes the byte layout could craft a request where the signature is valid for the original bytes but the parsed content is different.

**Recommendation:** Parse the JSON from the already-consumed bytes, not via a second framework call:

```ts
const body = await request.arrayBuffer()
const isValidRequest =
  signature &&
  timestamp &&
  (await verifyKey(body, signature, timestamp, DISCORD_PUBLIC_KEY))

if (!isValidRequest) {
  return { isValid: false }
}

const json = JSON.parse(new TextDecoder().decode(body)) as APIInteraction
return { interaction: json, isValid: true }
```

This guarantees that the bytes verified and the object acted upon originate from the exact same source.

---

## 2. Poor / Anti-Patterns

### 2.1 `dotenv/config` Imported in the Cloudflare Worker Entry Point

**File:** `src/index.ts`, line 8

```ts
import 'dotenv/config'
```

`dotenv` reads a `.env` file from the local filesystem at startup. Cloudflare Workers have **no filesystem**, so this import is a no-op at runtime. It:

- Adds a production dependency (`dotenv`) that provides no value in the deployed environment.
- Creates the false impression that secrets are loaded from a `.env` file at runtime (they are actually injected by Cloudflare's secrets mechanism via `wrangler secret bulk`).
- Could confuse future contributors into thinking they need a `.env` file to configure the worker.

**Recommendation:** Remove `import 'dotenv/config'` from `src/index.ts`. Keep it only in `src/register.ts`, which runs locally (outside the Worker) and legitimately needs to read from `.env`.

---

### 2.2 `DISCORD_PUBLIC_KEY` Read from `process.env` on Every Request

**File:** `src/index.ts`, lines 72–76

```ts
const DISCORD_PUBLIC_KEY = process.env['DISCORD_PUBLIC_KEY']
if (!DISCORD_PUBLIC_KEY) {
  throw new Error('The DISCORD_PUBLIC_KEY environment variable is required.')
}
```

This block executes inside `verifyDiscordRequest`, which is called on every HTTP request. The key doesn't change between requests, so re-reading and re-validating it 100 times a minute is unnecessary work.

More importantly, Cloudflare Workers expose secrets as **bindings** through the `env` parameter (typed via `Bindings`), not through `process.env`. Accessing secrets via `c.env` is the idiomatic and type-safe pattern, as already done for `DEFAULT_RATE_LIMIT`.

**Recommendation:**  
1. Add `DISCORD_PUBLIC_KEY: string` to the `Bindings` type and to `worker-configuration.d.ts`.  
2. Pass the value from `c.env` into `verifyDiscordRequest` as a parameter, so it is read once per request from the correct source rather than reaching through a Node.js compatibility shim on every invocation.

---

### 2.3 All Command Responses Are Public — Ephemeral Responses Not Supported

**File:** `src/index.ts`, lines 45–49

```ts
return c.json({
  type: InteractionResponseType.ChannelMessageWithSource,
  data: {
    content: commandValue.response,
  },
})
```

Every FAQ response is posted as a visible message in the channel. When a mod answers a common question in a busy channel, the response will appear in the public feed, which can increase noise.

Discord supports [ephemeral responses](https://discord.com/developers/docs/interactions/receiving-and-responding#message-flags) that are only visible to the user who invoked the command.

**Recommendation:** Add `flags: 64` (the `EPHEMERAL` flag) to the response data, or add a per-command `ephemeral` boolean to the command definition in `commands.ts` and apply it conditionally:

```ts
data: {
  content: commandValue.response,
  flags: 64, // EPHEMERAL — only visible to the invoking user
},
```

---

### 2.4 `commands` Object Has No Explicit Type Annotation

**File:** `src/commands.ts`

The `commands` object relies entirely on TypeScript's structural inference. If a contributor adds a new command and forgets the `response` property, the error will surface at the call site (`commandValue.response`) rather than at the definition, making the origin of the mistake harder to trace.

**Recommendation:** Define a `Command` interface and annotate `commands` with `Record<string, Command>` (or a mapped type) so that missing fields are flagged at the point of authorship:

```ts
interface Command {
  description: string
  response: string
  type: number
}

const commands: Record<string, Command> = { … }
```

---

### 2.5 Rate Limit Binding Accessed Without a Null Guard (Development / Test Environments)

**File:** `src/index.ts`, line 19

```ts
const { success } = await c.env.DEFAULT_RATE_LIMIT.limit({ key: 'default' })
```

`DEFAULT_RATE_LIMIT` is a Cloudflare rate-limit binding that is only injected by the Workers runtime. When the application is run locally with `npm run dev` (plain `tsx` without `wrangler`), `c.env` is an empty object and calling `.limit()` on `undefined` throws an unhandled runtime error, preventing any local testing.

**Recommendation:** Add a null check (or rely on `wrangler dev` for local development, and document that `npm run dev` does not work for Worker-specific features):

```ts
if (c.env.DEFAULT_RATE_LIMIT) {
  const { success } = await c.env.DEFAULT_RATE_LIMIT.limit({ key: 'default' })
  if (!success) return c.text('Rate Limited', 429)
}
```

---

## 3. Manual Verification Steps

The following steps let you confirm the bot is working end-to-end without automated tests.

### Prerequisites

- A Cloudflare account with Workers enabled.
- A Discord account with permission to create a Developer Application.
- Node.js ≥ 18 and `npm` installed locally.

---

### Step 1 — Create a Discord Application and Bot

1. Go to [https://discord.com/developers/applications](https://discord.com/developers/applications) and click **New Application**.
2. Give it a name (e.g. `faq-bot-test`) and confirm.
3. In the left sidebar, open **General Information** and copy the **Application ID** and **Public Key**.
4. Open **Bot** in the sidebar, scroll to the **Token** section, and click **Reset Token** to generate a bot token. Copy it.
5. Under **OAuth2 → URL Generator**, select the `applications.commands` scope and copy the generated URL. Open it in a browser and invite the bot to a test Discord server.

---

### Step 2 — Configure Environment Variables

1. Rename `.env.example` to `.env`.
2. Fill in the values below, replacing each `YOUR_…` placeholder with the real value:
   ```
   DISCORD_APPLICATION_ID=YOUR_APPLICATION_ID         # Application ID from Step 1
   DISCORD_PUBLIC_KEY=YOUR_PUBLIC_KEY                 # Public Key from Step 1
   DISCORD_BOT_TOKEN=YOUR_BOT_TOKEN                   # Bot Token from Step 1
   DISCORD_GUILD_ID=YOUR_SERVER_ID                    # Right-click your test server → Copy Server ID
   CLOUDFLARE_ACCOUNT_ID=YOUR_CLOUDFLARE_ACCOUNT_ID   # dash.cloudflare.com → Account ID in sidebar
   CLOUDFLARE_API_TOKEN=YOUR_CLOUDFLARE_API_TOKEN     # dash.cloudflare.com/profile/api-tokens — "Edit Cloudflare Workers" template
   ```

---

### Step 3 — Register the Slash Commands

```bash
npm install
npm run register
```

Expected output:
```
Registered all commands
```

Open your test Discord server. In any text channel, type `/` — the autocomplete menu should show all the bot commands (e.g. `/ossu_degree`, `/math_prereqs`, etc.).

---

### Step 4 — Deploy the Worker to Cloudflare

```bash
npm run build          # compile TypeScript → dist/
npm run secrets        # push .env secrets to Cloudflare
npm run publish        # deploy dist/index.js to Cloudflare Workers
```

After `publish` completes, Wrangler prints the deployed URL, e.g.:
```
https://faq-bot.<your-account>.workers.dev
```

---

### Step 5 — Register the Interactions Endpoint in the Discord Developer Portal

1. Go back to [https://discord.com/developers/applications](https://discord.com/developers/applications), open your application.
2. Under **General Information**, paste the Cloudflare Workers URL into the **Interactions Endpoint URL** field and click **Save Changes**.
3. Discord will immediately send a `PING` interaction to the URL. The worker must respond with `{ "type": 1 }` (Pong) within a few seconds.

**Expected result:** Discord shows a green checkmark and saves the URL. If you see an error like *"The provided URL did not respond correctly"*, the worker is not reachable or the `DISCORD_PUBLIC_KEY` secret is wrong.

---

### Step 6 — Smoke-Test a Slash Command in Discord

1. In your test server, type `/ossu_degree` and press Enter.
2. The bot should reply immediately with the text:

   > **Does OSSU offer a degree?**  
   > No. OSSU creates guides to resources …

**Expected result:** The message appears in the channel (or only for you if ephemeral mode is enabled). If the bot does not respond, check:
- The Cloudflare Workers dashboard → **Logs** tab for runtime errors.
- That the `DISCORD_PUBLIC_KEY` secret was pushed correctly (`npm run secrets`).
- That the Interactions Endpoint URL in the Discord Developer Portal matches the deployed worker URL exactly.

---

### Step 7 — Verify Rate Limiting

1. In rapid succession (within the same 60-second window), invoke the same slash command **6 or more times**.
2. After the 5th successful response, subsequent commands within the window should return no response (the worker returns HTTP 429 to Discord, which Discord may display as an interaction failure).

**Expected result:** The first five invocations succeed; the sixth causes Discord to report an error for that interaction. This confirms the rate limiting binding is active.

---

### Step 8 — Verify an Unknown Command is Handled Gracefully

The only way to trigger this path is via the Discord API directly, since the portal only shows registered commands. Use `curl` or a REST client to send a forged interaction.

> **Note:** Replace `YOUR_WORKER_SUBDOMAIN` below with the subdomain printed by Wrangler after `npm run publish` in Step 4 (e.g. if the URL was `https://faq-bot.alice.workers.dev`, use `alice`).

```bash
# This will be rejected (invalid signature), but the 401 confirms the endpoint is live
curl -X POST https://faq-bot.YOUR_WORKER_SUBDOMAIN.workers.dev \
  -H "Content-Type: application/json" \
  -H "x-signature-ed25519: deadbeef" \
  -H "x-signature-timestamp: 0" \
  -d '{"type":2,"data":{"name":"nonexistent"}}'
```

**Expected result:** HTTP `401 Bad request signature.` — confirming that the signature verification middleware correctly rejects tampered requests before any command lookup occurs.
