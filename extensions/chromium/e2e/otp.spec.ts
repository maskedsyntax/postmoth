// Real browser, real extension, real native host and daemon, real IMAP.
import { type BrowserContext, type Page, chromium, expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import net from "node:net";

const PROFILE = env("E2E_PROFILE");
const EXTENSION = env("E2E_EXTENSION");
const CTL = env("E2E_CTL");
const SMTP_PORT = Number(env("POSTMOTH_TEST_SMTP_PORT"));
const RCPT = env("POSTMOTH_TEST_IMAP_USER");

function env(k: string): string {
  const v = process.env[k];
  if (!v) throw new Error(`${k} not set; run tests/e2e/run.sh`);
  return v;
}

/** Minimal SMTP client: enough for GreenMail. */
async function sendMail(from: string, subject: string, body: string): Promise<void> {
  const msg = [
    `From: Example Security <${from}>`,
    `To: ${RCPT}`,
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString().replace("GMT", "+0000")}`,
    `Message-ID: <${crypto.randomUUID()}@example.com>`,
    "Content-Type: text/plain; charset=utf-8",
    "",
    body,
  ].join("\r\n");
  const script = [`HELO e2e`, `MAIL FROM:<${from}>`, `RCPT TO:<${RCPT}>`, `DATA`, `${msg}\r\n.`, `QUIT`];
  await new Promise<void>((resolve, reject) => {
    const sock = net.connect(SMTP_PORT, "127.0.0.1");
    let step = -1;
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString();
      while (buf.includes("\r\n")) {
        const line = buf.slice(0, buf.indexOf("\r\n"));
        buf = buf.slice(buf.indexOf("\r\n") + 2);
        if (/^\d{3}-/.test(line)) continue; // multi-line reply
        if (!/^[23]\d\d/.test(line)) return reject(new Error(`SMTP: ${line}`));
        step++;
        if (step < script.length) sock.write(`${script[step]}\r\n`);
        else sock.end();
      }
    });
    sock.on("end", () => resolve());
    sock.on("error", reject);
  });
}

function liveCandidates(): number {
  const out = execFileSync(CTL, ["status", "--json"], { encoding: "utf8" });
  return (JSON.parse(out) as { otp_live_candidates: number }).otp_live_candidates;
}

async function deliverCode(code: string): Promise<void> {
  const before = liveCandidates();
  await sendMail(
    "security@example.com",
    "Your sign-in code",
    `Hi,\r\n\r\nYour verification code is ${code}. It expires in 10 minutes.\r\n`,
  );
  execFileSync(CTL, ["sync-now"]);
  await expect
    .poll(() => liveCandidates(), { timeout: 20_000, message: "daemon picked up the code" })
    .toBeGreaterThan(before === 0 ? 0 : before - 1);
}

const chipOn = (page: Page) => page.locator("postmoth-suggestion");

async function expectNoChip(page: Page): Promise<void> {
  await page.waitForTimeout(1500);
  await expect(chipOn(page)).toHaveCount(0);
}

let ctx: BrowserContext;

test.beforeAll(async () => {
  ctx = await chromium.launchPersistentContext(PROFILE, {
    channel: "chromium",
    headless: true,
    ignoreHTTPSErrors: true,
    args: [
      `--disable-extensions-except=${EXTENSION}`,
      `--load-extension=${EXTENSION}`,
      "--host-resolver-rules=MAP *.test 127.0.0.1",
    ],
    env: { ...process.env } as Record<string, string>,
  });
  // Wait for the service worker so the extension is live.
  if (ctx.serviceWorkers().length === 0) await ctx.waitForEvent("serviceworker");
});

test.afterAll(async () => {
  await ctx?.close();
});

test("code is offered on the trusted site, filled on click, once, never submitted", async () => {
  await deliverCode("482913");
  const page = await ctx.newPage();
  await page.goto("https://login.postmoth.test/login.html");
  await page.click("#otp");
  await expect(chipOn(page)).toHaveCount(1);
  // Into the chip with the keyboard, then accept: real (trusted) input.
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(page.locator("#otp")).toHaveValue("482913");
  await expect(chipOn(page)).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __submits: number }).__submits)).toBe(0);
  expect(liveCandidates()).toBe(0);

  // Single use: nothing on a fresh visit.
  await page.reload();
  await page.click("#otp");
  await expectNoChip(page);
  await page.close();
});

test("nothing is offered on wrong origins, unrelated fields, frames, or without a gesture", async () => {
  await deliverCode("551234");
  const page = await ctx.newPage();
  for (const url of [
    "https://evil.postmoth.test/login.html", // sibling subdomain
    "https://login.postmoth.test.evil.test/login.html", // lookalike
  ]) {
    await page.goto(url);
    await page.click("#otp");
    await expectNoChip(page);
  }

  await page.goto("https://login.postmoth.test/unrelated.html");
  for (const sel of ["#zip", "#promo", "#cvv"]) {
    await page.click(sel);
  }
  await expectNoChip(page);

  await page.goto("https://login.postmoth.test/iframe.html");
  await page.frameLocator("#frame").locator("#otp").click();
  await expectNoChip(page);

  // The page focuses and clicks its own field: no user activation, no
  // request. (page.evaluate would carry a user gesture, so the page does it.)
  await page.goto("https://login.postmoth.test/autofocus.html");
  await expectNoChip(page);

  await page.goto("https://login.postmoth.test/login.html");

  expect(liveCandidates(), "candidate untouched by all of the above").toBe(1);

  // ...and the real site still gets it once the user clicks.
  await page.click("#otp");
  await expect(chipOn(page)).toHaveCount(1);
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(page.locator("#otp")).toHaveValue("551234");
  await page.close();
});

test("split single-digit boxes are filled", async () => {
  await deliverCode("246810");
  const page = await ctx.newPage();
  await page.goto("https://login.postmoth.test/split.html");
  await page.locator("input").first().click();
  await expect(chipOn(page)).toHaveCount(1);
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  const values = await page.locator("input").evaluateAll((els) =>
    els.map((e) => (e as HTMLInputElement).value).join(""),
  );
  expect(values).toBe("246810");
  await page.close();
});
