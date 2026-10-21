#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pbkdf2Sync, createCipheriv, randomBytes } from "node:crypto";

function usage() {
  console.error(
    "Usage: node tools/generate-encrypted-json.mjs [input] [output]  (run from site/; input defaults to private/file.json, output to json/index.html)",
  );
}

function buildHtml(embeddedUsers) {
  const usersJson = JSON.stringify(embeddedUsers).replace(/</g, "\\u003c");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>JSON Download</title>
  </head>
  <body>
    <script>
      const EMBEDDED_USERS = ${usersJson};
      const DEFAULT_FILENAME = "encrypted.json";

      function downloadJsonObject(data, fileName) {
        const text = JSON.stringify(data, null, 2) + "\\n";
        const blob = new Blob([text], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = fileName || DEFAULT_FILENAME;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      }

      function getParams() {
        const params = new URLSearchParams(window.location.search);
        return {
          user: (params.get("user") || "").trim(),
        };
      }

      async function processRequest(user, options = {}) {
        const isManual = Boolean(options.isManual);
        const payload = EMBEDDED_USERS && user ? EMBEDDED_USERS[user] : null;

        if (!payload) {
          downloadJsonObject({}, DEFAULT_FILENAME);
          return;
        }

        const outputFileName = isManual
          ? user + ".json"
          : user + ".encrypted.json";
        downloadJsonObject(payload, outputFileName);
      }

      async function run() {
        const { user } = getParams();
        if (user) {
          await processRequest(user, { isManual: false });
          return;
        }

        const input = window.prompt("Enter user:key") || "";
        const delimiterIndex = input.indexOf(":");
        const manualUser =
          delimiterIndex === -1 ? "" : input.slice(0, delimiterIndex).trim();
        await processRequest(manualUser, { isManual: true });
      }

      run();
    </script>
  </body>
</html>
`;
}

function normalizeEncryptContent(value) {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "undefined") {
    return "";
  }
  return `${JSON.stringify(value, null, 2)}\n`;
}

const GEMINI_KEY = /^(?:AIza[0-9A-Za-z_-]{35}|AQ\.[0-9A-Za-z_.-]{50})$/;
const GEMINI_FIELDS = ["userGeminiApiKeys", "userGeminiApiKey", "geminiApiKeys", "geminiApiKey", "gemini"];
// Every alias the extension reads for the removed providers (import.js), plus obsolete settings.
const DROPPED_FIELDS = [
  "userGroqApiKeys", "userGroqApiKey", "groqApiKeys", "groqApiKey", "groq",
  "userMistralApiKeys", "userMistralApiKey", "mistralApiKeys", "mistralApiKey", "mistral",
  "userOllamaApiKeys", "userOllamaApiKey",
  "geminiConcurrency",
];

const splitKeys = (v) =>
  (Array.isArray(v) ? v : [v]).flatMap((e) => (typeof e === "string" ? e.split(/[\n,]/) : [])).map((e) => e.trim()).filter(Boolean);

// Object payloads: force logging on, merge every Gemini field into one userGeminiApiKeys
// (valid shapes only), rescue Gemini-shaped keys from removed-provider fields, drop those
// fields. Strings pass through.
function prepareEncrypt(user, value, shared = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    if (typeof value === "string") {
      console.error(`Note: '${user}' encrypt is a string; passed through unchanged (no shared keys added)`);
    }
    return value;
  }
  const copy = { ...value, enableDetailedLogging: true };
  const gemini = [];
  let moved = 0, dropped = 0;
  const take = (e, fromProvider) => {
    if (!GEMINI_KEY.test(e)) { dropped++; return; }
    if (!gemini.includes(e)) { gemini.push(e); if (fromProvider) moved++; }
  };
  for (const f of GEMINI_FIELDS) {
    for (const e of splitKeys(copy[f])) take(e, false);
    delete copy[f];
  }
  for (const f of DROPPED_FIELDS) {
    for (const e of splitKeys(copy[f])) {
      if (GEMINI_KEY.test(e)) take(e, true); else dropped++;
    }
    delete copy[f];
  }
  if (moved || dropped) {
    console.error(`Note: '${user}' moved ${moved} Gemini-shaped key(s) from provider lists, dropped ${dropped} other entr(ies)`);
  }
  if (gemini.length) copy.userGeminiApiKeys = gemini;
  if (shared.length) copy.sharedGeminiApiKeys = shared;
  return copy;
}

function buildEncryptedPayload(plainText, passphrase, filename) {
  const inputBuffer = Buffer.from(plainText, "utf8");
  const salt = randomBytes(16);
  const iv = randomBytes(16);
  const iterations = 310000;
  const key = pbkdf2Sync(passphrase, salt, iterations, 32, "sha256");

  // AES-CTR intentionally has no auth tag: wrong key still yields bytes.
  const cipher = createCipheriv("aes-256-ctr", key, iv);
  const encrypted = Buffer.concat([cipher.update(inputBuffer), cipher.final()]);

  return {
    v: 1,
    alg: "AES-256-CTR",
    kdf: "PBKDF2-SHA256",
    iterations,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    data: encrypted.toString("base64"),
    filename,
    mimeType: "application/json",
  };
}

async function main() {
  const [, , inputFile = "private/file.json", outputFileArg] = process.argv;

  const outputFile = outputFileArg || "json/index.html";
  let inputText;
  try {
    inputText = await readFile(inputFile, "utf8");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    console.error(`Error: input ${inputFile} not found`);
    usage();
    process.exit(1);
  }
  const inputObject = JSON.parse(inputText);

  if (
    !inputObject ||
    typeof inputObject !== "object" ||
    Array.isArray(inputObject)
  ) {
    throw new Error("Input must be a JSON object keyed by username");
  }

  // shared.json beside the input: {"geminiApiKeys": [...]} goes into every object payload.
  let shared = [];
  try {
    const sharedText = await readFile(join(dirname(inputFile), "shared.json"), "utf8");
    shared = splitKeys(JSON.parse(sharedText).geminiApiKeys).filter((k) => GEMINI_KEY.test(k));
  } catch (error) {
    if (error.code !== "ENOENT") throw new Error(`shared.json unreadable: ${error.message}`);
  }
  if (shared.length) console.error(`Note: adding ${shared.length} shared key(s) from shared.json`);

  const embeddedUsers = {};
  const entries = Object.entries(inputObject);

  if (!entries.length) {
    throw new Error("Input JSON has no users");
  }

  for (const [user, definition] of entries) {
    if (
      !definition ||
      typeof definition !== "object" ||
      Array.isArray(definition)
    ) {
      throw new Error(
        `User '${user}' must be an object with key and encrypt fields`,
      );
    }

    const passphrase = `${definition.key || ""}`;
    if (!passphrase) {
      throw new Error(`User '${user}' is missing a non-empty key`);
    }

    if (!("encrypt" in definition)) {
      throw new Error(`User '${user}' is missing encrypt field`);
    }

    const plainText = normalizeEncryptContent(
      prepareEncrypt(user, definition.encrypt, shared),
    );
    const filename =
      typeof definition.filename === "string" && definition.filename.trim()
        ? definition.filename.trim()
        : `${user}.json`;

    embeddedUsers[user] = buildEncryptedPayload(
      plainText,
      passphrase,
      filename,
    );
  }

  const html = buildHtml(embeddedUsers);
  await writeFile(outputFile, html, "utf8");
  console.log(`Generated encrypted page at ${outputFile}`);
  console.log(
    "URL format: https://distributed-clients.github.io/json/?user=<user>",
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
