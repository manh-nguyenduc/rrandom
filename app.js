"use strict";
/* ---------- randomness ---------- */
const cryptoObj = globalThis.crypto;
const R = {
  int(max){ // uniform integer in [0, max)
    if (max <= 1) return 0;
    const lim = Math.floor(0x100000000 / max) * max, b = new Uint32Array(1);
    for(;;){ cryptoObj.getRandomValues(b); if (b[0] < lim) return b[0] % max; }
  },
  bytes(n){ const a = new Uint8Array(n); cryptoObj.getRandomValues(a); return a; },
  pick(arr){ return arr[R.int(arr.length)]; },
  str(alpha, len){ const a = Array.isArray(alpha) ? alpha : [...alpha]; let s = ""; for (let i = 0; i < len; i++) s += a[R.int(a.length)]; return s; },
  shuffle(a){ for (let i = a.length - 1; i > 0; i--){ const j = R.int(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; },
};
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const b64url = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const A = {
  lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?/~",
  b62: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  b64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  b32: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  grouped: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
  lookalike: "Il1O0o|`'\"",
};
const CRC_T = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++){ let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c; } return t; })();
const crc32 = (str) => { let c = 0xFFFFFFFF; for (const x of new TextEncoder().encode(str)) c = CRC_T[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
const b32enc = (bytes) => { // RFC 4648 base32, no padding
  let val = 0, bits = 0, out = "";
  for (const x of bytes){ val = ((val << 8) | x) & 0xFFFF; bits += 8; while (bits >= 5){ out += A.b32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += A.b32[(val << (5 - bits)) & 31];
  return out;
};
const toB62 = (n, w) => { let s = ""; do { s = A.b62[n % 62] + s; n = Math.floor(n / 62); } while (n > 0); return s.padStart(w, "0"); };

/* ---------- formatting ---------- */
const BIG = [[1e18,"quintillion"],[1e15,"quadrillion"],[1e12,"trillion"],[1e9,"billion"],[1e6,"million"]];
function bigNum(log10){
  if (log10 >= 21) return "10^" + Math.round(log10);
  const n = Math.pow(10, log10);
  for (const [v, w] of BIG) if (n >= v) return (n / v).toFixed(n / v < 10 ? 1 : 0).replace(/\.0$/, "") + " " + w;
  return Math.round(n).toLocaleString("en-US");
}
function crackTime(bits){ // average guesses = 2^(bits-1) at 10^12 guesses per second
  const secLog10 = (bits - 1) * Math.LOG10E * Math.LN2 - 12;
  const units = [[0,"seconds",1],[Math.log10(60),"minutes",60],[Math.log10(3600),"hours",3600],[Math.log10(86400),"days",86400],[Math.log10(31557600),"years",31557600]];
  if (secLog10 < 0) return "instantly";
  if (secLog10 > Math.log10(31557600) + 10.14) return "longer than the universe has existed";
  let u = units[0]; for (const x of units) if (secLog10 >= x[0]) u = x;
  const v = Math.pow(10, secLog10) / u[2];
  if (u[1] === "years" && v >= 1e6) return "about " + bigNum(Math.log10(v)) + " years";
  return "about " + Math.max(1, Math.round(v)).toLocaleString("en-US") + " " + u[1];
}
function strength(bits){
  if (bits < 45) return ["weak", "Weak"];
  if (bits < 64) return ["fair", "Fair"];
  if (bits < 90) return ["strong", "Strong"];
  return ["strong", "Very strong"];
}
const entropyMeta = (bits) => { const [lvl, word] = strength(bits); return { bits, level: lvl,
  html: `<strong>${word}</strong>, ${Math.floor(bits)} bits of entropy. Cracking would take ${crackTime(bits)} at a trillion guesses per second.` }; };

/* ---------- user agent versions ---------- */
function uaVersions(){
  const v = globalThis.RR_UA || {}, now = Date.now(), cycle = 28 * 864e5;
  const since = (date) => { const t = Date.parse(date); return Number.isFinite(t) ? Math.max(0, Math.floor((now - t) / cycle)) : null; };
  // Last known versions, used when versions.js is missing or a field is unusable.
  const BASE = { chrome:["158.0.8127.37","2026-11-03"], firefox:["160.0","2026-11-10"], edge:["157.0.4341.60","2026-11-06"] };
  const checked = since(v.updated);
  let estimated = false;
  const resolve = (k) => {
    let ver = String(v[k] || ""), drift = checked;
    if (!(parseInt(ver, 10) > 0) || drift === null){ ver = BASE[k][0]; drift = since(BASE[k][1]) || 0; estimated = true; }
    const parts = ver.split(".").map((x) => parseInt(x, 10) || 0), major = parts[0] + drift;
    // Exact builds are unknown after drifting; Chromium builds advance roughly 80 per release.
    return { major, full: drift ? `${major}.0.${parts[2] ? parts[2] + drift * 80 : 0}.${parts[2] ? 100 : 0}` : ver };
  };
  const c = resolve("chrome"), f = resolve("firefox"), e = resolve("edge");
  const d = new Date(), y = d.getFullYear(), m = d.getMonth() + 1;
  const safariEst = `${m >= 9 ? y - 1999 : y - 2000}.${Math.min(6, Math.floor((m >= 9 ? m - 9 : m + 3) / 2))}`;
  const safari = checked !== null && checked <= 4 && /^\d+\.\d+$/.test(String(v.safari)) ? String(v.safari) : safariEst;
  const source = estimated ? (checked !== null ? `Versions checked ${v.updated}; missing ones estimated from release schedules.` : "Versions estimated from each browser's release schedule.")
    : checked ? `Based on versions checked ${v.updated}, adjusted for releases since.` : `Browser versions checked ${v.updated}.`;
  return { chrome:c.major, chromeFull:c.full, firefox:f.major, edge:e.major, edgeFull:e.full, safari, source };
}
const UA_MATRIX = { chrome:["windows","mac","linux","android","ios"], firefox:["windows","mac","linux","android","ios"], edge:["windows","mac","linux","android","ios"], safari:["mac","ios"] };
const UA_WEIGHTS = [["chrome","windows",30],["chrome","android",22],["safari","ios",14],["chrome","mac",8],["safari","mac",6],["edge","windows",7],["firefox","windows",4],["chrome","linux",2],["firefox","linux",1],["firefox","mac",1],["chrome","ios",2],["firefox","android",1],["edge","mac",1],["edge","android",1]];
function buildUA(browser, os, V){
  const awk = "AppleWebKit/537.36 (KHTML, like Gecko)";
  const plat = { windows:"Windows NT 10.0; Win64; x64", mac:"Macintosh; Intel Mac OS X 10_15_7", linux:"X11; Linux x86_64", android:"Linux; Android 10; K" }[os];
  const ios = "iPhone; CPU iPhone OS 18_6 like Mac OS X", iosTail = "Mobile/15E148";
  if (browser === "chrome"){
    if (os === "ios") return `Mozilla/5.0 (${ios}) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/${V.chromeFull} ${iosTail} Safari/604.1`;
    return `Mozilla/5.0 (${plat}) ${awk} Chrome/${V.chrome}.0.0.0 ${os === "android" ? "Mobile " : ""}Safari/537.36`;
  }
  if (browser === "edge"){
    if (os === "ios") return `Mozilla/5.0 (${ios}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${parseInt(V.safari, 10)}.0 EdgiOS/${V.edgeFull} ${iosTail} Safari/604.1`;
    if (os === "android") return `Mozilla/5.0 (${plat}) ${awk} Chrome/${V.edge}.0.0.0 Mobile Safari/537.36 EdgA/${V.edgeFull}`;
    return `Mozilla/5.0 (${plat}) ${awk} Chrome/${V.edge}.0.0.0 Safari/537.36 Edg/${V.edgeFull}`;
  }
  if (browser === "firefox"){
    const f = V.firefox;
    if (os === "ios") return `Mozilla/5.0 (${ios}) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/${f}.0 ${iosTail} Safari/605.1.15`;
    if (os === "android") return `Mozilla/5.0 (Android ${R.pick([13,14,15,16])}; Mobile; rv:${f}.0) Gecko/${f}.0 Firefox/${f}.0`;
    const p = { windows:"Windows NT 10.0; Win64; x64", mac:"Macintosh; Intel Mac OS X 10.15", linux:"X11; Linux x86_64" }[os];
    return `Mozilla/5.0 (${p}; rv:${f}.0) Gecko/20100101 Firefox/${f}.0`;
  }
  // safari
  if (os === "ios") return `Mozilla/5.0 (${ios}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${V.safari} ${iosTail} Safari/604.1`;
  return `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${V.safari} Safari/605.1.15`;
}

/* ---------- word list (lazy) ---------- */
let wordsPromise = null;
function loadWords(){
  if (globalThis.RR_WORDS) return Promise.resolve(globalThis.RR_WORDS);
  if (!wordsPromise) wordsPromise = new Promise((ok, fail) => {
    const s = document.createElement("script"); s.src = "words.js"; s.async = true;
    s.onload = () => ok(globalThis.RR_WORDS); s.onerror = () => { wordsPromise = null; fail(new Error("words")); };
    document.head.appendChild(s);
  });
  return wordsPromise;
}

/* ---------- generators ---------- */
const COUNT = { type:"range", key:"count", label:"How many", min:1, max:50, def:1 };
class GenError extends Error {}

const TOOLS = [
{
  id:"password", group:"Secrets", name:"Password", sub:"Letters, digits, symbols",
  about:"A random password for an account or a database user. At least one character from every set you pick is guaranteed.",
  fields:[
    { type:"range", key:"length", label:"Length", min:6, max:128, def:20 },
    { type:"checks", label:"Characters", items:[["upper","A–Z",true],["lower","a–z",true],["digits","0–9",true],["symbols","!@#$",true]] },
    { type:"checks", label:"Options", items:[["noLookalike","Skip look-alikes (Il1O0o)",false]] },
    COUNT,
  ],
  pool(s){
    const sets = ["upper","lower","digits","symbols"].filter((k) => s[k]).map((k) => [...A[k]].filter((c) => !s.noLookalike || !A.lookalike.includes(c)));
    if (!sets.length) throw new GenError("Pick at least one character set.");
    return sets;
  },
  gen(s){
    const sets = this.pool(s), all = sets.flat();
    for (let tries = 0; tries < 1000; tries++){
      const pw = R.str(all, s.length);
      if (s.length < sets.length || sets.every((set) => set.some((c) => pw.includes(c)))) return pw;
    }
    return R.str(all, s.length);
  },
  meta(s){ return entropyMeta(s.length * Math.log2(this.pool(s).flat().length)); },
},
{
  id:"apikey", group:"Secrets", name:"API key", sub:"8 styles, prefix, checksum",
  about:"Secret tokens for your own services. Pick the format your system expects; a prefix makes leaked keys easy to search for.",
  fields:[
    { type:"styles", key:"style", label:"Style", def:"prefixed", options:[
      ["prefixed","Prefixed","sk_live_4eC39HqLyjWD","A prefix makes leaked keys easy to scan for"],
      ["checksum","Prefixed + checksum","app_k9XqT2…0aZ3fT","Last 6 characters catch typos before a lookup"],
      ["hex","Hex","9f86d081884c7d65","Works in any system, longest output"],
      ["b64url","Base64 URL-safe","Lx3Qk_v9-ZpR2wYe","Compact and safe in URLs and headers"],
      ["b62","Base62","7GkQ2mZpW4xHa9Tc","Letters and digits only, double-click selects it all"],
      ["base32","Base32","JBSWY3DPEHPK3PXP","RFC 4648, for 2FA apps (TOTP)"],
      ["grouped","Grouped","K7QM-2XPA-9HRT","License or invite codes people type"],
      ["pair","Key ID + secret","AKX7Q2… / wJalrX…","A public ID with a separate secret"]] },
    { type:"text", key:"prefix", label:"Prefix", def:"sk_live_", show:(s) => s.style === "prefixed" || s.style === "checksum" },
    { type:"range", key:"chars", label:"Random characters", min:16, max:96, def:32, show:(s) => ["prefixed","checksum","b62"].includes(s.style) },
    { type:"range", key:"bytes", label:"Random bytes", min:16, max:128, step:8, def:32, show:(s) => s.style === "hex" || s.style === "b64url" },
    { type:"range", key:"b32bytes", label:"Random bytes (20 is standard for TOTP)", min:10, max:64, step:5, def:20, show:(s) => s.style === "base32" },
    { type:"range", key:"groups", label:"Groups", min:3, max:8, def:5, show:(s) => s.style === "grouped" },
    { type:"range", key:"gsize", label:"Characters per group", min:4, max:6, def:5, show:(s) => s.style === "grouped" },
    COUNT,
  ],
  gen(s){
    switch (s.style){
      case "prefixed": return s.prefix + R.str(A.b62, s.chars);
      case "checksum": { const body = s.prefix + R.str(A.b62, s.chars); return body + toB62(crc32(body), 6); }
      case "hex": return hex(R.bytes(s.bytes));
      case "b64url": return b64url(R.bytes(s.bytes));
      case "b62": return R.str(A.b62, s.chars);
      case "base32": return b32enc(R.bytes(s.b32bytes));
      case "grouped": return Array.from({ length:s.groups }, () => R.str(A.grouped, s.gsize)).join("-");
      case "pair": return "Key ID   AK" + R.str(A.b32, 18) + "\nSecret   " + R.str(A.b64, 40);
    }
  },
  meta(s){
    const bits = { prefixed:s.chars*Math.log2(62), checksum:s.chars*Math.log2(62), hex:s.bytes*8, b64url:s.bytes*8, base32:s.b32bytes*8, b62:s.chars*Math.log2(62),
      grouped:s.groups*s.gsize*5, pair:240 }[s.style];
    return entropyMeta(bits);
  },
},
{
  id:"passphrase", group:"Secrets", name:"Passphrase", sub:"Words you can type",
  about:"Random words from the EFF list of 7,776. Easy to type and remember, and every word adds about 12.9 bits of strength.",
  fields:[
    { type:"range", key:"words", label:"Words", min:3, max:12, def:5 },
    { type:"select", key:"sep", label:"Separator", def:"-", options:[["-","Hyphen"],[" ","Space"],[".","Dot"],["_","Underscore"],["","None"],["digit","Random digit"]] },
    { type:"select", key:"caps", label:"Capitalization", def:"none", options:[["none","lowercase"],["first","Capitalize Each"],["upper","UPPERCASE"],["random","One random word upper"]] },
    { type:"checks", label:"Options", items:[["number","Add a number to one word",false]] },
    COUNT,
  ],
  async: true,
  gen(s, words){
    let w = Array.from({ length:s.words }, () => R.pick(words));
    if (s.caps === "first") w = w.map((x) => x[0].toUpperCase() + x.slice(1));
    if (s.caps === "upper") w = w.map((x) => x.toUpperCase());
    if (s.caps === "random"){ const i = R.int(w.length); w[i] = w[i].toUpperCase(); }
    if (s.number){ const i = R.int(w.length); w[i] += R.int(10); }
    if (s.sep === "digit") return w.reduce((acc, x, i) => acc + (i ? R.int(10) : "") + x, "");
    return w.join(s.sep);
  },
  meta(s){
    let bits = s.words * Math.log2(7776);
    if (s.number) bits += Math.log2(10) + Math.log2(s.words);
    if (s.caps === "random") bits += Math.log2(s.words);
    if (s.sep === "digit") bits += (s.words - 1) * Math.log2(10);
    return entropyMeta(bits);
  },
},
{
  id:"jwt", group:"Secrets", name:"JWT", sub:"Signing secrets, test tokens",
  about:"An HMAC secret for your auth server, or a signed token for testing an API. Tokens are signed in your browser.",
  fields:[
    { type:"select", key:"output", label:"Generate", def:"secret", options:[["secret","Signing secret"],["token","Signed test token"]] },
    { type:"select", key:"alg", label:"Algorithm", def:"HS256", options:[["HS256","HS256 (32-byte secret)"],["HS384","HS384 (48-byte secret)"],["HS512","HS512 (64-byte secret)"]] },
    { type:"select", key:"enc", label:"Secret format", def:"b64url", options:[["b64url","Base64 URL-safe"],["hex","Hex"]] },
    { type:"text", key:"sub", label:"Subject (sub)", def:"user_123", show:(s) => s.output === "token" },
    { type:"select", key:"exp", label:"Expires in", def:"3600", show:(s) => s.output === "token",
      options:[["900","15 minutes"],["3600","1 hour"],["86400","1 day"],["604800","7 days"],["2592000","30 days"]] },
    COUNT,
  ],
  bytes(s){ return { HS256:32, HS384:48, HS512:64 }[s.alg]; },
  secretOf(s){ const b = R.bytes(this.bytes(s)); return s.enc === "hex" ? hex(b) : b64url(b); },
  async before(s){
    if (s.output !== "token") return {};
    if (!cryptoObj.subtle) throw new GenError("Signing needs a secure page. Open rrandom over https or from localhost.");
    const secret = this.secretOf(s);
    // Most JWT libraries use the secret string's UTF-8 bytes as the HMAC key, so sign the same way.
    const key = await cryptoObj.subtle.importKey("raw", new TextEncoder().encode(secret),
      { name:"HMAC", hash:"SHA-" + s.alg.slice(2) }, false, ["sign"]);
    return { secret, key, payload0:null };
  },
  async gen(s, words, ctx){
    if (s.output !== "token") return this.secretOf(s);
    const enc = (o) => b64url(new TextEncoder().encode(JSON.stringify(o)));
    const iat = Math.floor(Date.now() / 1000);
    const payload = { sub:s.sub, iat, exp:iat + +s.exp, jti:R.str(A.b62, 16) };
    ctx.payload0 = ctx.payload0 || payload;
    const body = enc({ alg:s.alg, typ:"JWT" }) + "." + enc(payload);
    const sig = new Uint8Array(await cryptoObj.subtle.sign("HMAC", ctx.key, new TextEncoder().encode(body)));
    return body + "." + b64url(sig);
  },
  meta(s){
    if (s.output !== "token") return entropyMeta(this.bytes(s) * 8);
    const until = new Date(Date.now() + s.exp * 1000).toLocaleString("en-GB", { dateStyle:"medium", timeStyle:"short" });
    return { bits:0, level:"none", html:`<strong>${s.alg} token</strong>, valid until ${until}. Verify it with the signing secret below.` };
  },
  extra(s, ctx){
    if (s.output !== "token" || !ctx || !ctx.secret) return "";
    return `<div class="yours"><p>Signing secret, used as a UTF-8 string</p><div class="row"><code>${esc(ctx.secret)}</code><button type="button" data-copy="${esc(ctx.secret)}">Copy</button></div>
      <p class="gap">Payload of the first token</p><code>${esc(JSON.stringify(ctx.payload0))}</code></div>`;
  },
},
{
  id:"ulid", group:"IDs", name:"ULID", sub:"Sortable 26-character IDs",
  about:"26 characters that sort by creation time, in a case-insensitive alphabet with no look-alike letters. A tidy replacement for UUIDs as database keys.",
  fields:[
    { type:"checks", label:"Options", items:[["monotonic","Keep a batch strictly increasing",true],["lower","Lowercase",false]] },
    COUNT,
  ],
  before(){ return { prev:null }; },
  gen(s, words, ctx){
    const C = "0123456789ABCDEFGHJKMNPQRSTVWXYZ", ms = Date.now();
    let rnd;
    if (s.monotonic && ctx.prev && ctx.prev.ms === ms){
      rnd = ctx.prev.rnd.slice(); let i = 15;
      while (i >= 0 && rnd[i] === 31){ rnd[i] = 0; i--; }
      if (i < 0) throw new GenError("Ran out of room for increasing IDs in this millisecond. Press Generate again.");
      rnd[i]++;
    } else rnd = Array.from({ length:16 }, () => R.int(32));
    ctx.prev = { ms, rnd };
    let t = "", x = ms;
    for (let i = 0; i < 10; i++){ t = C[x % 32] + t; x = Math.floor(x / 32); }
    const id = t + rnd.map((v) => C[v]).join("");
    return s.lower ? id.toLowerCase() : id;
  },
  meta(){
    const when = new Date().toISOString().replace("T", " ").slice(0, 19);
    return { bits:80, level:"none", html:`<strong>80 random bits</strong> after a 48-bit timestamp, ${when} UTC. Sorting the text sorts by time.` };
  },
},
{
  id:"uuid", group:"IDs", name:"UUID", sub:"v4 random, v7 sortable",
  about:"Version 4 is fully random. Version 7 starts with a timestamp, so new IDs sort after old ones, including within a batch, and index well in databases.",
  fields:[
    { type:"select", key:"version", label:"Version", def:"v4", options:[["v4","v4, random"],["v7","v7, time-ordered"]] },
    { type:"checks", label:"Format", items:[["upper","Uppercase",false],["nohyphen","No hyphens",false],["braces","Braces {}",false]] },
    COUNT,
  ],
  before(){ return { last:null }; },
  gen(s, words, ctx){
    const b = R.bytes(16);
    if (s.version === "v7"){
      // rand_a (12 bits) is a counter within one millisecond, so a batch sorts in creation order.
      let ms = Date.now(), seq = R.int(0x800);
      if (ctx.last && ms <= ctx.last.ms){ ms = ctx.last.ms; seq = ctx.last.seq + 1; if (seq > 0xFFF){ ms++; seq = R.int(0x800); } }
      ctx.last = { ms, seq };
      for (let i = 0; i < 6; i++) b[i] = Math.floor(ms / Math.pow(2, 8 * (5 - i))) & 255;
      b[6] = 0x70 | (seq >>> 8); b[7] = seq & 255;
    } else b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = hex(b);
    let u = s.nohyphen ? h : `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
    if (s.upper) u = u.toUpperCase();
    return s.braces ? `{${u}}` : u;
  },
  meta(s){
    return s.version === "v7"
      ? { bits:74, level:"strong", html:"<strong>74 random bits</strong> after a 48-bit millisecond timestamp. Unique, but not a secret: anyone can read when it was made." }
      : { bits:122, level:"strong", html:"<strong>122 random bits.</strong> You would need about 2.7 quintillion IDs for a 50% chance of a single duplicate." };
  },
},
{
  id:"nanoid", group:"IDs", name:"NanoID", sub:"Short URL-safe IDs",
  about:"Compact IDs for URLs and records. Fewer characters than a UUID for the same collision safety.",
  fields:[
    { type:"range", key:"size", label:"Length", min:4, max:64, def:21 },
    { type:"select", key:"preset", label:"Alphabet", def:"urlsafe", options:[["urlsafe","URL-safe (A–Z a–z 0–9 _ -)"],["alnum","Alphanumeric"],["lowernum","Lowercase and digits"],["hexlower","Hex"],["numbers","Digits only"],["nolook","No look-alikes"],["custom","Custom"]] },
    { type:"text", key:"alphabet", label:"Custom alphabet", def:"abcdef123456", show:(s) => s.preset === "custom" },
    COUNT,
  ],
  alpha(s){
    const map = { urlsafe:"useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict", alnum:A.b62, lowernum:A.digits + A.lower,
      hexlower:"0123456789abcdef", numbers:A.digits, nolook:"6789BCDFGHJKLMNPQRTWbcdfghjkmnpqrtwz" };
    const a = s.preset === "custom" ? [...new Set([...s.alphabet])] : [...map[s.preset]];
    if (a.length < 2) throw new GenError("Use at least two different characters in the alphabet.");
    return a;
  },
  gen(s){ return R.str(this.alpha(s), s.size); },
  meta(s){
    const a = this.alpha(s).length, bits = s.size * Math.log2(a);
    const log10Ids = 0.5 * (Math.log10(-2 * Math.log(0.99)) + s.size * Math.log10(a));
    const [lvl] = strength(bits);
    return { bits, level: bits < 45 ? "weak" : lvl, html:`<strong>${Math.floor(bits)} bits.</strong> About ${bigNum(log10Ids)} IDs before a 1% chance of any duplicate.` };
  },
},
{
  id:"useragent", group:"Other", name:"User agent", sub:"Current browser versions",
  about:"Realistic user agent strings for testing and scraping, using the browser versions people are running now.",
  fields:[
    { type:"select", key:"browser", label:"Browser", def:"any", options:[["any","Any, weighted by usage"],["chrome","Chrome"],["safari","Safari"],["edge","Edge"],["firefox","Firefox"]] },
    { type:"select", key:"os", label:"Platform", def:"any", options:[["any","Any"],["windows","Windows"],["mac","macOS"],["linux","Linux"],["android","Android"],["ios","iOS"]] },
    COUNT,
  ],
  gen(s){
    const V = uaVersions();
    let pool = UA_WEIGHTS.filter(([b, o]) => (s.browser === "any" || b === s.browser) && (s.os === "any" || o === s.os));
    if (!pool.length){
      if (s.browser !== "any" && !UA_MATRIX[s.browser].includes(s.os)) throw new GenError(`${s.browser === "safari" ? "Safari" : s.browser} only runs on macOS and iOS. Pick one of those platforms.`);
      pool = [[s.browser, s.os, 1]];
    }
    const total = pool.reduce((t, x) => t + x[2], 0); let r = R.int(total), choice = pool[0];
    for (const x of pool){ if (r < x[2]){ choice = x; break; } r -= x[2]; }
    return buildUA(choice[0], choice[1], V);
  },
  meta(){
    const V = uaVersions();
    return { bits:0, level:"none", html:`Chrome ${V.chrome}, Safari ${V.safari}, Edge ${V.edge}, Firefox ${V.firefox}. ${V.source}` };
  },
  extra(){
    const ua = navigator.userAgent.replace(/[&<>]/g, (c) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;" }[c]));
    return `<div class="yours"><p>Your browser sends</p><code>${ua}</code></div>`;
  },
},
{
  id:"pick", group:"Other", name:"Pick from list", sub:"Draws, shuffles, teams",
  about:"Paste names or options, one per line, then press Generate. Pick winners, shuffle the order, or split everyone into even teams.",
  plain:true,
  fields:[
    { type:"textarea", key:"items", label:"Your list", def:"Alice\nBob\nCharlie\nDiana\nEthan\nFiona\nGeorge\nHannah\nIvan\nJulia" },
    { type:"select", key:"mode", label:"Do this", def:"pick", options:[["pick","Pick winners"],["shuffle","Shuffle the list"],["teams","Split into teams"]] },
    { type:"range", key:"picks", label:"Winners", min:1, max:20, def:1, show:(s) => s.mode === "pick" },
    { type:"range", key:"teams", label:"Teams", min:2, max:12, def:2, show:(s) => s.mode === "teams" },
    { type:"checks", label:"Options", items:[["repeat","Allow the same item twice",false]], show:(s) => s.mode === "pick" },
  ],
  list(s){
    const a = String(s.items).split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
    if (!a.length) throw new GenError("Add at least one item to the list, one per line.");
    return a;
  },
  gen(s){
    const a = this.list(s);
    if (s.mode === "shuffle") return R.shuffle(a.slice()).map((x, i) => `${i + 1}. ${x}`).join("\n");
    if (s.mode === "teams"){
      const sh = R.shuffle(a.slice()), n = Math.min(s.teams, sh.length), t = Array.from({ length:n }, () => []);
      sh.forEach((x, i) => t[i % n].push(x));
      return t.map((m, i) => `Team ${i + 1}: ${m.join(", ")}`).join("\n");
    }
    if (s.repeat) return Array.from({ length:s.picks }, () => R.pick(a)).join("\n");
    return R.shuffle(a.slice()).slice(0, s.picks).join("\n");
  },
  meta(s){
    const n = this.list(s).length;
    const html = s.mode === "teams" ? `${n} people across ${Math.min(s.teams, n)} teams. Team sizes differ by at most one.`
      : s.mode === "shuffle" ? `${n} items in a fair random order.`
      : !s.repeat && s.picks > n ? `The list has ${n} items, so all of them were picked.`
      : `Every one of the ${n} items had the same chance.`;
    return { bits:0, level:"none", html };
  },
},
];
const ORDER = ["password","passphrase","apikey","jwt","uuid","ulid","nanoid","useragent","pick"];
TOOLS.sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id));

/* ---------- state ---------- */
const store = {
  get(k){ try { return JSON.parse(localStorage.getItem("rr:" + k)); } catch { return null; } },
  set(k, v){ try { localStorage.setItem("rr:" + k, JSON.stringify(v)); } catch {} },
};
function defaults(tool){
  const s = {};
  for (const f of tool.fields){
    if (f.type === "checks") for (const [k,, d] of f.items) s[k] = d;
    else s[f.key] = f.def;
  }
  return s;
}
const states = {};
// Saved settings may come from an older version of the page; keep only values that are still valid.
function sanitize(tool, saved){
  const s = defaults(tool);
  if (!saved || typeof saved !== "object") return s;
  for (const f of tool.fields){
    if (f.type === "checks"){ for (const [k] of f.items) if (typeof saved[k] === "boolean") s[k] = saved[k]; continue; }
    const v = saved[f.key];
    if (f.type === "range"){
      const n = Number(v), step = f.step || 1;
      if (Number.isFinite(n)) s[f.key] = Math.min(f.max, Math.max(f.min, f.min + Math.round((n - f.min) / step) * step));
    } else if (f.type === "select" || f.type === "styles"){
      if (f.options.some((o) => o[0] === v)) s[f.key] = v;
    } else if (typeof v === "string") s[f.key] = v.slice(0, 20000);
  }
  return s;
}
TOOLS.forEach((t) => { states[t.id] = sanitize(t, store.get(t.id)); });

/* ---------- DOM ---------- */
const $ = (id) => document.getElementById(id);
const el = { nav:$("nav"), title:$("title"), about:$("about"), value:$("value"), opts:$("opts"), bars:$("bars"),
  meter:$("meter"), meterText:$("meterText"), extra:$("extra"), copyAll:$("copyAll"), download:$("download"), toast:$("toast") };
el.bars.innerHTML = "<i></i>".repeat(10);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;" }[c]));

let current = TOOLS[0], results = [], animId = 0;
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)");

el.nav.innerHTML = TOOLS.map((t, i) => (i === 0 || TOOLS[i - 1].group !== t.group ? `<span class="grp" role="presentation">${t.group}</span>` : "") + `<button type="button" role="tab" id="tab-${t.id}" data-id="${t.id}" aria-selected="false" aria-controls="panel"><b>${t.name}</b><small>${t.sub}</small></button>`).join("");
el.nav.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) select(b.dataset.id, true); });
el.nav.addEventListener("keydown", (e) => {
  if (!["ArrowDown","ArrowUp","ArrowLeft","ArrowRight","Home","End"].includes(e.key)) return;
  e.preventDefault();
  const i = TOOLS.indexOf(current), d = e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : -1;
  const next = e.key === "Home" ? TOOLS[0] : e.key === "End" ? TOOLS[TOOLS.length - 1] : TOOLS[(i + d + TOOLS.length) % TOOLS.length];
  select(next.id, true); $("tab-" + next.id).focus();
});

function renderFields(){
  const s = states[current.id];
  el.opts.innerHTML = current.fields.map((f, i) => {
    const id = `f-${current.id}-${i}`;
    if (f.type === "range") return `<div class="f" data-i="${i}"><label for="${id}">${f.label}<output id="${id}-o">${s[f.key]}</output></label>
      <input type="range" id="${id}" data-key="${f.key}" min="${f.min}" max="${f.max}" step="${f.step || 1}" value="${s[f.key]}"></div>`;
    if (f.type === "select") return `<div class="f" data-i="${i}"><label for="${id}">${f.label}</label><select id="${id}" data-key="${f.key}">
      ${f.options.map(([v, l]) => `<option value="${esc(v)}"${v === s[f.key] ? " selected" : ""}>${l}</option>`).join("")}</select></div>`;
    if (f.type === "text") return `<div class="f" data-i="${i}"><label for="${id}">${f.label}</label>
      <input type="text" id="${id}" data-key="${f.key}" value="${esc(s[f.key])}" spellcheck="false" autocomplete="off"></div>`;
    if (f.type === "textarea") return `<div class="f wide" data-i="${i}"><label for="${id}">${f.label}</label>
      <textarea id="${id}" data-key="${f.key}" rows="6" spellcheck="false">${esc(s[f.key])}</textarea></div>`;
    if (f.type === "styles") return `<div class="f wide" data-i="${i}" role="radiogroup" aria-label="${f.label}"><span class="l">${f.label}</span><div class="styles">
      ${f.options.map(([v, name, ex, note]) => `<label class="sty"><input type="radio" name="${id}" data-key="${f.key}" value="${esc(v)}"${v === s[f.key] ? " checked" : ""}>
        <span><i class="mk" aria-hidden="true"><svg viewBox="0 0 16 16"><path d="M4.6 8.3l2.3 2.3 4.5-4.9"/></svg></i><b>${name}</b><code>${esc(ex)}</code><small>${note}</small></span></label>`).join("")}</div></div>`;
    if (f.type === "checks") return `<div class="f" data-i="${i}" role="group" aria-label="${f.label}"><span class="l">${f.label}</span><div class="checks">
      ${f.items.map(([k, l]) => `<label class="chk"><input type="checkbox" data-key="${k}"${s[k] ? " checked" : ""}><span><i class="mk" aria-hidden="true"><svg viewBox="0 0 16 16"><path d="M4.6 8.3l2.3 2.3 4.5-4.9"/></svg></i>${l}</span></label>`).join("")}</div></div>`;
  }).join("");
  syncVisibility();
}
function syncVisibility(){
  const s = states[current.id];
  el.opts.querySelectorAll(".f").forEach((n) => { const f = current.fields[n.dataset.i]; n.hidden = f.show ? !f.show(s) : false; });
}
el.opts.addEventListener("input", (e) => {
  const t = e.target, k = t.dataset.key; if (!k) return;
  const s = states[current.id];
  s[k] = t.type === "checkbox" ? t.checked : t.type === "range" ? +t.value : t.value;
  if (t.type === "range") $(t.id + "-o").textContent = t.value;
  store.set(current.id, s);
  syncVisibility();
  if (t.tagName === "TEXTAREA"){ renderMeta(); return; } // redraw only when the person presses Generate
  generate(!(t.type === "range" || t.type === "text"));
});

function select(id, push){
  const found = TOOLS.find((t) => t.id === id);
  current = found || TOOLS[0];
  el.nav.querySelectorAll("button").forEach((b) => { const on = b.dataset.id === current.id; b.setAttribute("aria-selected", on); b.tabIndex = on ? 0 : -1; });
  $("panel").setAttribute("aria-labelledby", "tab-" + current.id);
  $("tab-" + current.id).scrollIntoView({ block:"nearest", inline:"nearest" });
  el.title.textContent = current.name; el.about.textContent = current.about;
  document.title = `${current.name} generator | rrandom`;
  if ((push || (!found && location.hash)) && location.hash !== "#" + current.id) history.replaceState(null, "", "#" + current.id);
  results = []; ctxOf.delete(current); renderList();
  renderFields();
  generate(true);
}

function sizeClass(v){ return v.length > 90 ? "xlong" : v.length > 44 ? "long" : ""; }
function showValue(v, animate){
  const n = el.value; n.className = "value " + sizeClass(v) + (current.plain ? " plain" : "");
  const id = ++animId;
  if (!animate || reduceMotion.matches || v.length > 160){ n.textContent = v; return; }
  if (current.plain){ // raffle: flick through list items, slowing down, then land on the result
    let pool; try { pool = current.list(states[current.id]); } catch { pool = [v]; }
    let step = 0; const tick = () => {
      if (id !== animId) return;
      if (step++ > 9){ n.textContent = v; return; }
      n.textContent = R.pick(pool); setTimeout(tick, 30 + step * step * 4);
    };
    tick(); return;
  }
  const chars = [...new Set(v.replace(/\s/g, ""))]; const start = performance.now(), dur = 380;
  const frame = (t) => {
    if (id !== animId) return;
    const p = Math.max(0, Math.min(1, (t - start) / dur)), cut = Math.floor(p * v.length);
    let out = v.slice(0, cut);
    for (let i = cut; i < v.length; i++) out += /\s/.test(v[i]) ? v[i] : chars[(Math.random() * chars.length) | 0];
    n.textContent = out;
    if (p < 1) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}
function showError(msg){ ++animId; el.value.className = "value err"; el.value.textContent = msg; results = []; }

function renderMeta(){
  const s = states[current.id];
  let m; try { m = current.meta(s); } catch { m = null; }
  el.meter.hidden = !m;
  if (!m) return;
  el.bars.hidden = m.level === "none";
  el.meter.dataset.level = m.level;
  const on = Math.max(1, Math.min(10, Math.round(m.bits / 12.8)));
  [...el.bars.children].forEach((b, i) => b.classList.toggle("on", i < on));
  el.meterText.innerHTML = m.html;
}

let genSeq = 0;
const ctxOf = new Map(); // per-tool context from the latest finished run (JWT secret, etc.)
async function generate(animate = true){
  const seq = ++genSeq, tool = current, s = { ...states[tool.id] };
  const stale = () => seq !== genSeq || tool !== current;
  let words;
  if (tool.async){
    if (!globalThis.RR_WORDS){ results = []; renderList(); ++animId; el.value.className = "value err"; el.value.textContent = "Loading word list…"; }
    try { words = await loadWords(); }
    catch { if (!stale()){ showError("The word list didn't load. Check that words.js sits next to index.html, then press Generate."); renderMeta(); } return; }
    if (stale()) return;
  }
  let out, ctx;
  try {
    ctx = tool.before ? await tool.before(s) : undefined;
    if (stale()) return;
    out = await Promise.all(Array.from({ length:s.count || 1 }, () => tool.gen(s, words, ctx)));
  } catch (e){
    if (stale()) return;
    if (e instanceof GenError){ showError(e.message); el.meter.hidden = true; ctxOf.delete(tool); renderList(); return; }
    throw e;
  }
  if (stale()) return;
  results = out; ctxOf.set(tool, ctx);
  showValue(results[0], animate);
  $("live").textContent = results.length > 1 ? `${results.length} new values generated.` : `New ${tool.name.toLowerCase()} generated.`;
  renderMeta();
  renderList();
}
function renderList(){
  const many = results.length > 1;
  el.copyAll.hidden = !many; el.download.hidden = !many;
  let html = many ? `<div class="list-head"><span>${results.length - 1} more</span></div><ul class="list">${
    results.slice(1).map((r, i) => `<li><code>${esc(r)}</code><button type="button" data-i="${i + 1}">Copy</button></li>`).join("")}</ul>` : "";
  if (current.extra) html += current.extra(states[current.id], ctxOf.get(current));
  el.extra.innerHTML = html;
}
el.opts.addEventListener("submit", (e) => e.preventDefault());
el.extra.addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  if (b.dataset.copy) copy(b.dataset.copy); else if (b.dataset.i) copy(results[b.dataset.i]);
});

/* ---------- actions ---------- */
let toastT;
function toast(msg){ el.toast.textContent = msg; el.toast.classList.add("show"); clearTimeout(toastT); toastT = setTimeout(() => el.toast.classList.remove("show"), 1400); }
async function copy(text, label = "Copied"){
  if (!text) return;
  let ok = true;
  try { await navigator.clipboard.writeText(text); }
  catch {
    const t = document.createElement("textarea"); t.value = text; t.style.position = "fixed"; t.style.opacity = "0";
    document.body.appendChild(t); t.select();
    try { ok = document.execCommand("copy"); } catch { ok = false; }
    t.remove();
  }
  toast(ok ? label : "Copy failed. Select the text and press Ctrl+C or Cmd+C.");
}
$("gen").addEventListener("click", () => generate(true));
$("copy").addEventListener("click", () => copy(results[0]));
el.copyAll.addEventListener("click", () => copy(results.join("\n"), `Copied ${results.length}`));
el.download.addEventListener("click", () => {
  const url = URL.createObjectURL(new Blob([results.join("\n") + "\n"], { type:"text/plain" }));
  const a = Object.assign(document.createElement("a"), { href:url, download:`${current.id}-${Date.now()}.txt` });
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
document.addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const tag = e.target.tagName;
  if (tag === "INPUT" && e.target.type === "text" || tag === "SELECT" || tag === "TEXTAREA") return;
  if (e.key === "g" || e.key === "G"){ e.preventDefault(); generate(true); }
  if (e.key === "c" || e.key === "C"){
    const sel = getSelection();
    if (!sel.toString() || el.value.contains(sel.anchorNode)){ e.preventDefault(); copy(results[0]); }
  }
});

/* ---------- theme ---------- */
const themeBtn = $("theme");
function isDark(){ const t = document.documentElement.dataset.theme; return t ? t === "dark" : matchMedia("(prefers-color-scheme: dark)").matches; }
function syncTheme(){ themeBtn.textContent = isDark() ? "Light" : "Dark"; themeBtn.setAttribute("aria-label", isDark() ? "Switch to light mode" : "Switch to dark mode"); }
try { const t = localStorage.getItem("rr:theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
themeBtn.addEventListener("click", () => {
  const next = isDark() ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("rr:theme", next); } catch {}
  syncTheme();
});
syncTheme();

/* ---------- start ---------- */
window.addEventListener("hashchange", () => select(location.hash.slice(1), false));
// Logo goes home: first generator, clean URL, no reload.
$("home").addEventListener("click", (e) => {
  if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return; // let "open in new tab" work
  e.preventDefault();
  history.replaceState(null, "", location.pathname + location.search);
  select(TOOLS[0].id, false);
  scrollTo({ top:0, behavior: reduceMotion.matches ? "auto" : "smooth" });
});
select(location.hash.slice(1) || "password", false);
// Warm the word list in idle time so the Passphrase tab opens instantly.
(globalThis.requestIdleCallback || ((f) => setTimeout(f, 1500)))(() => loadWords().catch(() => {}));

// Google Fonts stylesheet loads as media="print" so it never blocks rendering; switch it on once loaded.
const gf = $("gf");
if (gf){ if (gf.sheet) gf.media = "all"; else gf.addEventListener("load", () => { gf.media = "all"; }); }
// Browser versions for user agents; refresh the UA tab when they arrive.
{
  const vs = document.createElement("script"); vs.src = "versions.js"; vs.async = true;
  vs.onload = () => { if (current.id === "useragent"){ renderMeta(); generate(false); } };
  document.head.appendChild(vs);
}
