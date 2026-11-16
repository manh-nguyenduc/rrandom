# rrandom

Static page that generates passwords, passphrases, API keys (8 styles), JWT secrets and signed test tokens, UUIDs (v4/v7), ULIDs, NanoIDs, user agents, and random picks from a list. Everything uses `crypto.getRandomValues` in the browser. No build step, no dependencies.

```
index.html              the whole app (inline CSS + JS)
words.js                EFF large wordlist, lazy-loaded for passphrases
versions.js             latest Chrome/Firefox/Edge/Safari versions for user agents
scripts/update-ua.mjs   refreshes versions.js
```

Run locally: open `index.html`, or `python3 -m http.server` and visit http://localhost:8000.
JWT signing needs a secure context (https or localhost).

Update user agent versions: `node scripts/update-ua.mjs` (Node 18+). Run it on a schedule (cron / CI) to keep UAs current. If versions.js gets stale, the page adds one major version per 4 weeks since its date, so UAs stay close to current even without updates.

## License

MIT, see [LICENSE](LICENSE). The passphrase wordlist in `words.js` is the [EFF Large Wordlist](https://www.eff.org/dice), licensed CC BY 3.0 US.
