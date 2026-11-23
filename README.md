# Cyber Briefing – automated threat intel

A GitHub Action collects threat intel **twice a day (08:07 and 20:07 Singapore time)** and publishes it, with the page, to GitHub Pages.
The page reads one file, `data/intel.json`, so there are no browser CORS or proxy problems.

```
.github/workflows/fetch-intel.yml   schedule + build + deploy
scripts/fetch-intel.mjs             the collector (Node 20+, no dependencies)
config/feeds.json                   RSS sources – edit this to add/remove feeds
index.html                          the briefing page
```

## One-time setup (about 5 minutes)

1. Create a GitHub repo and push these files to `main`.
2. **Settings → Pages → Build and deployment → Source = "GitHub Actions".**
3. *(Optional but recommended)* **Settings → Secrets and variables → Actions → New repository secret**
   `NVD_API_KEY` = a free key from https://nvd.nist.gov/developers/request-an-api-key (makes the NVD step much faster).
4. **Actions → "Fetch threat intel & publish" → Run workflow.**
   (If the push already triggered a run before step 2, just re-run it.)
5. Open `https://<your-user-or-org>.github.io/<repo>/`.

## What each run does

- Fetches CISA KEV, NVD (last 14 days of HIGH + CRITICAL), GitHub Advisories, EPSS scores, Cloudflare Zero Wire and every RSS feed in `config/feeds.json`.
- If one source fails, the **previous data for that source is kept and marked "stale"** (orange chip on the page).
- If KEV, NVD **and** GitHub all fail, the run fails and nothing is published, so the last good page stays up.
- Marks what is new since the last run (🆕 on the page).
- Writes a per-source status table to the run's **Summary** tab – start there when something looks wrong.

## Common changes

| I want to… | Do this |
|---|---|
| Add or remove an RSS feed | Edit `config/feeds.json` (set `"on": false` to disable). A push triggers a run. |
| Change the schedule | Edit the `cron` line in the workflow. GitHub cron is **UTC** (SGT = UTC+8). |
| Keep more / fewer NVD days | `NVD_DAYS` in the workflow (default 14; the JSON file grows with it). |
| Run it right now | Actions → Run workflow. |
| Test locally | `OUT_FILE=site/data/intel.json node scripts/fetch-intel.mjs` then `cp index.html site/ && python3 -m http.server -d site 8000` |

## Notes

- **Your asset list never leaves the browser** and is never written to the repo. Matching happens in the page.
- The page is **public** on GitHub Free. It only contains public threat intel, but anyone with the URL can open it.
  A private Pages site needs GitHub Enterprise Cloud. If you host `index.html` elsewhere, put the Pages JSON URL in the page's ⚙ → "数据文件地址", or import the `intel-json` artifact (kept 14 days) from a run.
- Opening `index.html` straight from disk (`file://`) can't read `data/intel.json`. The page falls back to browser-only mode (KEV / NVD / GitHub, no RSS).
- GitHub may pause scheduled runs in a public repo after 60 days without activity. The workflow re-enables itself on each run, and the page shows an amber warning if data is older than 26 hours.
- Scheduled runs can start a few minutes late when GitHub is busy.
