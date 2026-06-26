# `webui/` — browser demo UI

A single-page browser UI for the prediction engine. It is **served by the API** ([`../api.py`](../api.py))
at `/` from the same origin, so the whole demo runs from one process with no separate build
step and no CORS setup:

```bash
uvicorn phishing_engine.api:app --host 0.0.0.0 --port 8000 --workers 1
# then open http://localhost:8000/
```

Paste a URL → the UI calls `POST /predict` and visualizes the run: the 3-stage cascade with
each stage's phishing probability, deferral band `[0.5−δ, 0.5+δ]` and latency; the decision
(band early-exit vs. `mean`/`max`/`median` aggregation); the driving signals; and the raw
evidence each stage collected (parsed URL, WHOIS/DNS/hosting record, TLS certificate, and the
page HTML/DOM on demand). The decision policy (margins, labels, aggregation) is read from the
live response, so the UI reflects whatever `config/pipeline.json` specifies.

## How it's wired

`engine.js` is the **only** file that talks to the backend. Its `analyze(url)` does a single
`fetch('/predict')` and maps the JSON onto the shape the React components render; there is no
fabricated/heuristic fallback (if the engine is unreachable it surfaces an error). The API's
response shape is produced by [`core/serialization.py`](../core/serialization.py)
`result_to_api_dict`, with the human-readable signals + evidence built in
[`core/explain.py`](../core/explain.py).

## Files

| File | Role |
|------|------|
| `index.html` | Entry point. Loads React 18 + Babel standalone from a CDN and the scripts below. |
| `engine.js` | The live API client — `window.PhishingEngine.analyze()` → `POST /predict`. The only backend touchpoint. |
| `app.jsx` | Top-level app: input → analyzing → result; reads the decision policy from the response. |
| `components.jsx` | Shared presentational components (verdict banner, pipeline, stage cards, icons). |
| `panels.jsx` | The "Phishing Indicators" (signals) and "Extracted evidence" panels, incl. the on-demand raw-data viewers. |
| `tweaks-panel.jsx` | Reusable floating "Tweaks" panel (accent, reveal speed, examples toggle). |
| `styles.css` | All styling (CSS variables for theming). |

## Notes

- This is a **prototype**, not a production frontend: JSX is transpiled **in the browser** by
  Babel standalone, and React is loaded from a CDN — so the page needs internet access for
  those CDN assets, and there is no bundler/minification. To productionize, recreate the same
  views in a real build (React/Vite, etc.) hitting the same `/predict` contract.
- Live `/predict` does real network collection (DNS/RDAP/WHOIS + page fetch + TLS), so a
  request takes a few seconds — the domain stage dominates.
- Override the served location with `PHISHING_ENGINE_WEBUI_DIR` if you relocate these files.
