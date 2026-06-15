/* ============================================================
   engine.js  —  PHISHING DETECTION ENGINE  (LIVE API CLIENT)
   ------------------------------------------------------------
   Thin client for the real engine. The UI calls
       window.PhishingEngine.analyze(url, { onStage, speed })
   which POSTs to the FastAPI service (phishing_engine/api.py) and
   returns the cascade result it produces — verdict, per-stage
   probabilities, real signals, and the live-collected evidence
   (WHOIS / DNS / page facts). There is NO fabricated/heuristic
   fallback: if the engine is unreachable, analyze() throws and the
   UI shows an error instead of inventing a result.

   The `onStage(stage, i, result)` callback replays the stages the
   cascade actually ran, in order, purely to animate the staged
   reveal — the data is the real response, delivered in one call.
   ============================================================ */

(function () {
  const PREDICT_URL = "/predict";
  const HEALTH_URL = "/health";

  /* Static, factual stage labels for the idle screen + the "analyzing" shells.
     (Probabilities, thresholds, latencies, signals all come from the live API.) */
  const STAGE_META = [
    {
      id: 1, key: "url", name: "URL Lexical Classifier", short: "URL",
      info: "URL string & lexical tokens only", network: false,
    },
    {
      id: 2, key: "content", name: "Page Content Classifier", short: "Content",
      info: "Static HTML + TLS certificate features", network: true,
    },
    {
      id: 3, key: "domain", name: "Domain Classifier", short: "Domain",
      info: "DNS / IP / RDAP / WHOIS record", network: true,
    },
  ];

  /* One-click examples — real, resolvable URLs so the live engine returns
     meaningful results (the verdict is whatever the engine decides). */
  const EXAMPLES = [
    { label: "GitHub login", url: "https://github.com/login" },
    { label: "Wikipedia", url: "https://www.wikipedia.org" },
    { label: "IANA example", url: "https://example.com" },
    { label: "Plain HTTP site", url: "http://neverssl.com" },
  ];

  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  /* Raised by analyze() for any failure (network, HTTP error, or no verdict).
     The UI catches it and renders a clean error state. */
  class EngineError extends Error {}

  async function health() {
    try {
      const res = await fetch(HEALTH_URL, { method: "GET" });
      if (!res.ok) return false;
      const body = await res.json();
      return body && body.status === "ok";
    } catch (e) {
      return false;
    }
  }

  /* ============================================================
     PUBLIC API
     ============================================================ */
  const PhishingEngine = {
    STAGE_META,
    EXAMPLES,

    health,

    /**
     * analyze(url, opts)
     *   opts.onStage(stage, index, result) — called as each RAN stage is revealed
     *   opts.speed                         — reveal-animation speed multiplier (1 = normal)
     * returns Promise<result>  (the live API's UI-shaped payload)
     * throws  EngineError      (network down / HTTP error / no verdict)
     */
    async analyze(url, opts = {}) {
      const { onStage, speed = 1 } = opts;

      let res;
      try {
        res = await fetch(PREDICT_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        });
      } catch (e) {
        throw new EngineError("Could not reach the engine. Is the API running?");
      }

      if (!res.ok) {
        let detail = "";
        try { detail = (await res.json()).detail || ""; } catch (_) { /* ignore */ }
        throw new EngineError(
          `Engine error (HTTP ${res.status})${detail ? " — " + detail : ""}`
        );
      }

      const result = await res.json();
      if (!result || !Array.isArray(result.stages)) {
        throw new EngineError("Malformed response from the engine.");
      }
      if (result.verdict === "unknown") {
        throw new EngineError("No stage could score this URL — no verdict available.");
      }

      // Replay the stages the cascade actually ran, in order, to animate the reveal.
      // Skipped stages (after an early-exit) never ran, so we stop at the first non-run one.
      for (let i = 0; i < result.stages.length; i++) {
        const st = result.stages[i];
        if (!st.ran) break;
        const wait = Math.max(120, Math.min(700, st.latencyMs || 200)) / Math.max(0.2, speed);
        await sleep(wait);
        if (onStage) onStage(st, i, result);
      }
      await sleep(140 / Math.max(0.2, speed));
      return result;
    },
  };

  PhishingEngine.EngineError = EngineError;
  window.PhishingEngine = PhishingEngine;
})();
