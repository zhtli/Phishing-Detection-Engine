/* ============================================================
   app.jsx — main application: input → analyzing → result
   Talks to the live engine via window.PhishingEngine.analyze().
   ============================================================ */
const { Icon: AIcon, VerdictBanner, Pipeline, SignalsPanel, ExtractedPanel, pct: apct, cls: acls } = window.PhishingUI;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "#4f46e5",
  "speed": 1,
  "showExamples": true
}/*EDITMODE-END*/;

const ACCENTS = ["#4f46e5", "#0d9488", "#2563eb", "#7c3aed", "#db2777"];

function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [url, setUrl] = useState("");
  const [phase, setPhase] = useState("idle"); // idle | analyzing | done | error
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [online, setOnline] = useState(null); // null = unknown, true/false from /health
  const [runState, setRunState] = useState(["pending", "pending", "pending"]);
  const [liveStages, setLiveStages] = useState(null);
  const reqId = useRef(0);

  // apply accent tweak
  useEffect(() => { document.documentElement.style.setProperty("--accent", t.accent); }, [t.accent]);

  // probe the engine for the "engine online" indicator
  useEffect(() => { window.PhishingEngine.health().then(setOnline); }, []);

  const meta = window.PhishingEngine.STAGE_META;
  const examples = window.PhishingEngine.EXAMPLES;

  async function run(targetUrl) {
    const u = (targetUrl ?? url).trim();
    if (!u) return;
    if (targetUrl) setUrl(targetUrl);
    const id = ++reqId.current;

    setPhase("analyzing");
    setResult(null);
    setError(null);
    setRunState(["running", "pending", "pending"]);
    // seed live stage shells from meta
    setLiveStages(meta.map(m => ({ ...m, score: 0, signals: [], latencyMs: 0, verdict: "legitimate", ran: false, skipped: false, decided: false, escalated: false, exited: false })));

    let res;
    try {
      res = await window.PhishingEngine.analyze(u, {
        speed: t.speed,
        onStage: (stage, i, full) => {
          if (id !== reqId.current) return;
          setLiveStages(prev => { const next = prev.slice(); next[i] = stage; return next; });
          setRunState(prev => {
            const next = prev.slice();
            next[i] = "done";
            // early-exit: this stage decided → remaining stages are skipped, not run
            if (full.decisionMode === "early-exit" && stage.decided) {
              for (let k = i + 1; k < 3; k++) next[k] = "skipped";
            } else if (i + 1 < 3) {
              next[i + 1] = "running";
            }
            return next;
          });
        },
      });
    } catch (err) {
      if (id !== reqId.current) return;
      setError(err && err.message ? err.message : String(err));
      setOnline(false);
      setPhase("error");
      return;
    }

    if (id !== reqId.current) return;
    setOnline(true);
    setResult(res);
    setLiveStages(res.stages);
    setRunState(res.stages.map(s => s.skipped ? "skipped" : "done"));
    setPhase("done");
  }

  const stagesToShow = result ? result.stages : liveStages;
  const showPipeline = (phase === "analyzing" || phase === "done") && stagesToShow;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><AIcon name="shield" /></div>
          <div className="brand-name">Phishing Detection<span className="dim"> Engine</span></div>
        </div>
        <div className="topbar-right">
          <span>3-stage cascade</span>
          <span className={acls("status-dot", online === false && "off")}>
            {online === false ? "engine offline" : "engine online"}
          </span>
        </div>
      </header>

      {/* ---------- input ---------- */}
      <section className="hero">
        {phase === "idle" && (
          <>
            <h1>Is this URL phishing?</h1>
            <p>Paste a link. The cascade scores it stage by stage and stops the moment one stage is confident it's phishing — otherwise all three run and the scores are aggregated.</p>
          </>
        )}
        <form className="searchbar" onSubmit={(e) => { e.preventDefault(); run(); }} style={phase!=="idle"?{marginTop:8}:undefined}>
          <span className="lock"><AIcon name="search" width="18" height="18" /></span>
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/login"
            spellCheck={false} autoComplete="off" autoFocus
          />
          <button className="btn-analyze" type="submit" disabled={phase === "analyzing" || !url.trim()}>
            {phase === "analyzing" ? <><span className="spin" /> Analyzing</> : <><AIcon name="bolt" width="15" height="15" /> Analyze</>}
          </button>
        </form>

        {t.showExamples && phase === "idle" && (
          <div className="examples">
            {examples.map((ex) => {
              const https = /^https:/i.test(ex.url);
              return (
                <button key={ex.url} className="chip" onClick={() => run(ex.url)} title={ex.url}>
                  <span className={"tag " + (https ? "l" : "p")}>{https ? "HTTPS" : "HTTP"}</span>
                  {ex.label}
                </button>
              );
            })}
          </div>
        )}
      </section>

      {/* ---------- idle: explain the cascade ---------- */}
      {phase === "idle" && (
        <div className="idle-stages">
          {meta.map((m) => (
            <div className="idle-stage" key={m.id}>
              <div className="stage-num">{m.id}</div>
              <h4>{m.name}</h4>
              <p>{m.info}</p>
            </div>
          ))}
        </div>
      )}

      {/* ---------- error ---------- */}
      {phase === "error" && (
        <div className="engine-error">
          <AIcon name="alert" width="20" height="20" />
          <div>
            <strong>Engine unavailable</strong>
            <p>{error} Start the API with <code className="mono">uvicorn phishing_engine.api:app --port 8000</code> and try again.</p>
          </div>
        </div>
      )}

      {/* ---------- verdict ---------- */}
      {phase === "done" && result && <VerdictBanner result={result} />}

      {/* ---------- pipeline ---------- */}
      {showPipeline && (
        <>
          <div className="section-head">
            <h3>Detection cascade</h3>
            <span className="hint">
              {phase === "analyzing" ? "Running stages in sequence…"
                : result.decisionMode === "early-exit"
                  ? `Stopped at the first stage confident outside its deferral band`
                  : `No stage left its band — all ran, verdict from ${result.aggregation} aggregation`}
            </span>
          </div>
          <Pipeline
            stages={stagesToShow}
            runState={runState}
            decisionMode={result ? result.decisionMode : null}
            margin={result ? result.margin : 0.4}
          />
        </>
      )}

      {/* ---------- details ---------- */}
      {/* Phishing Indicators (SignalsPanel) hidden for now */}
      {phase === "done" && result && (
        <div className="detail-grid">
          <ExtractedPanel result={result} />
        </div>
      )}

      {/* ---------- Tweaks ---------- */}
      <TweaksPanel>
        <TweakSection label="Appearance" />
        <TweakColor label="Accent" value={t.accent} options={ACCENTS} onChange={(v) => setTweak("accent", v)} />
        <TweakSection label="Demo controls" />
        <TweakSlider label="Reveal speed" value={t.speed} min={0.4} max={3} step={0.1} unit="×"
          onChange={(v) => setTweak("speed", v)} />
        <TweakToggle label="Show example URLs" value={t.showExamples} onChange={(v) => setTweak("showExamples", v)} />
      </TweaksPanel>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
