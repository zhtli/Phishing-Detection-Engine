/* ============================================================
   components.jsx — shared presentational components
   Exposed on window for app.jsx to consume.
   ============================================================ */
const { useState, useEffect, useRef } = React;

const pct = (v) => Math.round(v * 100);
const cls = (...a) => a.filter(Boolean).join(" ");

/* ---------- small icons ---------- */
function Icon({ name, ...rest }) {
  const paths = {
    shield: <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" />,
    alert: <><path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z"/><line x1="12" y1="8" x2="12" y2="13"/><circle cx="12" cy="16.5" r=".6" fill="currentColor" stroke="none"/></>,
    check: <polyline points="20 6 9 17 4 12" />,
    x: <><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></>,
    lock: <><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></>,
    arrow: <><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></>,
    bolt: <polygon points="13 2 4 14 11 14 10 22 20 10 13 10 13 2" />,
    search: <><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.5" y2="16.5"/></>,
    skip: <><polyline points="5 4 13 12 5 20"/><line x1="17" y1="4" x2="17" y2="20"/></>,
  };
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" {...rest}>
      {paths[name]}
    </svg>
  );
}

/* ============================================================
   VERDICT BANNER
   ============================================================ */
function VerdictBanner({ result }) {
  const phishing = result.verdict === "phishing";
  const agg = result.decisionMode === "aggregation";
  const decider = result.decidingStage ? result.stages[result.decidingStage - 1] : null;
  return (
    <div className={cls("verdict", result.verdict)}>
      <div className="verdict-badge">
        <Icon name={phishing ? "alert" : "check"} />
      </div>
      <div className="verdict-main">
        <div className="vlabel">
          <h2>{phishing ? "Phishing" : "Legitimate"}</h2>
          <span className="verdict-tag mono">{phishing ? result.positiveLabel : result.negativeLabel}</span>
        </div>
        <p className="sub">
          {agg ? (
            <>No stage crossed the <b>{pct(result.threshold)}%</b> threshold — verdict from the{" "}
            <b>{result.aggregation}</b>-aggregated score (<b>{pct(result.aggregateScore)}% phishing</b>) across all 3 stages.</>
          ) : (
            <>Decided at <b>Stage {result.decidingStage} · {decider.short}</b> — its phishing probability{" "}
            <b>{pct(decider.score)}%</b> cleared the <b>{pct(result.threshold)}%</b> threshold
            {result.decidingStage < 3 ? `, so the remaining ${3 - result.decidingStage} stage${3 - result.decidingStage > 1 ? "s were" : " was"} skipped` : ""}.</>
          )}
        </p>
      </div>
      <div className="verdict-stats">
        <div className="vstat">
          <div className="k">{agg ? "Aggregate" : "Probability"}</div>
          <div className="v tnum">{pct(agg ? result.aggregateScore : decider.score)}%</div>
        </div>
        <div className="vstat">
          <div className="k">Total time</div>
          <div className="v tnum">{result.totalLatencyMs}<span style={{fontSize:13,color:"var(--ink-4)",fontWeight:600}}>ms</span></div>
        </div>
        <div className="vstat">
          <div className="k">Stages run</div>
          <div className="v tnum">{result.stages.filter(s=>s.ran).length}<span style={{fontSize:13,color:"var(--ink-4)",fontWeight:600}}>/3</span></div>
        </div>
      </div>
    </div>
  );
}

/* ============================================================
   PIPELINE  (stage cards + connectors)
   ============================================================ */
function Pipeline({ stages, runState, decisionMode, threshold }) {
  return (
    <div className="pipeline">
      {stages.map((st, i) => (
        <React.Fragment key={st.id}>
          <StageCard stage={st} state={runState[i]} decisionMode={decisionMode} threshold={threshold} />
          {i < 2 && (
            <div className="pipe-arrow" style={{ left: `calc(${(i+1)*100/3}% - 7px)` }}>
              <Icon name="arrow" width="16" height="16" />
            </div>
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

function StageCard({ stage, state, decisionMode, threshold }) {
  const done = state === "done";
  const skipped = state === "skipped";
  const isDecider = done && stage.decided;
  const escalated = done && stage.escalated;
  const aggMode = done && decisionMode === "aggregation";
  const v = stage.verdict; // phishing | legitimate
  const crossed = stage.crossedThreshold;
  // Each stage can carry its own early-exit threshold; fall back to the pipeline default.
  const th = stage.threshold != null ? stage.threshold : threshold;
  // A stage with no loaded model (or one that errored) extracts/collects but produces no
  // probability — the cascade escalates past it. score comes back null in that case.
  const noScore = stage.score == null;

  return (
    <div className={cls("stage", state, isDecider && "deciding", isDecider && "v-" + v, skipped && "skipped")}>
      {isDecider && (
        <span className={cls("decide-badge", "v-" + v)}>
          <Icon name={v === "phishing" ? "alert" : "check"} width="11" height="11" /> Verdict reached here
        </span>
      )}
      {escalated && !aggMode && <span className="transparency-tag">↑ escalated</span>}
      {aggMode && <span className="transparency-tag">aggregated</span>}
      {skipped && <span className="transparency-tag">skipped</span>}

      <div className="stage-top">
        <div className="stage-num">{stage.id}</div>
        {state === "running" && <div className="btn-analyze spin" style={{borderColor:"var(--accent-ring)",borderTopColor:"var(--accent)"}} />}
      </div>
      <h4>{stage.name}</h4>
      <p className="stage-info">{stage.info}</p>

      <div className="stage-score">
        {skipped ? (
          <div className="skip-note">
            <Icon name="skip" width="14" height="14" />
            <span>Not evaluated — verdict already reached upstream.</span>
          </div>
        ) : done && noScore ? (
          <>
            <div className="score-row">
              <span className="label">No model score</span>
            </div>
            <div className="bar">
              <span className="bar-threshold" style={{ left: pct(th) + "%" }} title={`threshold ${pct(th)}%`} />
              <i style={{ width: "0%", background: "var(--accent-ring)" }} />
            </div>
            <div className="bar-foot">
              <span className="conf-flag unmet">
                <Icon name="arrow" width="11" height="11" /> {stage.error ? "errored · escalate" : "no model · escalate"}
              </span>
              <span>{stage.latencyMs != null ? stage.latencyMs + " ms" : "—"}</span>
            </div>
          </>
        ) : done ? (
          <>
            <div className="score-row">
              <span className="label">Phishing prob.</span>
              <span className={cls("score-val", "v-" + v)}>{pct(stage.score)}<span className="unit">%</span></span>
            </div>
            <div className="bar">
              <span className="bar-threshold" style={{ left: pct(th) + "%" }} title={`threshold ${pct(th)}%`} />
              <i className={"v-" + v} style={{ width: pct(stage.score) + "%" }} />
            </div>
            <div className="bar-foot">
              <span className={cls("conf-flag", crossed ? "met" : "unmet")}>
                {crossed
                  ? <><Icon name="check" width="11" height="11" /> ≥ {pct(th)}% · decides</>
                  : <><Icon name="arrow" width="11" height="11" /> &lt; {pct(th)}% · {aggMode ? "aggregated" : "escalate"}</>}
              </span>
              <span>{stage.latencyMs} ms</span>
            </div>
          </>
        ) : (
          <>
            <div className="score-row">
              <span className="label">{state === "running" ? "Evaluating…" : "Queued"}</span>
            </div>
            <div className="bar">
              <span className="bar-threshold" style={{ left: pct(th) + "%" }} />
              <i style={{ width: state === "running" ? "40%" : "0%", background: "var(--accent-ring)", transition:"width 1s ease" }} />
            </div>
            <div className="bar-foot"><span>threshold {pct(th)}%</span><span>{state==="running"?"…":"—"}</span></div>
          </>
        )}
      </div>
    </div>
  );
}

window.PhishingUI = Object.assign(window.PhishingUI || {}, {
  Icon, VerdictBanner, Pipeline, pct, cls,
});
