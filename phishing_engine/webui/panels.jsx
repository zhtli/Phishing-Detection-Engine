/* ============================================================
   panels.jsx — signals (explainability) + extracted info
   ============================================================ */
const { Icon: PIcon, pct: ppct, cls: pcls } = window.PhishingUI;

/* ---------- Explainability: signals grouped by stage ---------- */
function SignalsPanel({ result }) {
  const ranStages = result.stages.filter(s => s.ran);
  const skipped = result.stages.filter(s => s.skipped);
  const totalSignals = ranStages.reduce((a, s) => a + s.signals.length, 0);
  return (
    <div className="card">
      <div className="card-head">
        <h3>Phishing Indicators</h3>
      </div>
      <div className="card-body">
        {ranStages.map((st) => (
          <div className="sig-group" key={st.id}>
            <div className="sig-group-head">
              <span className="sig-stage-tag">S{st.id}</span>
              <span className="gname">{st.name}</span>
              <span className="gcount">{st.signals.length}</span>
            </div>
            {st.signals.map((sig, i) => (
              <div className="signal" key={i}>
                <span className={pcls("wdot", sig.weight)} />
                <div className="sbody">
                  <div className="sline">
                    <span className="slabel">{sig.label}</span>
                    <span className="svalue mono">{sig.value}</span>
                  </div>
                  {sig.detail && <p className="sdetail">{sig.detail}</p>}
                </div>
              </div>
            ))}
          </div>
        ))}
        {skipped.length > 0 && (
          <div className="skip-row">
            <PIcon name="skip" width="13" height="13" />
            <span>{skipped.map(s => "Stage " + s.id).join(" & ")} skipped — no features extracted (verdict reached upstream).</span>
          </div>
        )}
        <div style={{display:"flex",gap:16,flexWrap:"wrap",padding:"13px 0 4px",fontSize:11.5,color:"var(--ink-4)"}}>
          <Legend c="high" t="Strong phishing pull" />
          <Legend c="med" t="Moderate" />
          <Legend c="low" t="Minor" />
          <Legend c="safe" t="Lowers risk" />
        </div>
      </div>
    </div>
  );
}
function Legend({ c, t }) {
  return <span style={{display:"inline-flex",alignItems:"center",gap:6}}><span className={"wdot "+c} style={{marginTop:0}} />{t}</span>;
}

/* ---------- Collapsible raw-data block (revealed on demand) ---------- */
function RawBlock({ label, children }) {
  const [open, setOpen] = React.useState(false);
  return (
    <div className="raw-block">
      <button type="button" className="raw-toggle" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        <span className="raw-caret">{open ? "▾" : "▸"}</span>{label}
      </button>
      {open && <div className="raw-body">{children}</div>}
    </div>
  );
}
function fmtBytes(n) { return !n ? "0 B" : n < 1024 ? n + " B" : (n / 1024).toFixed(1) + " KB"; }
function fmtDate(iso) { return iso ? String(iso).slice(0, 10) : null; }

/* label/value rows for the parsed raw views */
function RawKV({ rows }) {
  return (
    <dl className="kv">
      {rows.filter(([, v]) => v != null && v !== "").map(([k, v], i) => (
        <React.Fragment key={i}>
          <dt>{k}</dt><dd className="mono" style={{ wordBreak: "break-all" }}>{v}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

/* ---------- URL stage: parsed structure ---------- */
function UrlRaw({ parsed }) {
  const words = Array.isArray(parsed.words_raw) ? parsed.words_raw.filter(Boolean) : [];
  return (
    <>
      <RawKV rows={[
        ["Protocol", parsed.protocol],
        ["Registered domain", parsed.registered_domain || parsed.domain],
        ["Subdomain", parsed.subdomain || "—"],
        ["TLD", parsed.tld],
        ["Path", parsed.path || "/"],
      ]} />
      {words.length > 0 && (
        <>
          <div className="raw-sub">Tokens</div>
          <div className="chips-row">{words.map((w, i) => <span className="rawchip" key={i}>{w}</span>)}</div>
        </>
      )}
    </>
  );
}

/* ---------- Domain stage: parsed DNS / RDAP / hosting record ---------- */
function dnssecLabel(dnssec, hasDnskey) {
  if (dnssec && typeof dnssec === "object") return dnssec.delegationSigned ? "signed" : "unsigned";
  if (typeof hasDnskey === "boolean") return hasDnskey ? "DNSKEY present" : "no DNSKEY";
  return null;
}
function DomainRaw({ rec }) {
  const dns = rec.dns || {};
  const rdap = rec.rdap || {};
  const rem = dns.remarks || {};
  const ents = rdap.entities || {};
  const ips = rec.ip_data || [];
  const entStr = (arr) => (arr && arr.length)
    ? arr.map(e => e.email ? `${e.name} <${e.email}>` : e.name).filter(Boolean).join(", ") : null;

  const dnsRows = [
    ["A", (dns.A || []).join(", ")],
    ["AAAA", (dns.AAAA || []).join(", ")],
    ["CNAME", dns.CNAME && dns.CNAME.value],
    ["MX", dns.MX ? Object.entries(dns.MX).map(([h, info]) => `${h} (pri ${info.priority})`).join(", ") : null],
    ["NS", dns.NS ? Object.keys(dns.NS).join(", ") : null],
    ["TXT", (dns.TXT || []).join("   |   ")],
    ["SOA", (dns.SOA && dns.SOA.primary_ns) || (dns.zone_SOA && dns.zone_SOA.primary_ns)],
  ].filter(([, v]) => v != null && v !== "");
  const mail = [["SPF", rem.has_spf], ["DKIM", rem.has_dkim], ["DMARC", rem.has_dmarc]].filter(([, v]) => v).map(([k]) => k);

  return (
    <>
      <div className="raw-sub">DNS records</div>
      {dnsRows.length
        ? <div>{dnsRows.map(([t, v], i) => <div className="dns-row" key={i}><span className="t">{t}</span><span className="v">{v}</span></div>)}</div>
        : <div className="raw-empty">no records resolved</div>}
      {mail.length > 0 && <div className="raw-flags">Mail auth: {mail.join(" · ")}</div>}

      <div className="raw-sub">Registration (RDAP / WHOIS)</div>
      <RawKV rows={[
        ["Registered", fmtDate(rdap.registration_date)],
        ["Expires", fmtDate(rdap.expiration_date)],
        ["Last changed", fmtDate(rdap.last_changed_date)],
        ["Registrar", entStr(ents.registrar)],
        ["Registrant", entStr(ents.registrant)],
        ["Admin", entStr(ents.administrative)],
        ["DNSSEC", dnssecLabel(rdap.dnssec, rem.has_dnskey)],
      ]} />

      <div className="raw-sub">Hosting IPs ({ips.length})</div>
      <div className="ip-list">
        {ips.map((e, i) => {
          const g = e.geo || {}, a = e.asn || {};
          const loc = [g.city, g.region, g.country].filter(Boolean).join(", ");
          const asn = a.as_org ? (a.as_org + (a.asn ? " · AS" + a.asn : "")) : null;
          return (
            <div className="ip-row" key={i}>
              <span className="ip">{e.ip}</span>
              <span className="ip-meta">{[asn, loc].filter(Boolean).join(" — ") || "—"}</span>
            </div>
          );
        })}
      </div>
    </>
  );
}

/* ---------- Extracted evidence — only real, engine-collected facts ---------- */
function ExtractedPanel({ result }) {
  const ex = result.extracted;
  const raw = result.raw || {};
  const tls = ex.tls || {};
  const secure = result.protocol === "https";
  const contentRan = result.stages[1].ran;  // Stage 2 · HTML + TLS collected here
  const domainRan = result.stages[2].ran;   // Stage 3 · DNS / WHOIS collected here
  const breakAll = { wordBreak: "break-all" };

  return (
    <div className="card">
      <div className="card-head">
        <h3>Extracted evidence</h3>
        <span className="meta mono">HTTP {ex.statusCode}</span>
      </div>
      <div className="card-body">
        {/* Connection — URL parsed in Stage 1, always available */}
        <dl className="kv">
          <dt>URL</dt><dd className="mono" style={breakAll}>{result.url}</dd>
          <dt>Connection</dt>
          <dd className={secure ? "ok" : "flag"}>
            <PIcon name={secure ? "lock" : "alert"} width="12" height="12"
                   style={{verticalAlign: "-1px", marginRight: 6}} />
            {secure ? "HTTPS" : "HTTP — not encrypted"}
          </dd>
        </dl>

        {contentRan ? (
          <>
            <div className="subhead">Page</div>
            <dl className="kv">
              <dt>Title</dt><dd>{ex.pageTitle || "—"}</dd>
              <dt>Final URL</dt><dd className="mono" style={breakAll}>{ex.finalUrl}</dd>
              <dt>Redirects</dt>
              <dd className={ex.redirects > 0 ? "flag" : "ok"}>{ex.redirects === 0 ? "none" : ex.redirects + " hop" + (ex.redirects>1?"s":"")}</dd>
              <dt>Credential form</dt>
              <dd className={ex.hasPwForm ? "flag" : "ok"}>{ex.hasPwForm ? "password field present" : "none"}</dd>
            </dl>

            <div className="subhead">TLS certificate</div>
            {tls.present ? (
              <dl className="kv">
                <dt>Issuer</dt><dd>{tls.issuer || "—"}</dd>
                <dt>Subject</dt><dd className="mono" style={breakAll}>{tls.subject || "—"}</dd>
                <dt>Valid</dt>
                <dd className={tls.expired ? "flag" : ""}>{(tls.validFrom || "?") + " → " + (tls.validTo || "?")}</dd>
                <dt>Protocol</dt><dd className="mono">{[tls.protocol, tls.cipher].filter(Boolean).join(" · ") || "—"}</dd>
                {tls.selfSigned && (<><dt>Trust</dt><dd className="flag">self-signed</dd></>)}
              </dl>
            ) : (
              <div className="skip-row">
                <PIcon name="alert" width="13" height="13" />
                <span>No TLS — served over plain HTTP.</span>
              </div>
            )}
          </>
        ) : (
          <div className="skip-row" style={{marginTop: 14}}>
            <PIcon name="skip" width="13" height="13" />
            <span>Stage 2 skipped — page content was never fetched (verdict reached upstream).</span>
          </div>
        )}

        {domainRan ? (
          <>
            <div className="subhead">WHOIS</div>
            <dl className="kv">
              <dt>Registered</dt>
              <dd className={ex.whois.ageDays < 60 ? "flag" : ""}>{ex.whois.created} · {ex.whois.ageLabel} ago</dd>
              <dt>Registrar</dt><dd>{ex.whois.registrar}</dd>
              <dt>Country</dt><dd>{ex.whois.country}</dd>
              <dt>Privacy</dt><dd>{ex.whois.privacy ? "masked" : "public"}</dd>
              <dt>Expires</dt><dd>{ex.whois.expires}</dd>
            </dl>

            <div className="subhead">DNS records</div>
            <div>
              {ex.dns.map((r, i) => (
                <div className="dns-row" key={i}><span className="t">{r.type}</span><span className="v">{r.value}</span></div>
              ))}
            </div>
          </>
        ) : (
          <div className="skip-row" style={{marginTop:14}}>
            <PIcon name="skip" width="13" height="13" />
            <span>Stage 3 skipped — no DNS / WHOIS lookup was performed.</span>
          </div>
        )}

        {/* Raw collected data — what each stage gathered, parsed; revealed on demand */}
        {(raw.url || raw.content || raw.domain) && (
          <>
            <div className="subhead">Raw collected data</div>

            {raw.url && raw.url.parsed && (
              <RawBlock label="URL data">
                <UrlRaw parsed={raw.url.parsed} />
              </RawBlock>
            )}

            {raw.content && (
              <RawBlock label={`Raw HTML (${fmtBytes(raw.content.htmlBytes)})`}>
                {raw.content.html
                  ? <pre className="raw-pre raw-html">{raw.content.html}</pre>
                  : <div className="skip-row"><PIcon name="alert" width="13" height="13" /><span>No HTML was captured.</span></div>}
              </RawBlock>
            )}

            {raw.domain && (
              <RawBlock label="Domain record">
                <DomainRaw rec={raw.domain} />
              </RawBlock>
            )}
          </>
        )}
      </div>
    </div>
  );
}

window.PhishingUI = Object.assign(window.PhishingUI, { SignalsPanel, ExtractedPanel });
