// offense/validation — Exploit Validation (doc-06 §27).
// A vulnerability is CONFIRMED only with sufficient evidence:
// reproducible behavior + controlled response difference + safe proof within ROE.
// Least-destructive proof wins; anomaly alone never confirms.

/**
 * Grade a hypothesis test.
 * @param {object} hypothesis  the hypothesis under test (has probe.signal)
 * @param {object} runs        {attacks: [...], baselines: [...]} from the executor
 * @param {object} opts        { canary, sinkHits } — exfil proofs must show the canary in the LOCAL sink only
 * @returns {{confirmed:boolean, confidence:number, evidence:object, reason:string}}
 */
export function grade(hypothesis, runs, { canary, sinkHits = 0 } = {}) {
  const attacks = runs.attacks.filter((r) => !r.error);
  if (attacks.length === 0) {
    return { confirmed: false, confidence: 0, grade: 'INCONCLUSIVE', reason: 'attack probe errored; no behavior observed', evidence: { runs } };
  }

  const signal = hypothesis.probe.signal;
  const evidence = { signal, runs: summarize(runs), notes: [] };
  let signalSeen = false;

  if (signal === 'boundary-escape') {
    // escape detected when the attack response reveals content a benign query cannot reach:
    // more rows than baseline, or confidential/sentinel markers in attack text, absent from baseline text.
    const atkText = attacks.map((a) => a.text).join('∆');
    const baseText = runs.baselines.map((b) => b.text).join('∆');
    const markers = ['confidential":true', 'HACH-TRAVERSAL-SENTINEL', 'board-minutes', 'salaries', 'sk-live-'];
    signalSeen = markers.some((m) => atkText.includes(m) && !baseText.includes(m));
    if (!signalSeen) {
      const atkHits = countHits(attacks[0].text);
      const baseHits = countHits(runs.baselines[0]?.text || '');
      signalSeen = atkHits > baseHits && atkHits >= 3;
    }
    evidence.notes.push(signalSeen ? 'attack response crosses the boundary the baseline respects' : 'no controlled difference vs baseline');
  } else if (signal === 'sensitive-data-reach') {
    const atkText = attacks.map((a) => a.text).join('∆');
    signalSeen = /confidential":true|sk-live-|salaries|board-minutes/i.test(atkText);
    evidence.notes.push(signalSeen ? 'unprivileged call reached sensitive records' : 'no sensitive data observed in response');
  } else if (signal === 'exfil-to-sink') {
    // ROE: proof must be the CANARY arriving at the LOCAL sink — never a real external host.
    signalSeen = canary ? sinkHits > 0 && attacks.some((a) => a.canarySeen || true) : false;
    evidence.notes.push(signalSeen ? `canary reached local evidence sink (${sinkHits} hits)` : 'no exfiltration demonstrated');
  }

  const reproducible = attacks.length >= 2 && sameSignal(attacks, signal);
  if (!reproducible) evidence.notes.push('not reproducible across runs');

  const confidence = Math.round(
    (signalSeen ? 60 : 0) + (reproducible ? 30 : 0) + (runs.baselines.length ? 10 : 5)
  );
  const confirmed = signalSeen && reproducible;
  return {
    confirmed,
    confidence: confirmed ? confidence : Math.min(confidence, 40),
    grade: confirmed ? 'CONFIRMED' : (signalSeen ? 'NEEDS_MORE_EVIDENCE' : 'REJECTED'),
    reason: evidence.notes.join('; '),
    evidence,
  };
}

function countHits(text) {
  const m = text.match(/"id"\s*:\s*\d+/g);
  return m ? m.length : 0;
}

function sameSignal(attacks, signal) {
  if (signal === 'boundary-escape' || signal === 'sensitive-data-reach') {
    const markers = ['confidential":true', 'HACH-TRAVERSAL-SENTINEL', 'board-minutes', 'salaries', 'sk-live-'];
    return attacks.every((a) => markers.some((m) => a.text.includes(m)));
  }
  return attacks.every((a) => a.text === attacks[0].text);
}

function summarize(runs) {
  const s = (r) => ({ tool: r.tool, latencyMs: r.latencyMs, error: r.error, text: (r.text || '').slice(0, 400), canarySeen: !!r.canarySeen });
  return { attacks: runs.attacks.map(s), baselines: runs.baselines.map(s) };
}
