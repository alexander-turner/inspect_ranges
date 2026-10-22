# Challenges v1: decisions parked for the user

*Each entry states the question, the recommendation, and the safe interim behavior in force. None blocks shipped behavior.*

## 1. Content templates for exfiltrate plants (docs exam gap 10, 2026-10-22)

**The fact:** an `exfiltrate` goal's planted file is the per-sample canary and nothing else (`plant_secret_file` writes `oracle.nonce()` as the whole content, `_challenges/setup.py`). There is no way to make `payroll_q3.csv` look like a payroll CSV with the canary embedded; realism is `data.description` flavor only. The fresh-context docs exam flagged this as the one plant-layer wish its scenario design produced.

**Why the later slot-in is small:** exfiltrate matching is already containment-based on both witnesses (`goaltypes.py`: the submission passes if it contains the canary; pcap corroboration is a source-bound substring scan), so a canary embedded inside realistic content would score today without scorer changes. The work is confined to the plant writer and its bookkeeping: a content-render parameter on `plant_secret_file`, plus plant-store semantics as the open sub-question (`PlantStore.record` stores the whole written value and digests it; template content either stores rendered-whole with the canary as a separate field, or `compare` keys off the canary alone). One new failure mode arrives with templates: a realistic prefix can push the canary across a TCP segment boundary, and the pcap scan matches within single packets, so corroboration of large templated files needs either canary-early placement guidance or cross-packet reassembly.

**A discrepancy to resolve when this lands:** `challenges-scoring-integrity.md` ("Proof contracts", exfiltrate row) says setup "embeds per-sample unpredictable canary material in the target content"; the implementation replaces the content instead of embedding. The template feature is what would make that sentence true; until then the docs state replace-semantics plainly (Challenges, "Planting").

**The decision parked:** whether to build content templates, and the plant-store/corroboration semantics above. Recommendation: not before a real range (not an exam) forces it; the opaque canary is strictly better for scoring integrity (nothing plausible to fabricate), and placement-based protection is unaffected by content realism.

**Interim behavior in force:** canary-only content, documented as by-design in Challenges ("Planting") with realism assigned to `data.description`; `ExfiltrateType`'s docstring points here.
