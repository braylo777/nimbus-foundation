# M0 — VIN-yield study: REPORT TEMPLATE

    Study:       nf-m0-vin-yield/1
    Derives from: NF-WP-1 §11 (the study), §13 limitation 1 (the untested assumption),
                  §14 M0 (the milestone), §15 recommendation 1 (the gate)
    Measures against: broker/src/fields.js — FIELD_CLASSES, the NF-2 closed vocabulary
    Instrument:  NHTSA vPIC DecodeVinValues / DecodeVinValuesBatch
    Status:      TEMPLATE — contains no findings

**This file is a form, not a result.** Every value in it is a placeholder. A copy of this
file with placeholders still in it is a draft; a copy with placeholders quietly replaced by
guesses is worse than no report at all, because it will be cited downstream as clearance.

## Why this template exists at all

M0 is the cheapest action in the programme and it gates every expensive one. The load-bearing
data assumption of the entire architecture — that a VIN yields the fields Layers 3 and 4 are
designed around — is **untested** (NF-WP-1 §13 limitation 1). Until this report is filled in
and signed, the broker is being built on an assumption, and the assumption is the kind that
fails late: after a counterparty has integrated, after a grant type has been published, after
the field vocabulary is in a signed object that live grants name.

The report therefore has one job: **produce a decision, or refuse to.** Sections 1 and 8 are
the decision. Everything between them is the evidence that the decision was earned.

---

## 0. How to fill this in

### 0.1 Placeholder conventions

| Marker | Meaning |
| --- | --- |
| `‹...›` | Free text. Replace with the actual value; never delete the row. |
| `__.__%` | An unfilled rate. Fill from the machine-generated report, never by hand-arithmetic. |
| `____` | An unfilled count. |
| `[ ]` / `[x]` | A check that a named human performed, not a check the Worker performed. |
| `ILLUSTRATIVE` | A worked example. **Not a finding. Delete before publication.** |

### 0.2 Where the numbers come from

Do not transcribe numbers by hand. Hand-transcription is where a threshold breach becomes a
rounding discussion. The study Worker renders the whole quantitative body of this report:

    GET /report?sample_id=<sample_id>&format=md     # sections 3-7 below, verbatim
    GET /report?sample_id=<sample_id>               # the same, as JSON, for archival
    GET /vocabulary                                 # what was measured and why, per field

Paste the rendered Markdown into sections 3 through 7. Fill sections 1, 2, 8 and 9 by hand —
those are the parts the Worker cannot know: where the sample came from, what is wrong with it,
what the numbers mean for the build, and who is accountable for saying so.

The Worker's section numbering maps onto this template as follows.

| Worker output section | This template |
| --- | --- |
| 1. Determination | §1 (restate) and §8 (decide) |
| 2. Sample integrity + Caveats | §3 |
| 3. Per-field coverage | §4 |
| 4. Mandatory negative findings | §5.1 |
| 5. Confirmed Layer-2 / operator dependencies | §5.2 |
| 6. Specification near-misses | §5.3 |
| 7. Contradictions of `fields.js` | §5.4 |
| 8. vPIC error codes | §6 |
| 9. What M0 does not establish | §7 |

### 0.3 The one rule that outranks the rest

**Invent no coverage numbers.** Not as a placeholder, not as an estimate, not as a
"provisional" figure pending a bigger run, not to make a table render nicely. An unfilled
`__.__%` is honest and obviously incomplete. A plausible invented number is neither, and it
propagates: the first person to quote this report will quote the number, not the caveat.

---

## 1. Determination (restated from the machine report)

    Sample id:           ‹sample_id›
    Runs aggregated:     ____
    VINs decoded:        ____     (this is the coverage denominator)
    Determination:       ‹THRESHOLD MET | THRESHOLD BREACH | INDETERMINATE›
    Re-scoping required: ‹true | false | undetermined›
    Gate decision:       ‹GO | NO-GO | NO DECISION› — see §8

> ‹paste the Worker's verdict statement here, verbatim and unedited›

The Worker declines to rule below 100 decoded VINs and reports `INDETERMINATE`. **A verdict
withheld is not a pass.** See §8.3.

---

## 2. Methodology

### 2.1 Sample construction

Fill this in before the run, not after. A sample described retrospectively is described to fit
the result.

| Item | Value |
| --- | --- |
| Sample id | `‹sample_id›` |
| Provenance (verbatim, as submitted to `POST /decode`) | ‹where these VINs came from and on what basis› |
| Acquisition date / window | ‹...› |
| Nominal sample size (VINs submitted) | ____ |
| Selection rule | ‹enumeration? random draw? whatever was to hand? state it plainly› |
| Strata, if any | ‹model year bands, WMI, body class, market — or "none"› |
| `strict` check-digit mode | ‹true = check-digit-invalid VINs excluded; false = submitted and cross-tabulated› |
| Number of runs, and why more than one | ‹at most 500 VINs per request; a larger study is several runs sharing one sample_id› |

The Worker refuses a run whose `provenance` is shorter than 16 characters. That is deliberate:
a coverage rate over an unattributed sample is not a finding, it is a number.

### 2.2 Known and suspected biases

Every sample of VINs is biased. The question is only whether the bias is written down. Work
this list; do not delete rows that do not apply — mark them "not applicable" and say why, so a
reader can tell the difference between "considered and excluded" and "never thought about".

| Bias | Present? | Direction of effect on measured coverage | Notes |
| --- | --- | --- | --- |
| **Market bias** — sample drawn from North American vehicles only | ‹yes/no› | ‹likely inflates: 49 C.F.R. Part 565 submissions are a US regulatory artefact and vPIC is populated from them› | ‹...› |
| **Recency bias** — sample skews to recent model years | ‹yes/no› | ‹state whether this run confirmed a model-year effect or merely assumed one; do not assert a trend this study did not measure› | ‹...› |
| **Marque concentration** — a few WMIs dominate | ‹yes/no› | ‹unknown direction; per-manufacturer submission practice varies› | ‹...› |
| **Body-class concentration** — e.g. passenger cars only, no heavy trucks | ‹yes/no› | ‹affects `gvwr_class` and `vehicle_type` disproportionately› | ‹...› |
| **Powertrain concentration** — e.g. few or no BEVs | ‹yes/no› | ‹affects `engine_displacement_l` and `fuel_type_primary`, and changes the `absent_not_applicable` share (§2.4)› | ‹...› |
| **Source-channel bias** — VINs from listings, fleets, salvage, or a partner's book | ‹yes/no› | ‹a listing or fleet book is not the vehicle population; say which population this sample is evidence about› | ‹...› |
| **Transcription bias** — VINs from OCR, scraping, or manual entry | ‹yes/no› | ‹raises the syntax-invalid and check-digit-invalid counts; those are findings about the SAMPLE, not about vPIC› | ‹...› |
| **Survivorship** — inoperable, exported, or deregistered vehicles absent | ‹yes/no› | ‹...› | ‹...› |
| **Check-digit exclusion** — `strict = true` drops structurally valid non-NA VINs | ‹yes/no› | **inflates.** 49 C.F.R. §565.15 mandates the check digit for the North American market only; excluding failures removes the population most likely to have poor vPIC coverage, which biases the result toward a pass | ‹...› |
| ‹any other bias› | | | |

State the population this sample is evidence about, in one sentence, and do not let it grow
later: ‹...›

### 2.3 Instrument — NHTSA vPIC

vPIC (Product Information Catalog and Vehicle Listing) is the only public source of
VIN-derived vehicle data. It is populated from manufacturer submissions under 49 C.F.R.
Part 565. It is public, keyless, and unregistered; no credential is involved and none belongs
in the study Worker.

| Property | Value |
| --- | --- |
| Batch endpoint | `POST {base}/DecodeVinValuesBatch/`, form-encoded, VINs `;`-delimited |
| **Batch limit** | **50 VINs per call.** Exceeding it truncates silently — which is why the Worker throws rather than trims |
| Single endpoint | `GET {base}/DecodeVinValues/{vin}?format=json` — used for a leftover batch of one, because it is edge-cacheable |
| Base used in this run | `‹VPIC_BASE›` |
| Result matching | by VIN, never by array index. vPIC does not promise ordering, and a positional match silently attributes one vehicle's build data to another |
| Timeout / attempts | `‹VPIC_TIMEOUT_MS›` ms, `‹VPIC_MAX_ATTEMPTS›` attempts, full-jitter backoff, `Retry-After` honoured |
| Cache TTL | `‹CACHE_TTL_S›` s. vPIC is deterministic per VIN, so a re-run costs nothing after the first pass |

What vPIC is not: it is not a resolver, not a credential source, and not a per-vehicle record
service. It returns build and specification data and nothing else — no owner, no address, no
location, no credential. There is no code path in M0 from a VIN to an authorization, and the
persistence layer is an allowlist projection so a future change to NHTSA's response schema
cannot quietly introduce one (NF-WP-1 §10.1 refusal 1).

### 2.4 The normalization rule — this is the measurement

**vPIC does not return nulls.** It returns empty strings and the literal string
`"Not Applicable"`. Both count as **MISSING for coverage purposes**. They are recorded as
**different states**, and keeping them apart is the whole reason the study exists rather than
being a spreadsheet of decode calls.

| State | Raw form | Counts as coverage? | What it means | Remedy |
| --- | --- | --- | --- | --- |
| `present` | any other non-empty value | **yes** | A usable value was returned | none needed |
| `absent_empty` | `""`, `null`, and the enumerated empty literals | no | Nothing was submitted under Part 565. A **gap** | *may* be fillable from a second source |
| `absent_not_applicable` | `"Not Applicable"` and its variants | no | The manufacturer asserts the field does not apply to this vehicle | **never** fillable — there is nothing to fill |
| `key_absent` | the key is not in the response object | no | The probe name may be wrong, or NHTSA changed the schema | fix the study, not the architecture |

Why the distinction is load-bearing, in one example: a battery-electric vehicle reporting
`DisplacementL = "Not Applicable"` is not a data gap, it is a correct answer. Collapsing it
into the gap bucket blames NHTSA for a fact about the vehicle, inflates the null rate, and
makes the architecture look like it needs a second source when it does not. The opposite
error is worse: counting `"Not Applicable"` as coverage manufactures yield that is not there.

Two normalization decisions a reader should be able to check rather than trust:

- **`"0"` is a present value, not a missing one.** vPIC uses `"0"` meaningfully — `ErrorCode`
  `"0"` is a clean decode. A displacement of `"0"` on a combustion vehicle is a data *defect*,
  not an *absence*. Reclassifying present-but-wrong as absent would report a data-quality
  problem as a coverage problem, which is the one substitution that makes the conclusion wrong
  in the flattering direction.
- **A field with several candidate keys resolves to the first key that is `present`.** If none
  is present, the reported state is that of the **primary** key, because the primary is what
  the architecture nominally reads, and reporting `"Not Applicable"` from a fallback key
  attributes a manufacturer assertion to a key the manufacturer never populated.

Record any deviation from the above here, with the reason: ‹none | ...›

### 2.5 Denominators, and how partial runs are disclosed

Three counters are kept strictly apart, and all three are reported. Conflating any two of them
lets an outage masquerade as a coverage finding.

| Counter | Definition |
| --- | --- |
| `vins_eligible` | passed local syntax and check-digit validation |
| `vins_attempted` | put on the wire **or served from cache** |
| `vins_decoded` | vPIC returned a result row **for that VIN** |

**Every coverage rate in this report is computed over `vins_decoded`, and the denominator is
printed alongside every rate.** A coverage figure detached from the count it was computed over
is the single easiest way for this study to mislead the decision it gates.

Partial runs are **disclosed, never averaged**:

- A VIN vPIC never answered about is recorded in `m0_unreached` with a per-VIN reason and is
  **excluded from the denominator**. It is not recorded as forty absent fields — that would let
  a network error drive a re-scoping decision.
- Any unreached VIN sets `truncated` on the run and emits a `PARTIAL SAMPLE` caveat naming the
  count, the percentage, and the fact that rates are over decoded VINs rather than over the
  sample as submitted. Reproduce that caveat in §3.2 verbatim.
- Runs are reported **individually and then summed**, never averaged. Averaging per-run rates
  weights a 12-VIN run equally with a 400-VIN one. The aggregate denominator is the sum of
  `vins_decoded` across runs; each run's own truncation state is listed separately in §3.1.
- A **null decode** — a result row containing not one present measured field — **is counted in
  the denominator**. A VIN vPIC accepts but cannot describe is a genuine coverage failure, and
  excluding it would be denominator-shopping in the flattering direction. It is also counted
  separately, so a reader can see how much of any shortfall is "vPIC knows nothing about this
  vehicle" versus "vPIC knows this vehicle but not its trim".

### 2.6 Pre-publication integrity checks (human, not machine)

The Worker cannot check these. A named person must, and must initial §9.

- [ ] **No run in the aggregate has a null `finished_at`.** A run that crashed mid-execution
      leaves its row with zero decodes and `truncated = 0`, and it will be summed into the
      totals as a silent zero rather than disclosed as partial. Query `m0_run` directly and
      exclude or re-run any unfinished row **before** rendering the report.
- [ ] **No VIN is counted twice.** The report aggregates by `sample_id` across runs and does
      not de-duplicate VINs between them. Re-submitting the same VIN list under one `sample_id`
      is cheap — the cache makes it nearly free — and it doubles the denominator without adding
      a single vehicle, including for the 100-VIN verdict floor in §8.3. Confirm that
      `SELECT COUNT(DISTINCT vin) FROM m0_observation WHERE run_id IN (...)` equals the
      reported denominator.
- [ ] **`vins_attempted` is understood.** It includes cache hits, which never touched vPIC in
      this run. Do not quote it as a load figure against NHTSA.
- [ ] **Every field in `fields.js` appears in §4.** A field omitted from the table reads
      exactly like a field that passed. Confirm the row count in §4 is 40.
- [ ] **`GET /vocabulary` was archived alongside this report**, so a reader can check what was
      measured against what `fields.js` declares, without reading the source.
- [ ] **The sample was purged, or a purge date is scheduled.** The study store holds VINs.
      `DELETE /sample/‹sample_id›` erases it. NF-WP-1 §9.5: the 45-day Delete Act cadence is an
      operation, not a promise.

### 2.7 What was deliberately not done

- No ground-truthing. A present value counts as coverage even if it is wrong. vPIC reflects
  manufacturer submissions; M0 does not verify them against the vehicle.
- No OEM or Layer-2 access of any kind. M0 measures the public VIN decode and nothing else.
- No second-source substitution. Where a field is missing, M0 records that it is missing; it
  does not go and find it somewhere else and call the result VIN yield.
- ‹anything else, stated plainly›

---

## 3. Sample integrity

*Paste from `GET /report?...&format=md` section 2, including the Caveats block, unedited.*

| Measure | Count |
| --- | --- |
| VINs submitted | ____ |
| Duplicates collapsed | ____ |
| Rejected — syntax (ISO 3779) | ____ |
| Flagged — check digit | ____ |
| Eligible after local validation | ____ |
| Attempted against vPIC (includes cache hits) | ____ |
| Served from cache | ____ |
| **Decoded (coverage denominator)** | **____** |
| Never decoded | ____ |
| Null decodes (row returned, no field present) | ____ |
| Batches / failed | ____ / ____ |
| Sample complete | ‹true/false› |

### 3.1 Per-run disclosure

| `run_id` | Started | Finished | Strict | Decoded | Unreached | Truncated — reason |
| --- | --- | --- | --- | --- | --- | --- |
| `‹...›` | ‹...› | ‹...› | ‹...› | ____ | ____ | ‹...› |

A blank **Finished** cell is a §2.6 failure, not a formatting artefact. Resolve it before
publishing.

### 3.2 Caveats

*Every caveat the Worker emitted, verbatim. If it emitted none, write "None observed." Do not
paraphrase a caveat into something softer.*

- ‹...›

---

## 4. Per-field results, keyed to `FIELD_CLASSES`

All rates are over the `vins_decoded` denominator stated in §3. **Coverage rate** is the
`present` share. **Null rate** is the `absent_empty` share — the gap. **N/A rate** is the
`absent_not_applicable` share — the manufacturer's assertion of inapplicability, which is not
a gap and is not fillable.

**VIN-derivable** is `yes` only at or above the 80% threshold of NF-WP-1 §15 recommendation 1.
**Second source** is `yes` for every field below that threshold and for every field with no
vPIC key at all.

> **ILLUSTRATIVE — NOT A FINDING — DELETE THIS BLOCK BEFORE PUBLICATION**
>
> The two rows below show the shape of a filled row on each side of the gate. The numbers are
> fabricated for the purpose of showing where a number goes. They are not measurements of
> anything, this study has not been run, and they must never be quoted.
>
> | Field | Class | Layer | vPIC key(s) | Coverage | Null | N/A | VIN-derivable | 2nd source | Verdict |
> | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
> | ILLUSTRATIVE `make` | build_specification | vpic | `Make` | ILLUSTRATIVE 99.9% | ILLUSTRATIVE 0.1% | ILLUSTRATIVE 0.0% | yes | no | `vin_derivable` |
> | ILLUSTRATIVE `trim` | build_specification | vpic | `Trim`, `Trim2` | ILLUSTRATIVE 41.0% | ILLUSTRATIVE 59.0% | ILLUSTRATIVE 0.0% | **no** | **yes** | `vin_derivable_below_threshold_second_source_required` |
>
> The second row is the case the whole study exists to catch: a field the architecture treats
> as VIN-derivable, present often enough to look workable in a demo, and not present often
> enough to scope a grant on. Parts applicability for an independent repairer turns on trim,
> not on body class.

### 4.1 `build_specification` — declared layer `vpic` (the class under test)

These fourteen are the only fields `fields.js` claims a VIN can supply. **Every one of them is
in scope for the §8 gate.**

| Field | vPIC key(s) | Coverage | Null | N/A | VIN-derivable | 2nd source | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `make` | `Make` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `model` | `Model` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `model_year` | `ModelYear` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `body_class` | `BodyClass` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `vehicle_type` | `VehicleType` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `drive_type` | `DriveType` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `engine_configuration` | `EngineConfiguration` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `engine_displacement_l` | `DisplacementL` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `fuel_type_primary` | `FuelTypePrimary` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `gvwr_class` | `GVWR`, `GVWR_From`, `GVWR_To` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `plant_country` | `PlantCountry` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `plant_company_name` | `PlantCompanyName` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `series` | `Series`, `Series2` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `trim` | `Trim`, `Trim2` | __.__% | __.__% | __.__% | ‹y/n› | ‹y/n› | ‹...› |

Note on `gvwr_class`: vPIC expresses GVWR as a banded class string with `GVWR_From`/`GVWR_To`
as the numeric band. All three keys are accepted. Refusing a value because it arrived in the
range keys rather than the class key would understate coverage for a reason about NHTSA's
serialization rather than about the vehicle.

Note on `series` and `trim`: these are the two build fields most likely to breach the
threshold and the two that matter most commercially. Manufacturers submit the same concept
under either `Series`/`Series2` or `Trim`/`Trim2`, so both are read.

### 4.2 `diagnostics` — declared layer `layer2`

Expected to have no vPIC key. The study **confirms** that rather than assuming it: an empty
key list is a claim about vPIC's schema, and a probe that hits is evidence the claim was wrong.

| Field | vPIC key(s) | Coverage | VIN-derivable | 2nd source | Verdict |
| --- | --- | --- | --- | --- | --- |
| `dtc_codes` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `dtc_first_seen_at` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `mil_status` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `freeze_frame` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `readiness_monitors` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `obd_protocol` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |

### 4.3 `battery_health` — declared layer `layer2`

| Field | vPIC key(s) | Probe key(s) | Coverage | VIN-derivable | 2nd source | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `state_of_charge_pct` | _none_ | — | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `state_of_health_pct` | _none_ | — | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `pack_temperature_c` | _none_ | — | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `charge_cycle_count` | _none_ | — | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `charge_rate_kw` | _none_ | `ChargerPowerKW`, `ChargerLevel` | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `usable_capacity_kwh` | _none_ | `BatteryKWh`, `BatteryKWh_From`, `BatteryKWh_To` | __.__% | ‹y/n› | ‹y/n› | ‹...› |

Probe results are reported in §5.3, **never** as coverage. See the warning there.

### 4.4 `motion_aggregate` — declared layer `layer2`

| Field | vPIC key(s) | Probe key(s) | Coverage | VIN-derivable | 2nd source | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `speed_mean_kph` | _none_ | — | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `speed_p95_kph` | _none_ | `TopSpeedMPH` | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `harsh_brake_count` | _none_ | — | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `harsh_accel_count` | _none_ | — | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `harsh_corner_count` | _none_ | — | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `aggregation_window_s` | _none_ | — | __.__% | ‹y/n› | ‹y/n› | ‹...› |

### 4.5 `usage` — declared layer `layer2`

| Field | vPIC key(s) | Coverage | VIN-derivable | 2nd source | Verdict |
| --- | --- | --- | --- | --- | --- |
| `odometer_km` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `engine_hours` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `service_due_km` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `annual_mileage_estimate_km` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |

### 4.6 `service_history` — declared layer `operator`

| Field | vPIC key(s) | Coverage | VIN-derivable | 2nd source | Verdict |
| --- | --- | --- | --- | --- | --- |
| `service_events` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `repair_order_summaries` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `recall_completion_status` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |
| `last_service_at` | _none_ | __.__% | ‹y/n› | ‹y/n› | ‹...› |

**Row count check: 14 + 6 + 6 + 6 + 4 + 4 = 40.** That is the whole NF-2 closed vocabulary. If
this report shows fewer than 40 rows, it is incomplete, not clean.

---

## 5. MANDATORY NEGATIVE FINDINGS

**This section is mandatory and is never omitted.** If a subsection has nothing in it, write
"None observed in this sample" and leave the heading. An omitted section reads exactly like a
section that passed, and this report will be read by people deciding whether to spend money.

### 5.1 Fields the architecture assumes are VIN-available but are not

Every field `fields.js` marks `layer: 'vpic'` — i.e. every field the design treats as
derivable from the index alone — that did **not** materialise at or above the threshold.

| Field | Class | Coverage | Null rate | N/A rate | Denominator | Verdict | Consequence for the design |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `‹field_id›` | build_specification | __.__% | __.__% | __.__% | ____ | ‹...› | ‹what grant type or Layer-3/4 assumption this invalidates› |

*If empty:* "None. Every field `fields.js` marks `layer: 'vpic'` materialised at or above the
threshold." — and then §8 still applies, because §5.2 is unaffected by that result.

Record here as well any field that a Layer-3 or Layer-4 design document, product page, pitch,
or API sketch **assumes** is VIN-available while `fields.js` marks it `layer2` or `operator`.
That is a negative finding about the design, not about vPIC, and it is an automatic NO-GO
under §8.2(c) regardless of what any coverage number says.

| Assumed VIN-available by | Field | `fields.js` layer | Where the assumption is written down |
| --- | --- | --- | --- |
| ‹document / page / conversation› | `‹field_id›` | ‹layer2 / operator› | ‹...› |

### 5.2 Confirmed Layer-2 and operator dependencies — the §3.3 ceiling as an empirical finding

State this plainly, in the report, in these terms:

> **vPIC yields build and specification data — make, model, model year, body class, plant,
> engine configuration, fuel type. It does NOT yield location, kinematics, live diagnostic
> trouble codes, battery state, or service history. Every one of those requires Layer-2
> authenticated access, not VIN decode.**

That paragraph is NF-WP-1 §3.3 — the honest ceiling — restated as an empirical finding rather
than as a caveat. NF-1 §6 makes the ceiling normative, and C-2 forbids representing a
Layer-2-dependent field as index-derivable. This section is the evidence for that prohibition,
so it is the section any commercial representation must be checked against.

Twenty-six of the forty fields are expected here. Confirm each, and record the per-field
reason a VIN cannot supply it:

| Field | Class | Layer | Why a VIN cannot supply it | Confirmed? |
| --- | --- | --- | --- | --- |
| `dtc_codes` | diagnostics | layer2 | Runtime state read over OBD-II or an OEM telematics API. Part 565 submissions describe the vehicle **as built** and carry no runtime state | ‹y/n› |
| `dtc_first_seen_at` | diagnostics | layer2 | A timestamp of a runtime event; vPIC holds no per-vehicle event history | ‹y/n› |
| `mil_status` | diagnostics | layer2 | Malfunction indicator lamp state is runtime state, not a build attribute | ‹y/n› |
| `freeze_frame` | diagnostics | layer2 | An ECU snapshot captured at fault time | ‹y/n› |
| `readiness_monitors` | diagnostics | layer2 | Emissions-cycle state, read from the ECU | ‹y/n› |
| `obd_protocol` | diagnostics | layer2 | Plausibly a build attribute and genuinely absent from `DecodeVinValues`; determining it requires interrogating the vehicle — a Layer-2 interaction bounded by the CFAA as narrowed by *Van Buren* and by DMCA §1201 | ‹y/n› |
| `state_of_charge_pct` | battery_health | layer2 | Instantaneous pack charge; no VIN-derived analogue exists | ‹y/n› |
| `state_of_health_pct` | battery_health | layer2 | Degradation measured against nameplate. vPIC can supply the nameplate, never the measurement — structurally Layer-2 **even where vPIC is complete** | ‹y/n› |
| `pack_temperature_c` | battery_health | layer2 | Sensor reading | ‹y/n› |
| `charge_cycle_count` | battery_health | layer2 | A cumulative counter held by the battery management system | ‹y/n› |
| `charge_rate_kw` | battery_health | layer2 | Rated onboard charger power is a build attribute; the **delivered** rate during a session is runtime state. See §5.3 | ‹y/n› |
| `usable_capacity_kwh` | battery_health | layer2 | Nameplate capacity is a Part 565 submission; usable capacity after degradation is a measurement only the pack can report. See §5.3 | ‹y/n› |
| `speed_mean_kph` | motion_aggregate | layer2 | An observed aggregate over a driving window; no build attribute corresponds | ‹y/n› |
| `speed_p95_kph` | motion_aggregate | layer2 | A rated maximum is a property of the vehicle, not of how it was driven. See §5.3 | ‹y/n› |
| `harsh_brake_count` | motion_aggregate | layer2 | An event count derived from consented telemetry | ‹y/n› |
| `harsh_accel_count` | motion_aggregate | layer2 | An event count derived from consented telemetry | ‹y/n› |
| `harsh_corner_count` | motion_aggregate | layer2 | An event count derived from consented telemetry | ‹y/n› |
| `aggregation_window_s` | motion_aggregate | layer2 | Metadata describing a Layer-4 aggregation that has not happened at VIN-decode time | ‹y/n› |
| `odometer_km` | usage | layer2 | **The single most-requested field in the repair and fleet use cases, and flatly unavailable from a VIN.** Odometer comes from the cluster over Layer 2, from a title record, or from an operator disclosure. Any design that assumed VIN-derived odometer is wrong | ‹y/n› |
| `engine_hours` | usage | layer2 | A cumulative ECU counter | ‹y/n› |
| `service_due_km` | usage | layer2 | Requires a live odometer **and** an OEM maintenance schedule | ‹y/n› |
| `annual_mileage_estimate_km` | usage | layer2 | An estimate over observed usage; requires a usage history, not a VIN | ‹y/n› |
| `service_events` | service_history | operator | Held by whoever performed the service | ‹y/n› |
| `repair_order_summaries` | service_history | operator | Held by the repairing operator | ‹y/n› |
| `recall_completion_status` | service_history | operator | **A trap worth naming.** NHTSA does publish recall data, so "the NHTSA API" sounds like it covers this. It does not: `DecodeVinValues` returns no recall field, and the Recalls endpoints are keyed by make/model/year and describe whether a **campaign** exists — never whether **this** vehicle has been remedied. Per-vehicle completion is OEM-held | ‹y/n› |
| `last_service_at` | service_history | operator | Held by the servicing operator | ‹y/n› |

**No positional field appears above because none exists.** Precise geolocation, biometrics and
in-cabin audio/video have no field id at all, and V1 admits no positional field at any
precision (NF-1 §6.3 C-7, C-8). Their absence from this table is structural, not an oversight,
and this study neither measures nor could measure them.

### 5.3 Specification near-misses — the most likely way this report gets misread

vPIC keys that describe the vehicle **as built** and could be mistaken for the runtime **state**
the field actually names. Counting any of these as coverage would manufacture a Layer-2
independence that does not exist.

| Field | vPIC probe key | Present | Present rate | Why it is not the same field |
| --- | --- | --- | --- | --- |
| `usable_capacity_kwh` | `BatteryKWh` | ____ | __.__% | Nameplate capacity as submitted under Part 565, not the measured usable capacity of a four-year-old pack |
| `charge_rate_kw` | `ChargerPowerKW` | ____ | __.__% | Rated onboard charger power, not the rate delivered during a session |
| `speed_p95_kph` | `TopSpeedMPH` | ____ | __.__% | A rated maximum; a 95th-percentile observed speed cannot be derived from it |
| `‹field_id›` | `‹key›` | ____ | __.__% | ‹...› |

A probe hit is **not** coverage and never becomes coverage. It is evidence that vPIC carries an
adjacent specification value, reported here precisely so that nobody quietly promotes it.

### 5.4 Contradictions of `fields.js`

Fields `fields.js` declares non-VIN-derivable for which M0 measured coverage above zero. Any
row here means one of the two artefacts is wrong, and both must be reconciled before either is
relied on. Do not "fix" this by editing `fields.js` to match the measurement without recording
it in §9 — the vocabulary is the source of truth the broker and NF-5 both read, and NF5-NT-002
pins its cardinality at 40 precisely so a silent edit is impossible.

| Field | Declared layer | Measured coverage | Reconciliation |
| --- | --- | --- | --- |
| `‹field_id›` | ‹layer2/operator› | __.__% | ‹...› |

*If empty:* "None. Every field declared non-VIN-derivable measured zero VIN-derived coverage."

---

## 6. vPIC error codes and anomalies

| `ErrorCode` | Occurrences | Meaning as reported by vPIC | Effect on the denominator |
| --- | --- | --- | --- |
| `‹code›` | ____ | ‹ErrorText, verbatim› | ‹counted / excluded — say which and why› |

### 6.1 Anomalies

Result rows with no VIN key, duplicate results, unrequested VINs in a response, and any
tripwire hit. A tripwire is a vPIC response key resembling personal information or position;
none are ever persisted, because the projection is an allowlist — but a hit means NF-WP-1
§10.1 refusals 1 and 2 need a fresh review of whether vPIC may still be consumed as-is.

- ‹...›

---

## 7. What M0 does not establish

Reproduce this list in every published copy. It is the boundary of the claim.

- **Nothing about data the OEM holds.** M0 measures the public VIN decode only. A field absent
  here may be readily available at Layer 2 — that is the point of Layer 2 — and a field
  present here says nothing about whether Layer 2 access is obtainable.
- **Nothing about whether Layer-2 access is legally or commercially obtainable.** That is a
  separate finding, bounded by the CFAA as narrowed by *Van Buren*, by DMCA §1201, and by
  whatever agreement an OEM will actually sign.
- **Nothing about accuracy.** A present value counts as coverage even if it is wrong.
- **Nothing about representativeness** beyond the sample provenance stated in §2.1 and the
  biases in §2.2.
- **Nothing about the non-transactable classes.** They have no field id, so there is nothing
  to measure. Their absence is a schema property, not a study result.
- **Nothing about Layer 5.** There is no pricing, payment, or settlement question in scope
  here, and this study neither creates nor informs one (NF-1 §8).

---

## 8. THE GATE — NF-WP-1 §15 recommendation 1

### 8.1 The decision rule, stated as a rule

> **If any architecturally-assumed field shows less than 80% VIN-derivable coverage, or
> requires a second source, then Layers 3 and 4 MUST be re-scoped around Layer-2
> authenticated access BEFORE the broker is built.**

"Architecturally-assumed" means: any field the design treats as obtainable from the index
alone. Concretely that is every field `fields.js` marks `layer: 'vpic'` (§4.1), plus any field
listed in the second table of §5.1 — a field some design artefact assumes is VIN-available
while `fields.js` says otherwise.

The threshold is 80% of the `vins_decoded` denominator. It is not a target, an average, or a
figure to be met by a favourable choice of denominator. A field the broker can only sometimes
populate is a field a grant cannot be scoped on, and a grant scoped on it is a promise the
protocol cannot keep.

### 8.2 Evaluate, in order. Any one of these is a NO-GO.

- [ ] **(a)** Any `layer: 'vpic'` field measured below 80% coverage.
      → Fields: ‹list, with coverage and denominator, or "none"›
- [ ] **(b)** Any `layer: 'vpic'` field marked `second_source_required = true`.
      → Fields: ‹list, or "none"›
- [ ] **(c)** Any field a design artefact assumes is VIN-available that `fields.js` marks
      `layer2` or `operator` (§5.1, second table). This is a NO-GO **regardless of any
      coverage number**, because §5.2 has already confirmed the field is not VIN-derivable.
      → Fields: ‹list, or "none"›
- [ ] **(d)** Any accounting defect: observation counts that do not reconcile with the
      denominator, or any §2.6 integrity check that failed. Treat the affected rows as
      **unmeasured**, not as low coverage, and do not rule on them.
      → ‹detail, or "none"›

### 8.3 The three outcomes

**NO-GO.** Any box in §8.2 is checked. The re-scoping statement is not paraphrasable; record it
verbatim:

> Layers 3 and 4 need re-scoping around Layer-2 authenticated access before the broker is built.

Re-scoping means: the affected fields are removed from the set of things a grant may be scoped
on from the index alone, and the Layer-3 and Layer-4 designs are rewritten so those fields are
reached through an authenticated `source-adapter` (NF-1 §3.2, boundary B2) or through an
operator disclosure. It does **not** mean lowering the threshold, widening the denominator,
re-drawing the sample, or shipping and finding out.

**GO — for the `build_specification` class only.** Every box in §8.2 is unchecked **and** the
denominator is at or above 100 decoded VINs. Layers 3 and 4 may proceed as scoped for
`build_specification`. **The Layer-2 dependency for the other twenty-six fields is unchanged
and is now empirically confirmed** (§5.2). A GO here authorizes nothing about them.

**NO DECISION.** Fewer than 100 VINs decoded, or a §8.2(d) accounting defect anywhere. The
gate stays **closed**. The study declines to rule, and a declined rule is not a pass: a verdict
drawn from a handful of VINs is worse than no verdict, because it will be cited downstream as
clearance. Run more VINs under the same `sample_id`, re-render, and decide then.

### 8.4 What this gate does not decide

It does not decide whether to build the broker. It decides **what the broker may assume**. A
NO-GO is not a stop-work order; it is a scope correction, delivered while a scope correction is
still cheap — which is the entire reason M0 is first (NF-WP-1 §14 M0, §15 rec 1).

---

## 9. Sign-off

No published copy of this report is valid without this block completed. The point is
attributability: a study that gates a build needs a name attached to its verdict, because the
verdict will be quoted long after everyone has forgotten how the sample was drawn.

| Field | Value |
| --- | --- |
| **Ran the study** | ‹full name, role› |
| **Date run** (first run in this sample) | ‹YYYY-MM-DD› |
| **Date run** (last run in this sample) | ‹YYYY-MM-DD› |
| **Report generated at** | ‹ISO-8601 timestamp from the Worker output› |
| **Study version** | `nf-m0-vin-yield/1` |
| **Sample id** | `‹sample_id›` |
| **Sample size — VINs submitted** | ____ |
| **Sample size — VINs decoded (denominator)** | ____ |
| **Runs aggregated** | ____ |
| **Coverage threshold applied** | 80% (NF-WP-1 §15 rec 1) |
| **Determination** | ‹THRESHOLD MET / THRESHOLD BREACH / INDETERMINATE› |
| **GATE DECISION** | ‹**GO** (build_specification only) / **NO-GO** / **NO DECISION**› |
| **§2.6 integrity checks performed by** | ‹full name› |
| **Reviewed by** (not the person who ran it) | ‹full name, role› |
| **Date reviewed** | ‹YYYY-MM-DD› |
| **`fields.js` reconciled?** | ‹yes / no / not required — if yes, what changed and where› |
| **Sample purged, or purge scheduled for** | ‹YYYY-MM-DD — `DELETE /sample/‹sample_id›`, NF-WP-1 §9.5› |
| **Raw JSON report archived at** | ‹path or URL› |
| **`GET /vocabulary` snapshot archived at** | ‹path or URL› |

### 9.1 Dissent

If the reviewer disagrees with the gate decision, record the disagreement here rather than
resolving it in conversation. An unrecorded dissent is indistinguishable from consensus six
months later.

- ‹...›

### 9.2 Statement of the person who ran it

> I ran the study described in §2. The numbers in §3 through §6 are the Worker's output,
> unedited. I have not filled any coverage figure by hand or by estimate. The biases in §2.2
> are the ones I know of, stated before I saw the result. The gate decision in §8 follows from
> the rule in §8.1 and not from what I would prefer to be true.

Signed: ‹name› · ‹date›
