# Evaluation report

## Public sample comparison

The evaluator compared the agent's predictions for all 32 rows in
`dataset/sample_deletion_requests.csv` with `dataset/sample_output.csv`. The
sample answers are used only by the evaluator and are not inputs to
`investigate_case` or the production classifier.

| Metric | Result | Definition |
| --- | ---: | --- |
| Case/status accuracy | 29 / 32 (90.63%) | Correct `deletion_status` values |
| Exact row accuracy | 7 / 32 (21.88%) | Correct status and exact ordered `steps_json` |
| Exact step accuracy | 99 / 196 (50.51%) | Exact step objects at the same array index; missing positions count as incorrect |
| Field accuracy | 873 / 1,372 (63.63%) | Matching values across the seven step fields at aligned positions; missing positions count as incorrect |
| Exact sequence accuracy | 7 / 32 (21.88%) | Entire ordered step arrays match exactly |

The comparison command is:

```powershell
python code/evaluation/evaluate_samples.py
```

## Independent regression cases

Twenty-three synthetic `unittest` checks are maintained in `test_agent.py`. They do
not read or hardcode sample answers. Representative independent cases include:

1. **Historical identity at a cutoff:** an old request email resolves to the
   user whose audit history links it to a phone number; the phone history is
   limited to changes known by `audit_at`. The test passes.
2. **Active data-flow remediation:** a linked enabled connector creates an
   active-flow finding, disable action, and disabled-state verification. The
   test passes.
3. **Tombstone redaction:** a tombstone keeps the stable subject reference but
   still triggers redaction when a direct email remains. The test passes.
4. **Snapshot absence:** a later full snapshot scope can prove that a previously
   observed resource is absent, with the snapshot file cited as evidence. The
   test passes.
5. **Evidence linking and parser safeguards:** matching trace IDs join sibling
   log records in the same evidence file; ambiguous names alone do not link a
   user; telephone digits must form a bounded number; nested support tables and
   attachment records are classified from their content rather than an export
   filename; placeholder references do not fan out a timeline; service instance
   names do not become customer resource IDs; hexadecimal email hashes are
   matched as opaque identifiers. These checks pass.
6. **Restore-state interpretation:** a restore candidate marked eligible with
   no deletion block creates a restore-risk remediation; an explicit block is
   not treated as an active restore path. The test passes.

Run all independent checks with:

```powershell
python -m unittest discover -s code/evaluation -p "test_*.py"
```

Result for the final code: **23 tests passed**.

## Failures found and improvements made

- Broad non-deletion wording initially misclassified requests about correcting
  or accessing data. Intent checks were tightened and deletion language was
  extended for the supplied multilingual requests.
- Evidence category inference let a log message or export filename overrule a
  resource prefix or nested JSON table. Explicit categories and table context
  now take precedence, with resource identifiers used before free-form log
  prose.
- Literal `null` references caused unrelated records to be pulled into a case.
  Placeholder values are now excluded from resource expansion.
- Related log rows sometimes carried the subject and the resource identifier on
  separate lines. Same-file trace and correlation IDs now join those records
  through indexed lookups; they are scoped to the evidence file and field to
  prevent broad cross-file joins.
- A shared name could match a different person. Names are now weak identifiers
  and are used only when unique at the cutoff; email, phone, hashes, and stable
  IDs remain direct matches. Phone matching also requires a bounded digit
  group.
- A false deletion-marker check on a support resource was treated like a
  redacted conversation. The marker evidence now drives the delete policy for
  that resource.
- A later coverage scope could be the latest observation and was discarded
  because it was not a record row. The policy evaluator now uses a matching row
  for policy conditions while allowing the newer scope to prove absence.
- A stored row's `account_status=DELETED` was treated as proof that the row was
  absent. Workflow labels no longer override a row observed in a snapshot.
- Stable internal references were counted as direct PII during redaction. They
  are excluded from direct-identifier checks, while anonymization checks still
  detect linkable internal references. Tombstones may retain their permitted
  stable reference while direct identifiers remain subject to redaction.
- Structured logs contain deployment instance names such as `account-2` next
  to real resource identifiers. Treating every resource-shaped token as a
  resource linked unrelated users' log entries; structured logs now require a
  resource field or a labeled resource reference before creating a resource
  link.
- Hexadecimal email hashes were routed through phone-number matching, which
  missed exact hash references in logs. Hash-shaped values now use exact opaque
  identifier matching. Restore-candidate fields `eligible` and
  `deletion_block` now determine whether a restore path remains active.

Three sample status errors remain (`case_01`, `case_02`, and `case_04`). The
nearby activity targets do not explicitly identify the request subject, and
the agent does not connect them by timing alone. Exact-row and sequence scores
remain lower than status accuracy, so resource discovery and evidence
attribution still need work. These are measured limitations, not estimates of
hidden-set performance.

## Full output validation

The final full-dataset run processed all 518 requests and wrote the repository
root `output.csv`: 118 `COMPLETE`, 391 `INCOMPLETE`, and 9 `NOT_APPLICABLE`,
with 2,502 total steps. The validator confirmed the exact column order, one
sorted row for every case, valid JSON arrays, consecutive step numbers, valid
evidence references, and required phase/operation/system/resource ordering.

```powershell
python code/evaluation/validate_output.py
```
