# Evaluation report

## Public sample comparison

The evaluator compared predictions for all 32 rows in
`dataset/sample_deletion_requests.csv` against `dataset/sample_output.csv`.
Sample answers are loaded only by the evaluation script; the production
investigation and classifier do not read them.

| Metric | Result | Definition |
| --- | ---: | --- |
| Case/status accuracy | 32 / 32 (100.00%) | Correct `deletion_status` values |
| Exact row accuracy | 14 / 32 (43.75%) | Correct status and exact ordered `steps_json` |
| Exact step accuracy | 124 / 194 (63.92%) | Exact step objects at the same array index; missing positions count as incorrect |
| Field accuracy | 1,004 / 1,358 (73.93%) | Matching values across seven step fields at aligned positions; missing positions count as incorrect |
| Exact sequence accuracy | 14 / 32 (43.75%) | Entire ordered step arrays match exactly |

The comparison command is:

```powershell
python code/evaluation/evaluate_samples.py
```

## Independent regression cases

Thirty synthetic `unittest` checks are maintained in `test_agent.py`. They
exercise general behavior without reading or hardcoding sample answers. The
suite includes:

1. **Identity at a cutoff:** resolve a historical email and phone through
   identity audit history, while excluding changes after `audit_at`.
2. **Request intent:** distinguish deletion requests from export, correction,
   and marketing-only requests, including supported non-English forms.
3. **Resource linkage:** join same-file records by scoped trace IDs, reject
   ambiguous report-time activity, and avoid linking a resource based on an
   unrelated service instance name.
4. **State and policy:** prefer an explicit same-time flow state, identify an
   eligible restore path, and distinguish blocked restores from active risks.
5. **PII handling:** preserve a stable tombstone reference while detecting
   direct identifiers, and apply the marketing deletion policy to explicit
   consent records.
6. **Parsing safeguards:** require whole-name boundaries, match email hashes
   as opaque identifiers, and classify nested support, attachment, and JSON
   records from their content.
7. **Output contract:** serialize valid, ordered steps and verify snapshot-based
   absence only when the scope supports it.

Run the checks with:

```powershell
python -m unittest discover -s code/evaluation -p "test_*.py"
```

Result for this version: **30 tests passed**.

## Failures found and improvements made

- Name matching previously accepted a name as a substring of a longer name.
  It now requires token boundaries, reducing false identity links.
- Hexadecimal email hashes were incorrectly eligible for phone-digit matching.
  Hash-shaped identifiers now use exact opaque-value matching.
- A nearby worker event can supply a resource lookup seed when it is uniquely
  associated with one request's report time. The event remains a claim; a
  current evidence row or snapshot is still required to establish state.
  Ambiguous events are excluded, and only a narrowly grouped action burst is
  followed.
- Same-time flow observations could select an event without a resulting state.
  Explicit state fields now break ties between observations with equal times.
- Log resource extraction could interpret service instance names as user
  records. Structured logs now require a resource field or a labeled resource
  reference.
- PDF parsing clipped identifiers before related subject fields on the same
  page. Extraction now preserves the section through the next resource
  reference, and attachment context takes precedence over incidental delivery
  wording.
- Explicit marketing-consent fields in analytics logs were being treated as
  analytics profiles. They now use the supplied `MARKETING_PROFILE` deletion
  policy while retaining the actual service system ID.
- Snapshot coverage can establish absence for an already linked resource when
  every latest relevant scope omits it and policy requires unconditional
  deletion.

The largest remaining limitation is resource attribution when a record or
snapshot contains neither a subject identifier nor a grounded reference to
the subject. Those resources are not assigned to a person by case number,
sample answer, or timestamp proximity alone. As a result, some public sample
step arrays remain different even though all sample deletion statuses match.
The reported scores measure the public sample only and do not predict hidden
set accuracy.

## Full output validation

The final run processed all 518 requests and wrote the repository-root
`output.csv`: 153 `COMPLETE`, 356 `INCOMPLETE`, and 9 `NOT_APPLICABLE`, with
2,553 total steps. The validator confirmed all rows are sorted and complete,
the exact required columns, valid JSON and evidence references, consecutive
step numbers, and required phase and operation ordering.

```powershell
python code/evaluation/validate_output.py
```
