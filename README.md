# Ghost Data Still Exists — Deletion Audit Agent

## Overview

Ghost Data Still Exists is a Python-based AI-powered audit agent designed to verify whether a user's personal data has been properly deleted across different systems.

Sometimes, deleting an account from the primary system does not remove all copies of the user's data. Information may remain in logs, backups, analytics exports, support attachments, or secondary databases. Active synchronization processes may also recreate previously deleted data.

This project investigates deletion requests, analyzes available evidence, identifies remaining personal information and potential restoration risks, and generates the actions required to complete or verify deletion.

## Objectives

- Determine whether each deletion request is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- Identify current and historical user identifiers across systems.
- Detect personal data that remains after a deletion request.
- Identify active synchronization, import, and restore processes that could recreate deleted information.
- Apply the supplied deletion and data-retention policies.
- Generate ordered remediation and verification steps.
- Produce a structured `output.csv` for all deletion requests.

## How It Works

1. **Load Data:** Read the supplied CSV files and local evidence files.
2. **Resolve Identities:** Connect current and historical identifiers associated with each user.
3. **Investigate Evidence:** Analyze records, logs, timestamps, and other evidence to determine the state of personal data.
4. **Check Policies:** Apply the rules governing deletion, redaction, anonymization, and data retention.
5. **Assess Risks:** Identify remaining data and processes that could recreate deleted information.
6. **Determine Status:** Classify each request based on the evidence and applicable requirements.
7. **Generate Output:** Create ordered remediation or verification steps and write the results to `output.csv`.
8. **Evaluate Results:** Validate the output and measure the agent's performance using an evaluation workflow.

## Technology Stack

- **Python** — Core processing and audit logic
- **Pandas / Python CSV utilities** — Structured data processing, depending on implementation
- **Evidence-processing libraries** — For supported document, image, and database formats
- **LLMs or OCR tools (optional)** — To assist with interpreting unstructured evidence where needed

The implementation should use deterministic validation and policy logic wherever possible, with AI-assisted analysis when appropriate.

## Project Inputs

The supplied `dataset/` directory contains the input data and evidence used by the agent.

Important files include:

- `deletion_requests.csv` — Deletion requests to investigate
- `user_identities.csv` — User identity information
- `user_audit_log.csv` — Audit history
- `system_activity.csv` — System activity and data-flow information
- `deletion_rules.csv` — Deletion and retention policies
- `evidence_files.csv` — Evidence file index
- `sample_deletion_requests.csv` — Sample requests
- `sample_output.csv` — Reference output for validation

Additional evidence may include logs, JSON files, PDFs, images, and database snapshots.

## Output

The agent generates `output.csv` in the repository root with the required schema:

```csv
case_id,deletion_status,steps_json
```

Each request receives one of the following statuses:

- **COMPLETE** — Required deletion or data treatment is complete, relevant risks are addressed, and the result is supported by evidence.
- **INCOMPLETE** — Required actions or unresolved risks remain.
- **NOT_APPLICABLE** — The person did not request deletion.

The `steps_json` column contains ordered steps with the following fields:

- `step_no`
- `phase`
- `system_id`
- `resource_id`
- `operation`
- `state`
- `evidence_id`

The generated output must follow the exact schema, allowed operations, ordering rules, and evidence requirements defined in `problem_statement.md`.

## Setup and Execution

### 1. Clone the Repository

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

### 2. Install Dependencies

Use the dependencies listed in `code/requirements.txt`.

```bash
python -m venv .venv
```

Activate the virtual environment and install the required packages:

**Windows PowerShell**

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r code/requirements.txt
```

**Linux / macOS**

```bash
source .venv/bin/activate
pip install -r code/requirements.txt
```

### 3. Run the Agent

From the repository root, execute:

```bash
python3 code/main.py
```

The program should process the supplied deletion requests and generate the populated `output.csv` in the repository root.

## Evaluation and Testing

The evaluation workflow should verify:

- Status accuracy for deletion requests
- Correct identification of remaining personal data and risks
- Accuracy of individual output fields and remediation steps
- Correct ordering of steps
- Valid evidence references
- CSV and JSON formatting
- Performance on sample data and independently created test cases

Evaluation results, identified failures, and improvement opportunities should be documented in `code/evaluation/evaluation_report.md`.

If AI models are used, actual model usage, token counts, and estimated costs should be documented in `code/evaluation/usage_report.md`.

## Design Principles

- **Evidence-based decisions:** Do not treat reported statuses as proof without supporting evidence.
- **Policy compliance:** Respect required data retention and permitted identifiers.
- **Historical investigation:** Consider current and historical identifiers and events up to the audit timestamp.
- **Recreation prevention:** Check synchronization, imports, and restore paths.
- **Structured output:** Follow the exact required output schema and step ordering.
- **Maintainable code:** Keep data loading, investigation, policy evaluation, and output generation in separate modules.
- **No hardcoded answers:** Process requests using general rules and evidence rather than hardcoded case labels or file-specific answers.

## Submission Artifacts

The project submission includes:

- `code.zip` — Runnable source code, dependencies, documentation, prompts/configuration, and evaluation reports
- `output.csv` — Predictions for the supplied deletion requests
- `log.txt` — Required development conversation transcript

Any additional agent trace archive should follow the challenge's submission instructions.

## Expected Outcome

The goal is to produce an evidence-backed audit report that distinguishes genuinely completed deletions from incomplete requests, identifies remaining personal data and restoration risks, and provides a clear sequence of actions to address outstanding issues.
