# Usage report

## Final full-dataset run

- Dataset: 518 requests from `dataset/deletion_requests.csv`
- Command: `.venv\Scripts\python.exe code\main.py` from the repository root
- Runtime: approximately 44 seconds on the local Windows environment
- Python runtime: 3.14.3
- Evidence indexed: 4,052 records and 386 snapshot scopes
- Output: 518 rows and 2,502 steps; 118 `COMPLETE`, 391 `INCOMPLETE`, and 9 `NOT_APPLICABLE`
- Model provider and model name: none; this implementation uses deterministic
  local Python logic and local evidence parsing, with no LLM calls

The tested local environment used `pypdf==6.21.2`, `Pillow==13.0.0`,
`pytesseract==0.3.13`, `packaging==26.3`, and Tesseract `5.4.0.20240606`.
Use the same Python, package, and OCR engine versions on another machine to
reproduce the reported accuracy, especially for screenshot evidence.

| Model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
| --- | ---: | ---: | ---: | ---: | ---: |
| None (no model used) | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | **0** | **0** | **0** | **0** | **$0.00** |

| Per-request measure | Result |
| --- | ---: |
| Requests processed | 518 |
| Average input tokens | 0.00 |
| Average output tokens | 0.00 |
| Average total tokens | 0.00 |
| Estimated average model cost | $0.000000 |

Screenshot OCR uses the locally installed Tesseract executable through
`pytesseract`; PDFs and tabular evidence are also parsed locally. Those steps
make no provider calls and consume no model tokens. The cost figure covers
model usage; local CPU and package-installation costs are not billed or
estimated here.
