# Usage report

## Final full-dataset run

- Dataset: 518 requests from `dataset/deletion_requests.csv`
- Command: `.venv\Scripts\python.exe code\main.py`, run from the repository root
- Runtime: approximately 85 seconds on the local Windows environment
- Python: 3.14.3
- Evidence indexed: 4,052 records and 386 snapshot scopes
- Output: 518 rows and 2,553 steps; 153 `COMPLETE`, 356 `INCOMPLETE`, and 9 `NOT_APPLICABLE`
- Model provider and model name: none; the solution uses deterministic local
  Python logic and local evidence parsing, with no model calls
- OCR: Tesseract `5.4.0.20240606`, detected at the standard Windows install
  path

The tested Python packages were `pypdf==6.21.2`, `Pillow==13.0.0`,
`pytesseract==0.3.13`, and `packaging==26.3`.

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

PDF and structured-data parsing, image OCR, and the audit itself run locally.
They make no provider calls and consume no model tokens. The cost figures
cover model usage; local CPU and package-installation costs are not estimated.
