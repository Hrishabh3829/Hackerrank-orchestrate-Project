"""Case investigation orchestration (implemented in a later project step)."""

from __future__ import annotations

from typing import Mapping

from data_loading import Dataset
from output_generation import CasePrediction


def investigate_case(request: Mapping[str, str], dataset: Dataset) -> CasePrediction:
    """Build an evidence-backed result for one request.

    This stage requires evidence parsers and temporal resource-state analysis.
    It intentionally raises until those pieces are implemented; callers must
    not substitute workflow statuses or sample answers for evidence.
    """
    del request, dataset
    raise NotImplementedError("Case investigation is the next implementation step.")
