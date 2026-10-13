"""
Semantic ranking of Falcon tools via TypeSafe System One.

Keyword retrieval stays in code. This module supplies the judgments that need
semantic understanding: how well each candidate serves the request, whether any
candidate actually does the job, and which tool to try first. Code combines those
answers to reorder `falcon_search_tools` results.

See https://docs.typesafe.ai/concepts/how-to-build-with-system-one.md
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from falcon_mcp.common.logging import get_logger

logger = get_logger(__name__)

# How many keyword hits TypeSafe re-ranks. Remaining matches keep keyword order
# behind that window. 30 scores + one Choice + one Noul fit comfortably in one
# System One request.
CANDIDATE_CAP = 30

# Truncate tool descriptions in state so a wide catalog cannot blow the token budget.
_DESC_CHARS = 400

# Noul below this means "no catalog tool here does the job." Reordering is skipped
# so a weak semantic signal cannot bury a keyword hit. 0.30 matches the skill-
# suggestion cookbook's gate; evaluate on your own traffic before treating it as
# a property of the model.
CAPABILITY_GATE = 0.30

# Score level 1 is "related but not the right tool." A Choice winner is only
# boosted to the front when its Score is at least this — otherwise we would
# promote a tool the per-item scores called wrong.
RELATED_LEVEL = 1.0

NONE_OPTION = "none"
FIRST_TOOL_ID = "first_tool"
CAPABILITY_ID = "capability_present"

SCORE_LEVELS = [
    (
        "This tool does a different job than the request. Using it would not "
        "accomplish what was asked."
    ),
    (
        "This tool is in the right Falcon area but is not the action the request "
        "is asking for. A sibling tool (search vs delete, list vs details, "
        "preview vs apply) would be a better fit."
    ),
    ("This tool is what the request is asking to do. Calling it is the right next step."),
]


class SystemOneClient(Protocol):
    """The TypeSafe client surface this ranker needs."""

    async def system_one(self, state: Any, questions: Mapping[str, Any]) -> Any: ...


@dataclass(frozen=True)
class SemanticRanking:
    """Typed answers composed into a ranking the search path can apply."""

    scores: dict[str, float]
    confidences: dict[str, float]
    first_tool: str | None
    first_tool_confidence: float
    capability_present: float


class ToolRanker(Protocol):
    """Anything DynamicMode can ask to reorder a keyword shortlist."""

    async def rank(
        self, query: str, candidates: list[dict[str, Any]]
    ) -> SemanticRanking | None: ...


def score_question_id(tool_name: str) -> str:
    """Question ID for one tool's relevance Score. IDs are for code, not the model."""
    return f"rel:{tool_name}"


def build_state(query: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    """Named JSON fields the questions can point at with backticked paths."""
    tools = []
    for candidate in candidates:
        description = candidate.get("description") or ""
        if len(description) > _DESC_CHARS:
            description = description[: _DESC_CHARS - 1] + "…"
        tools.append(
            {
                "name": candidate["name"],
                "module": candidate.get("module", ""),
                "description": description,
                "read_only": bool(candidate.get("read_only", True)),
                "destructive": bool(candidate.get("destructive", False)),
            }
        )
    return {"request": query, "tools": tools}


def build_questions(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    """One request: a Score per tool, a Noul for presence, a Choice for first try.

    Questions are independent and evaluated in parallel. Code consumes the Choice
    only when the corresponding Score says the tool is at least related.
    """
    questions: dict[str, Any] = {}
    for index, candidate in enumerate(candidates):
        name = candidate["name"]
        questions[score_question_id(name)] = {
            "type": "score",
            "instructions": (
                f"How well does `tools[{index}].name` serve `request`? "
                f"Judge the job described in `tools[{index}].description` against "
                "what the request is asking to do, not whether words overlap. "
                f"`tools[{index}].read_only` and `tools[{index}].destructive` "
                "describe mutation risk; they do not change whether this is the "
                "right capability."
            ),
            "criteria": SCORE_LEVELS,
        }

    questions[CAPABILITY_ID] = {
        "type": "noul",
        "instructions": (
            "Does any tool in `tools` perform the action `request` is asking for? "
            "Related tools in the same Falcon module do not count unless calling "
            "one of them would actually accomplish the request."
        ),
        "criteria": {
            "yes": ("At least one listed tool is the right action for this request."),
            "no": (
                "None of these tools do what was asked; they are unrelated or "
                "only loosely adjacent."
            ),
        },
    }

    choice_criteria: dict[str, str] = {NONE_OPTION: "None of these tools do what the request asks."}
    for index, candidate in enumerate(candidates):
        description = candidate.get("description") or ""
        if len(description) > 160:
            description = description[:159] + "…"
        choice_criteria[candidate["name"]] = (
            f"{candidate['name']} ({candidate.get('module', '')}): {description}"
        )
    questions[FIRST_TOOL_ID] = {
        "type": "choice",
        "instructions": (
            "Which single tool in `tools` should be called first to accomplish "
            "`request`? Pick `none` if none of them do this job."
        ),
        "criteria": choice_criteria,
    }
    return questions


def apply_ranking(
    candidates: list[dict[str, Any]], ranking: SemanticRanking
) -> list[dict[str, Any]]:
    """Reorder keyword hits from TypeSafe answers. Never drops a candidate.

    A Noul below CAPABILITY_GATE leaves keyword order untouched: the model is
    saying nothing here is a fit, and burying a lexical hit would hide the only
    remaining lead. Otherwise sort by Score, keep read-only as a tie-break so
    ranking never steers toward a mutator when scores match, and promote the
    Choice winner only when its Score says it is at least related.
    """
    if ranking.capability_present < CAPABILITY_GATE:
        return list(candidates)

    original_index = {candidate["name"]: i for i, candidate in enumerate(candidates)}

    def sort_key(candidate: dict[str, Any]) -> tuple[float, float, bool, int]:
        name = candidate["name"]
        return (
            -ranking.scores.get(name, 0.0),
            -ranking.confidences.get(name, 0.0),
            not bool(candidate.get("read_only", True)),
            original_index[name],
        )

    ordered = sorted(candidates, key=sort_key)

    first = ranking.first_tool
    if (
        first
        and first != NONE_OPTION
        and first in original_index
        and ranking.scores.get(first, 0.0) >= RELATED_LEVEL
    ):
        winner = next(c for c in ordered if c["name"] == first)
        ordered = [winner] + [c for c in ordered if c["name"] != first]

    return ordered


def ranking_from_response(candidates: list[dict[str, Any]], response: Any) -> SemanticRanking:
    """Read typed answers off a System One response."""
    scores: dict[str, float] = {}
    confidences: dict[str, float] = {}
    response_scores = getattr(response, "scores", {}) or {}
    for candidate in candidates:
        name = candidate["name"]
        answer = response_scores.get(score_question_id(name))
        if answer is None:
            continue
        scores[name] = float(answer.score)
        confidences[name] = float(getattr(answer, "confidence", 0.0))

    nouls = getattr(response, "nouls", {}) or {}
    capability = nouls.get(CAPABILITY_ID)
    capability_present = float(capability.noul) if capability is not None else 0.0

    choices = getattr(response, "choices", {}) or {}
    first = choices.get(FIRST_TOOL_ID)
    first_tool = first.choice if first is not None else None
    first_conf = float(getattr(first, "confidence", 0.0)) if first is not None else 0.0

    return SemanticRanking(
        scores=scores,
        confidences=confidences,
        first_tool=first_tool,
        first_tool_confidence=first_conf,
        capability_present=capability_present,
    )


def attach_relevance(
    candidates: list[dict[str, Any]], ranking: SemanticRanking
) -> list[dict[str, Any]]:
    """Copy relevance onto each entry from the Score answers. Keyword order is unchanged."""
    decorated = []
    for candidate in candidates:
        entry = dict(candidate)
        name = candidate["name"]
        if name in ranking.scores:
            entry["relevance"] = round(ranking.scores[name], 2)
        decorated.append(entry)
    return decorated


def resolve_semantic_ranker(*, dynamic: bool) -> TypeSafeRanker:
    """Build a ranker or raise a configuration error.

    Credentials stay in the environment (`TYPESAFE_API_KEY`); they are never
    accepted as tool input or returned in search results.
    """
    if not dynamic:
        raise ValueError(
            "Semantic search (--semantic-search / FALCON_MCP_SEMANTIC_SEARCH) "
            "requires dynamic mode (--dynamic / FALCON_MCP_DYNAMIC)."
        )
    api_key = os.environ.get("TYPESAFE_API_KEY", "").strip()
    if not api_key:
        raise ValueError(
            "Semantic search requires TYPESAFE_API_KEY. Create a key at "
            "https://console.typesafe.ai and set it in the environment."
        )
    try:
        import typesafe_sdk  # noqa: F401
    except ImportError as exc:
        raise ValueError(
            "Semantic search requires the TypeSafe SDK. Install it with "
            "pip install 'falcon-mcp[typesafe]' or uv add typesafe-sdk."
        ) from exc
    return TypeSafeRanker()


class TypeSafeRanker:
    """Ask TypeSafe one request per search and return a SemanticRanking.

    The HTTP client is created lazily so tests can inject a fake `system_one`.
    """

    def __init__(self, client: SystemOneClient | None = None) -> None:
        self._client = client

    async def _ensure_client(self) -> SystemOneClient:
        if self._client is None:
            from typesafe_sdk import AsyncTypeSafeClient

            self._client = AsyncTypeSafeClient()
        return self._client

    async def rank(self, query: str, candidates: list[dict[str, Any]]) -> SemanticRanking | None:
        """Return rankings for ``candidates``, or None when there is nothing to ask."""
        if not query or not candidates:
            return None
        window = candidates[:CANDIDATE_CAP]
        state = build_state(query, window)
        questions = build_questions(window)
        client = await self._ensure_client()
        response = await client.system_one(state=state, questions=questions)
        ranking = ranking_from_response(window, response)
        logger.debug(
            "TypeSafe ranked %d tools for query %r (capability_present=%.2f, first=%s)",
            len(window),
            query,
            ranking.capability_present,
            ranking.first_tool,
        )
        return ranking
