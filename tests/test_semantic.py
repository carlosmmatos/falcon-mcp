"""Tests for TypeSafe semantic ranking of dynamic-mode search results."""

import asyncio
import os
import unittest
from collections.abc import Coroutine
from types import SimpleNamespace
from typing import Any, TypeVar
from unittest.mock import MagicMock, patch

from falcon_mcp.dynamic import DynamicMode
from falcon_mcp.modules.detections import DetectionsModule
from falcon_mcp.modules.hosts import HostsModule
from falcon_mcp.modules.ioc import IOCModule
from falcon_mcp.semantic import (
    CAPABILITY_GATE,
    FIRST_TOOL_ID,
    NONE_OPTION,
    RELATED_LEVEL,
    SCORE_LEVELS,
    SemanticRanking,
    TypeSafeRanker,
    apply_ranking,
    attach_relevance,
    build_questions,
    build_state,
    ranking_from_response,
    resolve_semantic_ranker,
    score_question_id,
)

_T = TypeVar("_T")


def run_async(coro: Coroutine[Any, Any, _T]) -> _T:
    return asyncio.run(coro)


def _candidate(name: str, *, read_only: bool = True, module: str = "detections") -> dict:
    return {
        "name": name,
        "module": module,
        "description": f"Does {name}",
        "read_only": read_only,
        "destructive": not read_only,
    }


def _ranking(
    scores: dict[str, float],
    *,
    capability_present: float = 0.9,
    first_tool: str | None = NONE_OPTION,
    first_tool_confidence: float = 0.8,
    confidences: dict[str, float] | None = None,
) -> SemanticRanking:
    return SemanticRanking(
        scores=scores,
        confidences=confidences or {name: 0.8 for name in scores},
        first_tool=first_tool,
        first_tool_confidence=first_tool_confidence,
        capability_present=capability_present,
    )


class TestBuildStateAndQuestions(unittest.TestCase):
    def test_state_uses_named_fields_and_truncates_descriptions(self):
        long_desc = "x" * 500
        state = build_state(
            "contain this host",
            [_candidate("falcon_search_hosts") | {"description": long_desc}],
        )
        self.assertEqual(state["request"], "contain this host")
        self.assertEqual(state["tools"][0]["name"], "falcon_search_hosts")
        self.assertLessEqual(len(state["tools"][0]["description"]), 400)
        self.assertTrue(state["tools"][0]["description"].endswith("…"))

    def test_questions_cover_each_tool_plus_presence_and_first_choice(self):
        candidates = [
            _candidate("falcon_search_detections"),
            _candidate("falcon_search_hosts", module="hosts"),
        ]
        questions = build_questions(candidates)
        self.assertIn(score_question_id("falcon_search_detections"), questions)
        self.assertIn(score_question_id("falcon_search_hosts"), questions)
        self.assertEqual(questions["capability_present"]["type"], "noul")
        self.assertEqual(questions[FIRST_TOOL_ID]["type"], "choice")
        self.assertEqual(questions[FIRST_TOOL_ID]["criteria"][NONE_OPTION][:4], "None")
        self.assertIn("falcon_search_detections", questions[FIRST_TOOL_ID]["criteria"])
        score_q = questions[score_question_id("falcon_search_detections")]
        self.assertEqual(score_q["criteria"], SCORE_LEVELS)
        self.assertIn("`request`", score_q["instructions"])
        self.assertIn("`tools[0].name`", score_q["instructions"])

    def test_question_ids_are_for_code_not_the_only_meaning(self):
        questions = build_questions([_candidate("falcon_search_iocs", module="ioc")])
        for question in questions.values():
            self.assertTrue(question["instructions"])


class TestApplyRanking(unittest.TestCase):
    def test_capability_gate_preserves_keyword_order(self):
        candidates = [
            _candidate("falcon_search_hosts", module="hosts"),
            _candidate("falcon_search_detections"),
        ]
        ranking = _ranking(
            {
                "falcon_search_detections": 2.0,
                "falcon_search_hosts": 0.1,
            },
            capability_present=CAPABILITY_GATE - 0.01,
        )
        ordered = apply_ranking(candidates, ranking)
        self.assertEqual(
            [c["name"] for c in ordered],
            ["falcon_search_hosts", "falcon_search_detections"],
        )

    def test_sorts_by_score_then_prefers_read_only_on_ties(self):
        candidates = [
            _candidate("falcon_remove_iocs", read_only=False, module="ioc"),
            _candidate("falcon_search_iocs", module="ioc"),
        ]
        ranking = _ranking(
            {"falcon_remove_iocs": 1.5, "falcon_search_iocs": 1.5},
        )
        ordered = apply_ranking(candidates, ranking)
        self.assertEqual(ordered[0]["name"], "falcon_search_iocs")

    def test_choice_winner_is_promoted_when_related_or_better(self):
        candidates = [
            _candidate("falcon_search_hosts", module="hosts"),
            _candidate("falcon_search_detections"),
            _candidate("falcon_get_detection_details"),
        ]
        ranking = _ranking(
            {
                "falcon_search_hosts": 1.8,
                "falcon_search_detections": 1.6,
                "falcon_get_detection_details": 1.1,
            },
            first_tool="falcon_search_detections",
        )
        ordered = apply_ranking(candidates, ranking)
        self.assertEqual(ordered[0]["name"], "falcon_search_detections")

    def test_choice_winner_is_not_promoted_when_score_says_wrong_tool(self):
        candidates = [
            _candidate("falcon_search_detections"),
            _candidate("falcon_search_hosts", module="hosts"),
        ]
        ranking = _ranking(
            {
                "falcon_search_detections": 2.0,
                "falcon_search_hosts": RELATED_LEVEL - 0.2,
            },
            first_tool="falcon_search_hosts",
        )
        ordered = apply_ranking(candidates, ranking)
        self.assertEqual(ordered[0]["name"], "falcon_search_detections")

    def test_never_drops_a_candidate(self):
        candidates = [
            _candidate("a"),
            _candidate("b"),
            _candidate("c"),
        ]
        ranking = _ranking({"b": 2.0, "c": 1.0, "a": 0.0}, first_tool="b")
        ordered = apply_ranking(candidates, ranking)
        self.assertEqual({c["name"] for c in ordered}, {"a", "b", "c"})


class TestRankingFromResponse(unittest.TestCase):
    def test_reads_typed_answers(self):
        candidates = [_candidate("falcon_search_detections")]
        response = SimpleNamespace(
            scores={
                score_question_id("falcon_search_detections"): SimpleNamespace(
                    score=1.7, confidence=0.9
                )
            },
            nouls={"capability_present": SimpleNamespace(noul=0.81)},
            choices={
                FIRST_TOOL_ID: SimpleNamespace(choice="falcon_search_detections", confidence=0.7)
            },
        )
        ranking = ranking_from_response(candidates, response)
        self.assertAlmostEqual(ranking.scores["falcon_search_detections"], 1.7)
        self.assertAlmostEqual(ranking.capability_present, 0.81)
        self.assertEqual(ranking.first_tool, "falcon_search_detections")

    def test_attach_relevance_rounds_scores(self):
        candidates = [_candidate("falcon_search_detections")]
        ranking = _ranking({"falcon_search_detections": 1.666})
        decorated = attach_relevance(candidates, ranking)
        self.assertEqual(decorated[0]["relevance"], 1.67)
        self.assertEqual(candidates[0].get("relevance"), None)


class FakeRanker:
    def __init__(self, ranking: SemanticRanking, error: Exception | None = None):
        self.ranking = ranking
        self.error = error
        self.queries: list[tuple[str, list[str]]] = []

    async def rank(self, query: str, candidates: list[dict[str, Any]]) -> SemanticRanking:
        self.queries.append((query, [c["name"] for c in candidates]))
        if self.error:
            raise self.error
        return self.ranking


class TestDynamicModeSemanticSearch(unittest.TestCase):
    def setUp(self):
        self.modules = {
            "detections": DetectionsModule(MagicMock()),
            "hosts": HostsModule(MagicMock()),
            "ioc": IOCModule(MagicMock()),
        }

    def test_semantic_ranking_reorders_search_results(self):
        ranker = FakeRanker(
            _ranking(
                {
                    "falcon_search_detections": 0.4,
                    "falcon_get_detection_details": 1.9,
                },
                first_tool="falcon_get_detection_details",
            )
        )
        dynamic = DynamicMode(self.modules, MagicMock(), ranker=ranker)
        result = run_async(dynamic._search_tools(query="detections"))
        names = [r["name"] for r in result["results"]]
        self.assertEqual(names[0], "falcon_get_detection_details")
        self.assertEqual(result["ranking"], "semantic")
        self.assertIn("not just keyword overlap", result["hint"])
        self.assertEqual(result["results"][0]["relevance"], 1.9)
        self.assertTrue(ranker.queries)

    def test_low_capability_noul_keeps_keyword_order(self):
        dynamic_plain = DynamicMode(self.modules, MagicMock())
        keyword = run_async(dynamic_plain._search_tools(query="detections"))
        ranker = FakeRanker(
            _ranking(
                {r["name"]: 2.0 for r in keyword["results"][:3]},
                capability_present=0.05,
                first_tool=keyword["results"][2]["name"],
            )
        )
        dynamic = DynamicMode(self.modules, MagicMock(), ranker=ranker)
        result = run_async(dynamic._search_tools(query="detections"))
        self.assertEqual(
            [r["name"] for r in result["results"]],
            [r["name"] for r in keyword["results"]],
        )
        self.assertEqual(result["ranking"], "keyword")
        self.assertIn("did not find a strong match", result["hint"])

    def test_ranker_failure_falls_back_to_keyword_order(self):
        dynamic_plain = DynamicMode(self.modules, MagicMock())
        keyword = run_async(dynamic_plain._search_tools(query="hosts"))
        ranker = FakeRanker(_ranking({}), error=RuntimeError("typesafe down"))
        dynamic = DynamicMode(self.modules, MagicMock(), ranker=ranker)
        result = run_async(dynamic._search_tools(query="hosts"))
        self.assertEqual(
            [r["name"] for r in result["results"]],
            [r["name"] for r in keyword["results"]],
        )
        self.assertNotIn("ranking", result)

    def test_exact_tool_name_skips_the_ranker(self):
        ranker = FakeRanker(_ranking({"falcon_search_hosts": 0.0}))
        dynamic = DynamicMode(self.modules, MagicMock(), ranker=ranker)
        result = run_async(dynamic._search_tools(query="falcon_search_hosts"))
        self.assertEqual(result["results"][0]["name"], "falcon_search_hosts")
        self.assertEqual(len(result["results"]), 1)
        self.assertFalse(ranker.queries)

    def test_schema_lookup_skips_the_ranker(self):
        ranker = FakeRanker(_ranking({}))
        dynamic = DynamicMode(self.modules, MagicMock(), ranker=ranker)
        result = run_async(dynamic._search_tools(tool_names=["falcon_search_detections"]))
        self.assertIn("parameters", result["results"][0])
        self.assertFalse(ranker.queries)

    def test_empty_query_skips_the_ranker(self):
        ranker = FakeRanker(_ranking({}))
        dynamic = DynamicMode(self.modules, MagicMock(), ranker=ranker)
        result = run_async(dynamic._search_tools(query=""))
        self.assertGreater(len(result["results"]), 0)
        self.assertFalse(ranker.queries)


class TestTypeSafeRanker(unittest.TestCase):
    def test_rank_sends_one_request_with_every_question(self):
        captured: dict[str, Any] = {}

        class Client:
            async def system_one(self, state, questions):
                captured["state"] = state
                captured["questions"] = questions
                return SimpleNamespace(
                    scores={
                        score_question_id("falcon_search_detections"): SimpleNamespace(
                            score=2.0, confidence=0.95
                        )
                    },
                    nouls={"capability_present": SimpleNamespace(noul=0.99)},
                    choices={
                        FIRST_TOOL_ID: SimpleNamespace(
                            choice="falcon_search_detections", confidence=0.9
                        )
                    },
                )

        ranker = TypeSafeRanker(client=Client())
        ranking = run_async(
            ranker.rank("recent critical detections", [_candidate("falcon_search_detections")])
        )
        self.assertIsNotNone(ranking)
        self.assertEqual(len(captured["questions"]), 3)
        self.assertEqual(captured["state"]["request"], "recent critical detections")
        self.assertAlmostEqual(ranking.scores["falcon_search_detections"], 2.0)

    def test_rank_returns_none_without_a_query(self):
        ranker = TypeSafeRanker(client=MagicMock())
        self.assertIsNone(run_async(ranker.rank("", [_candidate("falcon_search_detections")])))


class TestResolveSemanticRanker(unittest.TestCase):
    def test_requires_dynamic_mode(self):
        with self.assertRaises(ValueError) as ctx:
            resolve_semantic_ranker(dynamic=False)
        self.assertIn("--dynamic", str(ctx.exception))

    def test_requires_api_key(self):
        with patch.dict("os.environ", {}, clear=False):
            os.environ.pop("TYPESAFE_API_KEY", None)
            with self.assertRaises(ValueError) as ctx:
                resolve_semantic_ranker(dynamic=True)
        self.assertIn("TYPESAFE_API_KEY", str(ctx.exception))

    def test_requires_sdk_when_key_is_set(self):
        with patch.dict("os.environ", {"TYPESAFE_API_KEY": "test-key"}):
            with patch.dict("sys.modules", {"typesafe_sdk": None}):
                # ImportError path: pretend the package is missing.
                import builtins

                real_import = builtins.__import__

                def fake_import(name, *args, **kwargs):
                    if name == "typesafe_sdk":
                        raise ImportError("no typesafe")
                    return real_import(name, *args, **kwargs)

                with patch("builtins.__import__", side_effect=fake_import):
                    with self.assertRaises(ValueError) as ctx:
                        resolve_semantic_ranker(dynamic=True)
        self.assertIn("falcon-mcp[typesafe]", str(ctx.exception))


class TestParseArgsSemanticSearch(unittest.TestCase):
    @patch("sys.argv", ["falcon-mcp", "--semantic-search"])
    def test_parse_args_semantic_search_flag(self):
        from falcon_mcp.server import parse_args

        args = parse_args()
        self.assertTrue(args.semantic_search)

    @patch("sys.argv", ["falcon-mcp"])
    @patch.dict("os.environ", {"FALCON_MCP_SEMANTIC_SEARCH": "true"})
    def test_parse_args_semantic_search_env_var(self):
        from falcon_mcp.server import parse_args

        args = parse_args()
        self.assertTrue(args.semantic_search)

    @patch("sys.argv", ["falcon-mcp"])
    def test_parse_args_semantic_search_defaults_false(self):
        os.environ.pop("FALCON_MCP_SEMANTIC_SEARCH", None)
        from falcon_mcp.server import parse_args

        args = parse_args()
        self.assertFalse(args.semantic_search)


class TestServerSemanticSearch(unittest.TestCase):
    @patch("falcon_mcp.server.FalconClient")
    @patch("falcon_mcp.server.FastMCP")
    def test_injected_ranker_reaches_dynamic_mode(self, mock_fastmcp, mock_client):
        from falcon_mcp.server import FalconMCPServer

        mock_client.return_value.authenticate.return_value = True
        mock_fastmcp.return_value = MagicMock()
        ranker = FakeRanker(_ranking({}))
        server = FalconMCPServer(
            enabled_modules={"detections"},
            dynamic=True,
            semantic_ranker=ranker,
        )
        self.assertIs(server._dynamic_mode._ranker, ranker)
        instructions = mock_fastmcp.call_args.kwargs["instructions"]
        self.assertIn("semantic ranking", instructions)

    @patch("falcon_mcp.server.FalconClient")
    @patch("falcon_mcp.server.FastMCP")
    def test_semantic_search_without_dynamic_fails_before_auth(self, mock_fastmcp, mock_client):
        from falcon_mcp.server import FalconMCPServer

        with self.assertRaises(ValueError) as ctx:
            FalconMCPServer(
                enabled_modules={"detections"},
                dynamic=False,
                semantic_search=True,
            )
        self.assertIn("dynamic mode", str(ctx.exception))
        mock_client.return_value.authenticate.assert_not_called()


class TestCatalogExactName(unittest.TestCase):
    def test_is_exact_name_accepts_prefix_and_unprefixed(self):
        from falcon_mcp.dynamic import DynamicToolCatalog

        catalog = DynamicToolCatalog({"detections": DetectionsModule(MagicMock())})
        self.assertTrue(catalog.is_exact_name("falcon_search_detections"))
        self.assertTrue(catalog.is_exact_name("search_detections"))
        self.assertFalse(catalog.is_exact_name("detections"))


if __name__ == "__main__":
    unittest.main()
