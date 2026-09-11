"""Unit tests for overflow slicing and snapshot storage."""

import unittest

from falcon_mcp.common.overflow import (
    OverflowStore,
    bound_result,
    coerce_max_chars,
    mcp_size,
    record_id,
)


def _fat(i: int, blob: int = 400) -> dict:
    return {
        "composite_id": f"det:{i}",
        "severity": 50,
        "status": "new",
        "blob": "x" * blob,
    }


class TestCoerceAndIds(unittest.TestCase):
    def test_invalid_budget_becomes_default(self):
        self.assertEqual(coerce_max_chars("nope"), 25_000)
        self.assertGreaterEqual(coerce_max_chars(10, cli=True), 2_000)

    def test_record_id_prefers_composite(self):
        self.assertEqual(
            record_id({"composite_id": "a", "id": "b", "blob": "z"}),
            "a",
        )


class TestBoundResult(unittest.TestCase):
    def setUp(self):
        self.owner = object()
        self.store = OverflowStore(max_bytes=2_000_000, ttl_seconds=60)

    def test_small_search_envelope_is_unchanged(self):
        raw = {
            "results": [_fat(1, 20)],
            "pagination": {"total": 1, "next": "cursor-1"},
        }
        out = bound_result(raw, 25_000, self.store, self.owner)
        self.assertIs(out, raw)
        self.assertNotIn("overflow", out)

    def test_small_bare_list_is_unchanged(self):
        raw = [_fat(1, 20), _fat(2, 20)]
        out = bound_result(raw, 25_000, self.store, self.owner)
        self.assertIs(out, raw)

    def test_oversized_page_keeps_prefix_and_freezes_cursor(self):
        rows = [_fat(i, 300) for i in range(20)]
        raw = {
            "results": rows,
            "pagination": {"total": 20, "next": "page-2", "offset": 0, "limit": 20},
        }
        out = bound_result(raw, 2_500, self.store, self.owner)
        self.assertIn("overflow", out)
        self.assertGreater(len(out["results"]), 0)
        self.assertLess(len(out["results"]), 20)
        self.assertIsNone(out["pagination"]["next"])
        self.assertTrue(out["overflow"]["upstream_cursor"])
        self.assertEqual(out["overflow"]["offset"], len(out["results"]))
        self.assertEqual(out["overflow"]["remaining"], 20 - len(out["results"]))
        self.assertTrue(out["overflow"]["handle"])
        self.assertLessEqual(mcp_size(out), 2_500)

        continued = bound_result(
            raw,
            2_500,
            self.store,
            self.owner,
            offset=out["overflow"]["offset"],
            handle=out["overflow"]["handle"],
        )
        recovered = out["results"] + continued["results"]
        self.assertGreater(len(recovered), len(out["results"]))
        self.assertEqual(recovered[0]["composite_id"], "det:0")

    def test_single_huge_record_uses_character_slices(self):
        raw = {"sandbox": "y" * 8_000, "id": "report-1"}
        out = bound_result(raw, 1_200, self.store, self.owner)
        self.assertEqual(out["overflow"]["unit"], "characters")
        self.assertIn("text", out["overflow"])
        self.assertTrue(out["overflow"]["handle"])
        self.assertLessEqual(mcp_size(out), 1_200)

        chunks = [out["overflow"]["text"]]
        char_offset = out["overflow"]["next_char_offset"]
        while char_offset is not None:
            nxt = bound_result(
                raw,
                1_200,
                self.store,
                self.owner,
                char_offset=char_offset,
                handle=out["overflow"]["handle"],
            )
            chunks.append(nxt["overflow"]["text"])
            char_offset = nxt["overflow"]["next_char_offset"]
        self.assertIn("sandbox", "".join(chunks))

    def test_huge_cursor_stays_out_of_the_overflow_footer(self):
        raw = {
            "results": [_fat(i, 80) for i in range(8)],
            "pagination": {"total": 8, "next": "C" * 12_000},
        }
        out = bound_result(raw, 2_500, self.store, self.owner)
        self.assertIn("overflow", out)
        self.assertTrue(out["overflow"]["upstream_cursor"])
        self.assertNotIn("upstream_next", out["overflow"])
        self.assertLessEqual(mcp_size(out), 2_500)
        self.assertTrue(out["overflow"]["handle"])

    def test_first_record_too_big_keeps_leftover_ids(self):
        raw = {
            "results": [_fat(0, 4_000), _fat(1, 20), _fat(2, 20)],
            "pagination": {"next": "n"},
        }
        out = bound_result(raw, 900, self.store, self.owner)
        self.assertEqual(out["overflow"]["unit"], "characters")
        self.assertIn("det:1", out["overflow"]["ids"])

    def test_stateless_owner_omits_handle_but_keeps_ids(self):
        rows = [_fat(i, 300) for i in range(15)]
        raw = {"results": rows, "pagination": {"next": "n"}}
        out = bound_result(raw, 2_000, self.store, None)
        self.assertIn("overflow", out)
        self.assertIsNone(out["overflow"]["handle"])
        self.assertTrue(out["overflow"]["ids"])

    def test_store_rejects_other_session(self):
        store = OverflowStore(max_bytes=50_000, ttl_seconds=60)
        owner = object()
        handle = store.put(owner, {"results": [1]})
        self.assertIsNotNone(handle)
        with self.assertRaises(ValueError):
            store.get(object(), handle)


if __name__ == "__main__":
    unittest.main()
