import copy
import json
import unittest

from analyze_purchase_logic import ROOT, loaded_actions, walk


class LoaderOrderChecks(unittest.TestCase):
    def test_reverse_only_action_arrays(self):
        original = [
            {"id": 1, "rect": [1, 2, 3, 4], "script": "first()\nsecond()", "next": [{"id": 2}, {"id": 3}]},
            {"id": 4, "next2": [{"id": 5}, {"id": 6}]},
        ]
        before = copy.deepcopy(original)
        result = loaded_actions(original, "$.actions")
        self.assertEqual([action["id"] for action in result], [4, 1])
        self.assertEqual([action["id"] for action in result[1]["next"]], [3, 2])
        self.assertEqual([action["id"] for action in result[0]["next2"]], [6, 5])
        self.assertEqual(result[1]["rect"], [1, 2, 3, 4])
        self.assertEqual(result[1]["script"], "first()\nsecond()")
        self.assertEqual(result[1]["next"][0]["source_path"], "$.actions[0].next[1]")
        self.assertEqual(original, before)

    def test_disabled_ancestors_are_preserved(self):
        result = loaded_actions([{"disabled": True, "next": [{"id": 1}]}], "$.actions")
        self.assertTrue(result[0]["next"][0]["effective_disabled"])

    def test_complete_macro_count_and_start(self):
        original = json.loads((ROOT / "recovered_source/macro.readable.json").read_text(encoding="utf-8"))
        total = 0
        for name in ("actionsEntry", "actions", "actionsEnding"):
            result = loaded_actions(original.get(name, []), f"$.{name}")
            total += len(list(walk(result)))
        self.assertEqual(total, 2281)
        result = loaded_actions(original["actions"], "$.actions")
        self.assertEqual(result[0]["condition"], "动态延迟")
        self.assertEqual(result[-1]["mark"], "提前打开逻辑")
        self.assertEqual(result[-1]["next"][-1]["type_name"], "timer")


if __name__ == "__main__":
    unittest.main()
