import argparse
import copy
import csv
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
BRANCHES = ("next", "next2")


def loaded_actions(actions, path, disabled=False):
    output = []
    for index in reversed(range(len(actions))):
        original = actions[index]
        action = copy.deepcopy(original)
        source_path = f"{path}[{index}]"
        effective_disabled = disabled or bool(original.get("disabled", False))
        action["source_path"] = source_path
        action["effective_disabled"] = effective_disabled
        for branch in BRANCHES:
            if branch in original:
                action[branch] = loaded_actions(
                    original[branch], f"{source_path}.{branch}", effective_disabled
                )
        output.append(action)
    return output


def walk(actions, depth=0):
    for action in actions:
        yield action, depth
        for branch in BRANCHES:
            yield from walk(action.get(branch, []), depth + 1)


def render(actions, lines, indent=0):
    for action in actions:
        fields = {key: value for key, value in action.items() if key not in BRANCHES}
        lines.append("  " * indent + json.dumps(fields, ensure_ascii=False))
        for branch in BRANCHES:
            if action.get(branch):
                lines.append("  " * (indent + 1) + branch + ":")
                render(action[branch], lines, indent + 2)


def main():
    parser = argparse.ArgumentParser(description="Static action loader-order analysis; never executes macros")
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "analysis/purchase_logic")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    original = json.loads((ROOT / "recovered_source/macro.readable.json").read_text(encoding="utf-8"))
    transformed = {
        name: loaded_actions(original.get(name, []), f"$.{name}")
        for name in ("actionsEntry", "actions", "actionsEnding")
    }
    (args.output / "actions.execution_order.json").write_text(
        json.dumps(transformed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "Static loader-order tree, not a linear runtime trace.",
        "Native loader RVA 0xb3790 traverses packed arrays from end to start.",
        "Branches, loops, jumps, blocks and disabled ancestors still control execution.",
        "source_path refers to the ORIGINAL macro.readable.json, before reversal.",
    ]
    rows = []
    for name, actions in transformed.items():
        lines.append(name + ":")
        render(actions, lines, 1)
        rows.extend(action for action, depth in walk(actions))
    (args.output / "actions.execution_order.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with (args.output / "ocr_regions.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        fields = ["source_path", "effective_disabled", "variable", "text", "rect", "row", "match", "mark"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for action in rows:
            if action["type_name"] == "ocr":
                record = {key: action.get(key, "") for key in fields}
                record["rect"] = json.dumps(record["rect"])
                writer.writerow(record)
    summary = {
        "method": "Static native-loader order; not a runtime trace",
        "native_loader_rva": "0xb3790",
        "action_count": len(rows),
        "effective_disabled_count": sum(action["effective_disabled"] for action in rows),
        "ocr_count": sum(action["type_name"] == "ocr" for action in rows),
        "ocr_not_disabled": sum(action["type_name"] == "ocr" and not action["effective_disabled"] for action in rows),
        "color_count": sum(action["type_name"] == "color" for action in rows),
        "color_not_disabled": sum(action["type_name"] == "color" and not action["effective_disabled"] for action in rows),
        "block_definitions": [
            {key: action.get(key) for key in ("id", "mark", "source_path", "effective_disabled")}
            for action in rows if action["type_name"] == "block"
        ],
        "block_calls": [
            {key: action.get(key) for key in ("id", "source_path", "effective_disabled")}
            for action in rows if action["type_name"] == "blockExec"
        ],
    }
    (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in summary.items() if not isinstance(value, list)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
