import json
import pathlib
import re
import subprocess
from argparse import Namespace
from typing import Any, Dict, List, Optional


class CompileError(Exception):
    pass


def compile_ast(
    file_path: str, solc_bin: Optional[str], base_path: str, include_path_str_list: List[str], remappings: List[str]
) -> Dict[str, Any]:
    if solc_bin is None:
        solc_bin = "solc"
    include_path_args = " ".join("--include-path " + p for p in include_path_str_list)
    p = subprocess.run(
        f"{solc_bin} --combined-json ast --base-path {base_path} {include_path_args} {' '.join(remappings)} {file_path}",
        capture_output=True,
        shell=True,
    )
    if p.returncode != 0:
        raise CompileError(p.stdout.decode("utf-8") + "\n" + p.stderr.decode("utf-8"))
    return json.loads(p.stdout.decode("utf-8"))


def generate_standard_input_json(target_file_str: str, args: Namespace) -> Dict[str, Any]:
    if args.base_path is None:
        base_path = pathlib.Path.cwd()
    else:
        base_path = pathlib.Path(args.base_path).expanduser().resolve()
    remappings = get_remappings(base_path, args.remappings_file)
    include_path_str_list = args.include_path
    if not include_path_str_list and (base_path / "node_modules").is_dir():
        include_path_str_list = [str(base_path / "node_modules")]

    ast_json = compile_ast(target_file_str, args.solc_bin, str(base_path), include_path_str_list, remappings)

    sources = {}
    for file_name in ast_json["sourceList"]:
        file_path = (base_path / file_name).resolve()
        # NOTE safety check
        assert str(file_path).startswith(str(base_path))

        if not file_path.is_file():
            for include_path_str in include_path_str_list:
                include_path = pathlib.Path(include_path_str).expanduser().resolve()
                file_path = (include_path / file_name).resolve()
                # NOTE safety check
                assert str(file_path).startswith(str(include_path))
                if file_path.is_file():
                    break

        if not file_path.is_file():
            raise FileNotFoundError(f"cannot find '{file_name}' under <base_path> or <include_path>")

        with open(file_path) as f:
            file_content = f.read()
        sources[file_name] = dict(content=file_content)

    std_input_json = dict(
        language="Solidity",
        sources=sources,
        settings=dict(
            remappings=remappings,
        ),
    )

    return std_input_json


def get_remappings(base_path: pathlib.Path, remappings_file_str: Optional[str]) -> List[str]:
    if remappings_file_str is not None:
        remappings_file = pathlib.Path(remappings_file_str)
    elif (base_path / "remappings.txt").is_file():
        remappings_file = base_path / "remappings.txt"
    else:
        return []

    remappings = []
    with open(remappings_file) as f:
        for line in f:
            if not line.strip():
                continue
            remappings.append(line.strip())
    remappings.sort()
    return remappings


def compile_standard_json(
    std_input_json,
    contract_name: Optional[str] = None,
    solc_bin: Optional[str] = None,
    add_output_selection: Optional[bool] = None,
) -> Dict[str, Any]:
    for d in std_input_json["sources"].values():
        content = d["content"]
        content = re.sub(
            r"pragma\s+solidity\s+([<=>\^]{0,2}(\s*\d+\s*\.){2}\s*\d+\s*)+;",
            r"",
            content,
        )
        content = re.sub(r"uint(\d*)(\s*)\((\s*)-(\s*)1(\s*)\)", r"type(uint\1).max \2\3\4\5", content)
        d["content"] = content

    if "settings" not in std_input_json:
        std_input_json["settings"] = {}
    if add_output_selection is True or (
        add_output_selection is None
        and (contract_name is not None or "outputSelection" not in std_input_json["settings"])
    ):
        if contract_name is None:
            contract_name = "*"
        std_input_json["settings"]["outputSelection"] = {
            "*": {
                contract_name: ["ir"],
            }
        }
    else:
        assert "outputSelection" in std_input_json["settings"], "outputSelection not in standard input json"

    if solc_bin is None:
        solc_bin = "solc"
    p = subprocess.run(
        f"{solc_bin} --standard-json -",
        input=json.dumps(std_input_json).encode(),
        capture_output=True,
        shell=True,
    )
    if p.returncode != 0:
        raise CompileError(
            f"Compile Error: returncode = {p.returncode}\nstdout: {p.stdout.decode('utf-8')}\nstderr: {p.stderr.decode('utf-8')}"
        )
    std_json = json.loads(p.stdout.decode())
    if "contracts" not in std_json:
        errors = [err.get("formattedMessage") for err in std_json["errors"] if err.get("severity") == "error"]
        raise CompileError(f"Compile Error: {json.dumps(errors)}")

    return std_json
