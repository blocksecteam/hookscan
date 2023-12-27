import argparse
import json
import os
import sys
import traceback
from argparse import Namespace
from json import JSONEncoder
from typing import Any, Dict, Optional, Tuple

from uniscan.components.instruction import Instruction
from uniscan.detectors.all_detectors import all_detectors, all_detectors_dict
from uniscan.detectors.detector_result import DetectorResult
from uniscan.uniscan import Uniscan
from uniscan.utils.cfg_visualizer import generate_cfg
from uniscan.utils.compiler import compile_standard_json, generate_standard_input_json


class UniscanJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Instruction):
            return obj.__repr__()
        if isinstance(obj, DetectorResult):
            return obj.to_json_dict()
        if isinstance(obj, set):
            return list(obj)
        return JSONEncoder.default(self, obj)


def handle_input(args) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any], Optional[str]]:
    """
    Convert various input types to standard json.
    """

    if ":" in args.input:
        # TODO support windows drive letter colon
        file_path, target = args.input.split(":")
        assert args.contract is None or args.contract == target
    else:
        file_path, target = args.input, args.contract
    if file_path == "-" or file_path.endswith(".json"):
        if file_path == "-":
            std_json: Dict[str, Any] = json.load(sys.stdin)
        else:
            with open(file_path) as f:
                std_json = json.load(f)
        if "contracts" not in std_json:
            # NOTE standard input json
            std_input_json = std_json
            std_output_json = compile_standard_json(std_input_json, target)
        else:
            std_input_json = None
            std_output_json = std_json
    elif file_path.endswith(".sol"):
        std_input_json = generate_standard_input_json(file_path, args)
        std_output_json = compile_standard_json(std_input_json, target)
    else:
        raise Exception(f"invalid input file: {file_path}")
    return std_input_json, std_output_json, target


def parse_cli_args() -> Namespace:
    parser = argparse.ArgumentParser(prog="uniscan", description="vulnerability detection tool for Solidity")

    parser.add_argument(
        "input",
        metavar="INPUT_FILE[:CONTRACT_NAME]",
        help='input file (standard input/output json or sol), use "-" for stdin, contract name is optional',
    )

    parser.add_argument(
        "-m", "--mode", default="detect", choices=["detect", "cfg"], help="detect or cfg (default: detect)"
    )
    parser.add_argument("-c", "--contract", help="the name of contract to be detected (optional)")
    parser.add_argument(
        "-d",
        "--detector",
        metavar="D1,D2,...",
        help=f"detector names splitted by comma (default: all detectors). supported detectors: {[d.__name__ for d in all_detectors]}",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="OUTPUT_FILE",
        help="output file (for detect mode) or directory (for cfg mode), default: using stdout in detect mode",
    )
    parser.add_argument("--timeout-limit-per-round", type=float, help="timeout limit per round, default: 60 seconds")

    parser.add_argument("--solc-bin", default="solc", help="solc binary path (optional)")
    parser.add_argument(
        "--base-path", help="solc base path, usually the project dir, default: current working directory"
    )
    parser.add_argument(
        "--include-path",
        action="append",
        default=[],
        help='solc include path (optional), can be used multiple times, default: "node_modules" under base path if exists',
    )
    parser.add_argument(
        "--remappings-file", help='solc remappings file (optional), default: "remappings.txt" under base path if exists'
    )

    parser.add_argument("--overwrite", action="store_true", help="overwrite existing output file")
    parser.add_argument("--silent", action="store_true", help="suppress exception and output error message")
    parser.add_argument("--only-run-not-protected", action="store_true", help="only run not protected path")

    args = parser.parse_args()
    return args


def execute_and_output(args: Namespace) -> None:
    try:
        std_input_json, std_output_json, contract_name = handle_input(args)

        uniscan = Uniscan(
            std_output_json,
            contract_name=contract_name,
            std_in_json=std_input_json,
            only_run_not_protected=args.only_run_not_protected,
            timeout_limit_per_round=args.timeout_limit_per_round,
        )

        if args.mode == "cfg":
            assert args.output and os.path.isdir(args.output), f"CFG output should be directory but not: {args.output}"
            generate_cfg(uniscan.contract, f"{args.output}/{uniscan.contract.file_name}", render=True)
            return

        assert args.mode == "detect"
        if args.detector is None:
            detectors = all_detectors
        else:
            detectors = []
            for detector_str in args.detector.split(","):
                assert detector_str in all_detectors_dict, f"unknown detector: {detector_str}"
                detectors.append(all_detectors_dict[detector_str])
        uniscan.register_detectors(detectors)
        result = uniscan.detect()
        detection_results = []
        for k, v in result["detection_results"].items():
            for item in v:
                d = {
                    "detector_name": k.__name__,
                    "vulnerability": k.VULNERABILITY_DESCRIPTION,
                }
                d.update(item.to_json_dict())
                detection_results.append(d)
        result["detection_results"] = detection_results

    except Exception as e:
        if args.mode == "cfg" or not args.silent:
            raise
        result = {
            "error": traceback.format_exc(),
            "error_type": type(e).__name__,
        }

    if args.output:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        if os.path.exists(args.output) and not args.overwrite:
            raise Exception(f"output file exist: {args.output}, add --overwrite to force output.")
        with open(args.output, "w") as of:
            json.dump(result, of, indent=4, cls=UniscanJSONEncoder)
    else:
        print(json.dumps(result, indent=4, cls=UniscanJSONEncoder))


if __name__ == "__main__":
    args = parse_cli_args()
    execute_and_output(args)
