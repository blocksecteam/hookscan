import json
from typing import Any, Dict, Optional, Union

from hookscan.components.function import Function, FunctionType
from hookscan.components.instruction import Instruction
from hookscan.core.instruction_instance import ValueInstance


class DetectorResult:
    def __init__(
        self,
        target: Union[ValueInstance, Function],
        severity: str,
        confidence: str,
        additional_info: Optional[Any] = None,
    ) -> None:
        self._target = target
        assert severity in {"high", "medium", "low", "info"}, "unknown severity"
        self.severity = severity
        assert confidence in {"high", "medium", "low"}, "unknown confidence"
        self.confidence = confidence
        self.additional_info = additional_info

        self._target_id: int

        self.external_function_name = None
        self.function_selector = None
        self.call_stack = None
        self.yul_source_map = None
        self.source_code_info = None

        if isinstance(target, ValueInstance):
            self._target_id = target.value.id
            info = target.info
            if info is not None:
                self.external_function_name = info.entry_point_function.solidity_name  # pyright: ignore
                self.function_selector = info.current_function_selector
                self.call_stack = info.get_call_stack_functions()
            if isinstance(target.value, Instruction):
                self.yul_source_map = target.value.yul_source_map
                self.source_code_info = target.value.source_code_info
        elif isinstance(target, Function):
            assert target.type == FunctionType.EXTERNAL
            self._target_id = target.id
            self.external_function_name = target.solidity_name
            self.function_selector = target.selector
            self.yul_source_map = target.yul_source_map
            self.source_code_info = target.source_code_info
        else:
            raise Exception(f"unsupported target type: {type(target)}")

    def __eq__(self, __o: "DetectorResult"):
        return self.__hash__() == __o.__hash__()

    def __hash__(self):
        return hash(
            (
                self._target_id,
                self.function_selector,
                self.additional_info,
            )
        )

    def __repr__(self):
        return json.dumps(self.to_json_dict())

    def __str__(self):
        return json.dumps(self.to_json_dict())

    def to_json_dict(self) -> Dict[str, Any]:
        """Convert to json compatible dict."""
        output_json = {}
        output_json["external_function"] = self.external_function_name
        if self.function_selector is not None:
            if self.function_selector == "FALLBACK":
                output_json["function_selector"] = "(FALLBACK_OR_RECEIVE)"
            else:
                output_json["function_selector"] = f"{self.function_selector:#010x}"
        if self.call_stack is not None:
            output_json["yul_call_stack"] = [f.name for f in self.call_stack]
        if self.source_code_info is not None:
            file_name = self.source_code_info["file_name"]
            row_number = self.source_code_info["row_number"]
            output_json["source_location"] = f"{file_name}:{row_number}"
        output_json["severity"] = self.severity
        output_json["confidence"] = self.confidence
        if self.additional_info is not None:
            output_json["additional_info"] = self.additional_info
        return output_json
