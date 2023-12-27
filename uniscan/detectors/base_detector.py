from typing import TYPE_CHECKING, Any, Dict, Hashable, Iterable, List, MutableSet, Optional, Type, Union

from uniscan.components.evm_instructions import Call, Callcode, Delegatecall, Revert, Staticcall
from uniscan.components.instruction import Instruction, UnreachableInst
from uniscan.core.instruction_instance import ValueInstance
from uniscan.utils.ordered_set import OrderedSet as set

if TYPE_CHECKING:
    from uniscan.core.traversal_info import TraversalInfo
    from uniscan.detectors.detector_result import DetectorResult


class BaseDetector:
    # NOTE describe the vulnerability detected by this detector
    VULNERABILITY_DESCRIPTION = ""

    def __init__(self) -> None:
        self.register_traverse_event: bool = True
        self.callback_keys: Iterable[Type[Instruction]]
        self.traversal_rounds_and_dependency: Dict[int, tuple[Type["BaseDetector"]]] = {0: ()}

    def get_internal_result(self) -> List["DetectorResult"]:
        """Get the detector's result as intermediate result in framework."""
        return []

    def get_external_result(self) -> List["DetectorResult"]:
        """Get the detector's result as output."""
        return []

    def callback(self, info: "TraversalInfo", inst_instance: ValueInstance, is_end: bool):
        """Trigger detector's callback method while traversing.

        Note:
            The function will be triggered when meeting this instruction in traversing, if the type(instruction) is registered in callback_keys.
            And if this detector is triggered in the path, it will trigger this method again at the end of the path with is_end == True.
            Detector should override this method.

        Args:
            info (TraversalInfo): the current traversal_info
            inst_instance (ValueInstance): hooked value instance
            is_end (bool): at the end of the path or not

        """
        pass

    def traverse_start(self, info: "TraversalInfo", current_round: int):  # noqa: B027
        self.current_round = current_round
        """At the start of traversing every round, trigger this method.

        Args:
            info (TraversalInfo): the current traversal_info
            current_round:  relative round of this detector

        """

        pass  # noqa: B027

    def traverse_stop(self, info: "TraversalInfo", current_round: int):  # noqa: B027
        """At the end of traversing every round, trigger this method.

        Args:
            info (TraversalInfo): the current traversal_info
            current_round:  relative round of this detector

        """

        pass  # noqa: B027

    def get_call_signature(self, vi: ValueInstance) -> Union[None, int]:
        """To get signature about a call/callcode/staticallcall/delegatecall value instance.

        Args:
            vi (ValueInstance): call/staticcall/callcode/delegatecall value instance

        Returns:
            Union[None, int]: if getting the signature successfully, it will return the signature(int)

        """
        if isinstance(vi.value, (Call, Callcode, Staticcall, Delegatecall)):
            return vi.function_signature
        else:
            return None

    def set_detector_info(self, info: "TraversalInfo", input_info: Any):
        """Record information about current path in detector instance.

        Args:
            info (TraversalInfo): the current traversal_info
            input_info (Any): the information will be recorded
        """
        path_node = info.path[-1]
        pre_detector_info = path_node.detector_info_dict[self.__class__]
        new_detector_info = pre_detector_info.copy()
        new_detector_info.append(input_info)
        path_node.detector_info_dict[self.__class__] = new_detector_info

    def get_detector_info(
        self, info: "TraversalInfo", detector_type: Optional[Type["BaseDetector"]] = None
    ) -> List[Any]:
        """To get current path information stored in this or other detector instance.

        Args:
            info (TraversalInfo): the current traversal_info
            detector_type (Optional[Type[BaseDetector]]): target detector's class

        Returns:
            List[Any]: the path information stored in target detector instance
        """

        detector_type = self.__class__ if detector_type is None else detector_type
        return info.path[-1].detector_info_dict[self.__class__]

    def get_call_args_member(self, vi: ValueInstance, index: int) -> Optional[ValueInstance]:
        """To get the call arguments.

        Args:
            vi (ValueInstance): the call(call/staticcall/delegetecall/callcode) value instance
            index (int): the requested argument's index, starts with 0

        Returns:
            Optional[ValueInstance]: the call argument value instance if successfully

        """
        if isinstance(vi.value, (Call, Staticcall, Delegatecall, Callcode)):
            if index > len(vi.call_args) - 1:
                return None
            return vi.call_args[index].origin
        else:
            raise Exception("get_call_args_member input vi should be a call instance")

    def terminated_by_revert(self, info: "TraversalInfo") -> bool:
        assert isinstance(info.current_inst, UnreachableInst), "not is_end"
        if isinstance(info.current_path_node.inst_instances[-2].value, Revert):
            return True
        return False

    def add_taint(self, info: "TraversalInfo", vi: ValueInstance, taint: Any, additional_info: Hashable = None):
        """Add taint to value instance, which is isolated by detector instance.

        Args:
            info (TraversalInfo): the current traversal_info
            vi (ValueInstance): the value instance which will be added taint and must be current value instance in the path
            taint (Any): the taint to be added
            additional_info (Hashable): additional info

        """
        assert info.current_inst_instance is vi
        taint_tuple = (self.__class__, taint, additional_info)
        vi.taints.add(taint_tuple)

    def get_taints(self, vi: ValueInstance, target_detector: Optional[Type["BaseDetector"]] = None) -> MutableSet[Any]:
        """Get taints recorded in the vi, both of basic taint added by framework and detector's taint.

        Args:
            vi (ValueInstance): value instance
            target_taint (Any): to get taints from which detector instance, default self-detector

        Returns:
            MutableSet[Any]: taints
        """
        if target_detector is None:
            target_detector = self.__class__
        ret_taints = set()
        for taint in vi.taints:
            if isinstance(taint, tuple):
                if taint[0] == target_detector:
                    assert taint[1] not in ret_taints
                    ret_taints.add(taint[1])
            else:
                assert taint not in ret_taints
                ret_taints.add(taint)
        return ret_taints

    def taint_in(
        self,
        vi: ValueInstance,
        target_taint: Any,
        target_detector: Optional[Type["BaseDetector"]] = None,
    ) -> bool:
        """Check whether vi has target taint or not.

        Args:
            vi (ValueInstance): the vi to be checked
            target_taint (Any): the taint to be checked
            target_detector (Type[BaseDetector]): check taints from which detector instance, default self-detector

        """
        if target_detector is None:
            target_detector = self.__class__
        for taint in vi.taints:
            if isinstance(taint, tuple):
                if taint[0] == target_detector and taint[1] == target_taint:
                    return True
            elif taint == target_taint:
                return True
        return False
