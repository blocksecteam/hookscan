from typing import Dict, List

from hookscan.detectors.uniswap_hook.uniswap_public_callback import UniswapPublicCallback
from hookscan.detectors.uniswap_hook.uniswap_public_hook import UniswapPublicHook
from hookscan.detectors.uniswap_hook.uniswap_suicidal_hook import UniswapSuicidalHook
from hookscan.detectors.uniswap_hook.uniswap_upgradable_hook import UniswapUpgradableHook

all_detectors: List[type] = [
    UniswapPublicCallback,
    UniswapPublicHook,
    UniswapSuicidalHook,
    UniswapUpgradableHook,
]

all_detectors_dict: Dict[str, type] = {detector.__name__: detector for detector in all_detectors}
