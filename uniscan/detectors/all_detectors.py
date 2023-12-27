from uniscan.detectors.uniswap_hook.uniswap_public_callback import UniswapPublicCallback
from uniscan.detectors.uniswap_hook.uniswap_public_hook import UniswapPublicHook
from uniscan.detectors.uniswap_hook.uniswap_suicidal_hook import UniswapSuicidalHook
from uniscan.detectors.uniswap_hook.uniswap_upgradable_hook import UniswapUpgradableHook

all_detectors = [
    UniswapPublicCallback,
    UniswapPublicHook,
    UniswapSuicidalHook,
    UniswapUpgradableHook,
]

all_detectors_dict = {detector.__name__: detector for detector in all_detectors}
