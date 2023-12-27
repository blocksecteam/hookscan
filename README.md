# UniScan

UniScan is an automated static analyzer designed specifically for [Uniswap v4](https://blog.uniswap.org/uniswap-v4) hooks.
Its purpose is to identify the most prevalent and severe vulnerabilities within Uniswap v4 hooks that are susceptible to malicious manipulation.

UniScan is based on Phalcon Inspector, a powerful static analysis framework developed by BlockSec.
Phalcon Inspector will also be open-sourced and announced in the future.

## Get started

### Prerequisite

```bash
solc>=0.8.14
python>=3.8

pip install -r requirements.txt
```

### Usage

```bash
# [optional] for foundry projects, fetch dependencies before running UniScan
cd path/to/foundry/project
forge build

# simple usage
PYTHONPATH=path/to/this/repo python -m uniscan path/to/source_file.sol:ContractName

# help
PYTHONPATH=path/to/this/repo python -m uniscan --help
```

## Detector Spec

| **Detector**            | **Description**                                                                          | **Severity** | **Confidence** |
| ----------------------- | ---------------------------------------------------------------------------------------- | ------------ | -------------- |
| `UniswapPublicHook`     | callers of hook functions are not exclusively<br />restricted to the pool manager alone  | High         | High           |
| `UniswapPublicCallback` | callers of callback functions are not exclusively<br />restricted to the contract itself | High         | High           |
| `UniswapUpgradableHook` | the contract `DELEGATECALL`s to mutable addresses                                        | High         | High           |
| `UniswapSuicidalHook`   | the contract contains `SELFDESTRUCT`                                                     | Medium       | High           |

## Evaluation

We've conducted tests on 13 hook contracts associated with Uniswap v4, as listed in the compilation [awesome-uniswap-hook](https://github.com/hyperoracle/awesome-uniswap-hooks), all of which compiled without errors.
The test results are as follows:

| **Detector**            | **TP/ground_truth** |
| ----------------------- | ------------------- |
| `UniswapPublicHook`     | 7/7 contracts       |
| `UniswapPublicCallback` | 3/3 contracts       |
| `UniswapUpgradableHook` | 0                   |
| `UniswapSuicidalHook`   | 0                   |
