#!/bin/bash

SOLC_VERSION=${SOLC_VERSION:-0.8.21}
PROJECT_PATH=/project

ARGS=(--base-path $PROJECT_PATH $PROJECT_PATH/$CONTRACT)

if [ "${SOLC_VERSION:=""}" ]; then
   SOLC_VERSION=0.8.19
fi
ARGS=(--solc-bin $HOME/.solc-select/artifacts/solc-$SOLC_VERSION/solc-$SOLC_VERSION ${ARGS[@]})

echo "arg list: ${ARGS[@]}"

python -m uniscan "${ARGS[@]}"
