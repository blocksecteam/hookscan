#!/bin/bash

PROJECT_PATH=/project

ARGS=(--base-path $PROJECT_PATH $PROJECT_PATH/$CONTRACT)

if [ "${SOLC_VERSION:=""}" ]; then
   SOLC_VERSION=0.8.19
fi
ARGS=(--solc-bin $SOLC_PATH/v$SOLC_VERSION/solc ${ARGS[@]})

echo "arg list: ${ARGS[@]}"

python -m uniscan "${ARGS[@]}"
