#!/bin/bash

PROJECT_PATH=/project

# set base path
ARGS=(--base-path $PROJECT_PATH)

# set solc bin path
if [ "${SOLC_VERSION:=""}" ]; then
   SOLC_VERSION=0.8.19
fi
ARGS+=(--solc-bin $SOLC_PATH/v$SOLC_VERSION/solc)

# add external args
ARGS+=($@)

# set the input contract
ARGS+=($PROJECT_PATH/$CONTRACT)

echo "arg list: ${ARGS[@]}"

python -m uniscan "${ARGS[@]}"
