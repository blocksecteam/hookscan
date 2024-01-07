#!/bin/bash

PROJECT_PATH=/project
SCANNER=scanner

HOST_UID=$(stat -c "%u" $PROJECT_PATH)
HOST_GID=$(stat -c "%g" $PROJECT_PATH)
groupadd -g $HOST_GID $SCANNER && useradd -u $HOST_UID -g $HOST_GID $SCANNER
chown -R $SCANNER:$SCANNER $UNISCAN_PATH

# set base path
ARGS=(--base-path $PROJECT_PATH)

# set solc bin path
if [ -z "$SOLC_VERSION" ]; then
   SOLC_VERSION=0.8.19
fi
SOLC_PATH=$SOLC_PATH/v$SOLC_VERSION/solc
ARGS+=(--solc-bin $SOLC_PATH)

# add external args
ARGS+=($@)

# set the input contract
ARGS+=($PROJECT_PATH/$CONTRACT)

# forge build
su -c "$FOUNDRY_DIR/bin/forge build --root $PROJECT_PATH --use $SOLC_PATH" $SCANNER

# run uniscan
echo "uniscan arg list: ${ARGS[@]}"
su -c "python -m uniscan `echo ${ARGS[@]}`" $SCANNER
