FROM python:3.8-slim

ENV SOLC_PATH=/solc
ENV UNISCAN_PATH=/uniscan
ENV FOUNDRY_DIR=/foundry

WORKDIR $UNISCAN_PATH

# install solc>=0.8.14
RUN apt-get update && apt-get install -y curl jq wget
RUN curl -H "Accept: application/vnd.github.v3+json" https://api.github.com/repos/ethereum/solidity/releases \
    | jq -r '.[] | select(.tag_name | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")) \
        | select((.tag_name | ltrimstr("v")) | split(".") \
        | map(tonumber) >= [0, 8, 14]) | .tag_name' \
    | xargs -P 8 -I {} sh -c "mkdir -p $SOLC_PATH/{}; \
        wget -O $SOLC_PATH/{}/solc https://github.com/ethereum/solidity/releases/download/{}/solc-static-linux; \
        chmod +x $SOLC_PATH/{}/solc"

# install foundry
RUN apt-get install -y git
RUN curl -L https://foundry.paradigm.xyz | bash
RUN $FOUNDRY_DIR/bin/foundryup

# copy repo
COPY . .

# install pypi dependencies
RUN pip install --no-cache-dir -r requirements.txt

# move and chmod entrypoint.sh
RUN mv $UNISCAN_PATH/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# cleanup
RUN apt-get remove -y curl jq wget git
RUN apt-get autoremove -y

# set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
