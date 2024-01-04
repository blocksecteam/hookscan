FROM python:3.8-slim

ENV SOLIDITY_REPO=/solidity
ENV SOLC_PATH=/solc

# install solc>=0.8.14
# RUN apt-get update && apt-get install -y curl jq wget
# RUN curl -H "Accept: application/vnd.github.v3+json" https://api.github.com/repos/ethereum/solidity/releases \
#     | jq -r '.[] | select(.tag_name | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")) | select((.tag_name | ltrimstr("v")) | split(".") | map(tonumber) >= [0, 8, 14]) | .tag_name' \
#     | xargs -P 8 -I {} sh -c "mkdir -p $SOLC_PATH/{}; wget -O $SOLC_PATH/{}/solc https://github.com/ethereum/solidity/releases/download/{}/solc-static-linux; chmod +x $SOLC_PATH/{}/solc"

# build solc>=0.8.14
RUN apt-get update && apt-get install -y git cmake g++ libboost-all-dev
RUN git clone https://github.com/ethereum/solidity $SOLIDITY_REPO
WORKDIR $SOLIDITY_REPO
RUN touch prerelease.txt
RUN git tag -l 'v[0-9]*' | grep -E "^(v)?([0-9]+\.){1,2}(8\.(1[4-9]|[2-9][0-9])|[9-9]\.[0-9]+)" \
    | xargs -I {} sh -c "git checkout {}; mkdir -p build; cd build; \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DTESTS=0 -DSOLC_LINK_STATIC=1 && make -j $(nproc --all) solc; \
    mkdir -p $SOLC_PATH/{}; mv solc/solc $SOLC_PATH/{}/solc; cd ..; rm -rf build"

# change workdir
WORKDIR /uniscan

# copy repo
COPY . .

# install pypi dependencies
RUN pip install --no-cache-dir -r requirements.txt

# chmod entrypoint.sh
RUN chmod +x scripts/entrypoint.sh

# cleanup
# RUN apt-get remove -y curl jq wget
RUN apt-get remove -y git cmake g++ libboost-all-dev
RUN apt-get autoremove -y
RUN rm -rf $SOLIDITY_REPO

# set entrypoint
ENTRYPOINT ["/uniscan/scripts/entrypoint.sh"]
