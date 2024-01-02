FROM python:3.8-slim

WORKDIR /uniscan

# install solc>=0.8.14
RUN pip install solc-select
RUN solc-select install | awk '{ gsub(/[^0-9.]/, "", $1); if ($1 > "0.8.14") print $1 }' | xargs -P8 solc-select install

# copy repo
COPY . .

# install pypi denpendencies
RUN pip install --no-cache-dir -r requirements.txt

# chmod entrypoint.sh
RUN chmod +x scripts/entrypoint.sh

# set entrypoint
ENTRYPOINT ["/uniscan/scripts/entrypoint.sh"]
