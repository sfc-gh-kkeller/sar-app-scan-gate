FROM python:3.12-slim
RUN pip install --no-cache-dir "snowflake-cli==3.27.*" "pyyaml==6.0.2" \
 && useradd -m -u 1001 gate
COPY scanner/gate.py /gate/scanner/gate.py
COPY publisher/publish.py /gate/publisher/publish.py
ENV HOME=/home/gate SNOWFLAKE_HOME=/home/gate/.snowflake
USER gate
ENTRYPOINT ["python3", "/gate/publisher/publish.py"]
