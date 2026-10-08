FROM python:3.12-slim
# Semgrep runs fully offline: local rules, --metrics=off, no EAI on the job.
RUN pip install --no-cache-dir "semgrep==1.180.0" "pyyaml==6.0.2" \
 && useradd -m -u 1001 gate
WORKDIR /gate
COPY rules/ /gate/rules/
COPY scanner/gate.py scanner/rewrite.py scanner/check_app.py scanner/job.py /gate/scanner/
ENV GATE_RULES=/gate/rules SEMGREP_SEND_METRICS=off HOME=/home/gate
USER gate
ENTRYPOINT ["python3", "/gate/scanner/job.py"]
