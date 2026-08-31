# execution-tool Python SDK — thin client over executiond (Phase 3)
# pip: execution-tool-sdk (scaffold)
#   from execution_tool_sdk import ExecutionClient
#   c = ExecutionClient("http://localhost:3000")
#   print(c.execute("shell", {"program": "/bin/echo", "args": ["hi"]}))
#   for event, data in c.stream("shell", {"program": "/bin/echo", "args": ["hi"]}):
#       print(event, data)
import json
import requests

class ExecutionClient:
    def __init__(self, base_url, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def health(self):
        r = self.session.get(f"{self.base_url}/health", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def tools(self):
        r = self.session.get(f"{self.base_url}/v1/tools", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def create_session(self, label=None):
        r = self.session.post(f"{self.base_url}/v1/sessions", json={"label": label}, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def execute(self, tool, args, session_id=None, idempotency_key=None):
        body = {"tool": tool, "args": args}
        if session_id: body["session_id"] = session_id
        if idempotency_key: body["idempotency_key"] = idempotency_key
        r = self.session.post(f"{self.base_url}/v1/execute", json=body, timeout=self.timeout)
        if r.status_code >= 400:
            try:
                err = r.json()
            except: err = {"error": r.text}
            raise RuntimeError(f"{err.get('code')}: {err.get('error')}")
        return r.json()  # {outcome: ToolOutcome}

    def batch(self, requests, max_concurrency=8):
        body = {"requests": [{"tool": t, "args": a} for t,a in requests], "max_concurrency": max_concurrency}
        r = self.session.post(f"{self.base_url}/v1/execute/batch", json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def sequence(self, steps, continue_on_error=False):
        body = {"steps": [{"tool": t, "args": a} for t,a in steps], "continue_on_error": continue_on_error}
        r = self.session.post(f"{self.base_url}/v1/execute/sequence", json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def stream(self, tool, args, session_id=None):
        """Yield (event, data) SSE tuples. Requires `requests` stream."""
        body = {"tool": tool, "args": args}
        if session_id: body["session_id"] = session_id
        with self.session.post(f"{self.base_url}/v1/execute/stream", json=body, stream=True, timeout=self.timeout, headers={"accept": "text/event-stream"}) as r:
            r.raise_for_status()
            buf = ""
            for chunk in r.iter_content(decode_unicode=True):
                if not chunk: continue
                buf += chunk
                while "\n\n" in buf:
                    raw, buf = buf.split("\n\n", 1)
                    event = "message"
                    data_raw = ""
                    for line in raw.splitlines():
                        if line.startswith("event: "): event = line[7:]
                        elif line.startswith("data: "): data_raw = line[6:]
                    try: data = json.loads(data_raw)
                    except: data = data_raw
                    yield event, data
