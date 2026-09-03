// marshall JS SDK — thin client over marshalld (Phase 3)
// npm: marshall-sdk (scaffold)
// Usage:
//   import { ExecutionClient } from './index.js'
//   const c = new ExecutionClient('http://localhost:3000')
//   await c.execute('shell', {program:'/bin/echo', args:['hi']})
//   for await (const chunk of c.stream('shell', {program:'/bin/echo', args:['hi']})) console.log(chunk)

export class ExecutionClient {
  constructor(baseUrl, opts = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetch = opts.fetch || globalThis.fetch;
  }

  async health() {
    const r = await this.fetch(`${this.baseUrl}/health`);
    if (!r.ok) throw new Error(`health ${r.status}`);
    return r.json();
  }

  async tools() {
    const r = await this.fetch(`${this.baseUrl}/v1/tools`);
    if (!r.ok) throw new Error(`tools ${r.status}`);
    return r.json();
  }

  async createSession(label) {
    const r = await this.fetch(`${this.baseUrl}/v1/sessions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ label }),
    });
    if (!r.ok) throw new Error(`createSession ${r.status}: ${await r.text()}`);
    return r.json();
  }

  async execute(tool, args, opts = {}) {
    const body = { tool, args, session_id: opts.sessionId, idempotency_key: opts.idempotencyKey };
    const r = await this.fetch(`${this.baseUrl}/v1/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({ error: r.statusText }));
      throw Object.assign(new Error(err.error || err.code), { code: err.code, status: r.status });
    }
    return r.json(); // { outcome: ToolOutcome }
  }

  // SSE streaming — yields {event, data} per chunk
  async batch(requests, opts = {}) {
    const body = { requests: requests.map(([tool, args]) => ({ tool, args })), max_concurrency: opts.maxConcurrency };
    const r = await this.fetch(`${this.baseUrl}/v1/execute/batch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(`batch ${r.status}: ${await r.text()}`);
    return r.json();
  }

  async sequence(steps, opts = {}) {
    const body = { steps: steps.map(([tool, args]) => ({ tool, args })), continue_on_error: opts.continueOnError };
    const r = await this.fetch(`${this.baseUrl}/v1/execute/sequence`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(`sequence ${r.status}: ${await r.text()}`);
    return r.json();
  }

  async *stream(tool, args, opts = {}) {
    const body = { tool, args, session_id: opts.sessionId };
    const r = await this.fetch(`${this.baseUrl}/v1/execute/stream`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
      body: JSON.stringify(body),
    });
    if (!r.ok || !r.body) throw new Error(`stream ${r.status}`);
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n\n')) !== -1) {
        const raw = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const event = (raw.match(/^event: (.*)/m) || [])[1] || 'message';
        const dataRaw = (raw.match(/^data: (.*)/m) || [])[1] || '';
        let data;
        try { data = JSON.parse(dataRaw); } catch { data = dataRaw; }
        yield { event, data };
      }
    }
  }
}
