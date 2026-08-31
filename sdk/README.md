# SDKs for executiond

Thin clients over `executiond` HTTP API (`/v1/execute`, SSE `/v1/execute/stream`).

## JS

```js
import { ExecutionClient } from './js/index.js'
const c = new ExecutionClient('http://localhost:3000')
console.log(await c.health())
console.log(await c.tools())
const {session_id} = await c.createSession('demo')
console.log(await c.execute('filesystem', {operation:'mkdir', path:`/tmp/executiond/${session_id}/hi`}))
for await (const {event, data} of c.stream('shell', {program:'/bin/echo', args:['hi']})) console.log(event, data)
```

## Python

```python
from python.execution_tool_sdk import ExecutionClient
c = ExecutionClient("http://localhost:3000")
c.health()
c.create_session("demo")
c.execute("shell", {"program": "/bin/echo", "args": ["hi"]})
for event, data in c.stream("shell", {"program": "/bin/echo", "args": ["hi"]}): print(event, data)
```
