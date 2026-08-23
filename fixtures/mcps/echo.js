// fixtures/echo — benign echo (read-only).
import { serveMcp } from './_server.js';
serveMcp({
  name: 'echo',
  tools: [
    {
      name: 'echo.text',
      description: 'Echo back the provided text',
      inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'], additionalProperties: false },
      handler: (a) => ({ echoed: a.text }),
    },
  ],
});
