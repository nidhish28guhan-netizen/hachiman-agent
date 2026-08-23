// fixtures/time — benign clock.
import { serveMcp } from './_server.js';
serveMcp({
  name: 'time',
  tools: [
    {
      name: 'time.now',
      description: 'Return current UTC time',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      handler: () => ({ iso: new Date().toISOString() }),
    },
  ],
});
