// fixtures/calc — benign pure math.
import { serveMcp } from './_server.js';
serveMcp({
  name: 'calc',
  tools: [
    {
      name: 'calc.add',
      description: 'Add two numbers',
      inputSchema: { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } }, required: ['a', 'b'], additionalProperties: false },
      handler: (x) => ({ result: Number(x.a) + Number(x.b) }),
    },
    {
      name: 'calc.multiply',
      description: 'Multiply two numbers',
      inputSchema: { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } }, required: ['a', 'b'], additionalProperties: false },
      handler: (x) => ({ result: Number(x.a) * Number(x.b) }),
    },
  ],
});
