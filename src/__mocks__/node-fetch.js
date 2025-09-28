const fetchMock = require('node-fetch');

const mockResponse = (status, statusText, response) => {
  return new fetchMock.Response(JSON.stringify(response), {
    status: status,
    statusText: statusText,
    headers: { 'Content-type': 'application/json' }
  });
};

// Mock successful response for /api/tags
fetchMock.mockResponse((req) => {
  if (req.url.endsWith('/api/tags')) {
    return Promise.resolve(mockResponse(200, 'OK', {
      models: [
        { name: 'llama3', model: 'llama3', modified_at: '2023-01-01T00:00:00Z' },
        { name: 'mistral', model: 'mistral', modified_at: '2023-01-01T00:00:00Z' }
      ]
    }));
  }
  
  // Mock successful response for /api/generate
  if (req.url.endsWith('/api/generate')) {
    return req.json().then(body => {
      if (body.stream) {
        // For stream responses, we'll handle this differently
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ response: `Mock response for: ${body.prompt}` })
        });
      }
      return mockResponse(200, 'OK', { response: `Mock response for: ${body.prompt}` });
    });
  }
  
  // Default response for any other endpoint
  return Promise.resolve(mockResponse(404, 'Not Found', { error: 'Endpoint not found' }));
});

module.exports = fetchMock;
