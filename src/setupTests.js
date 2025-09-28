// Mock the global fetch API
global.fetch = jest.fn();

// Mock the Response object for testing
class Response {
  constructor(body, init = {}) {
    this.body = body;
    this.status = init.status || 200;
    this.statusText = init.statusText || 'OK';
    this.headers = new Map();
    
    if (init.headers) {
      Object.entries(init.headers).forEach(([key, value]) => {
        this.headers.set(key.toLowerCase(), value);
      });
    }
  }
  
  json() {
    return Promise.resolve(JSON.parse(this.body));
  }
  
  text() {
    return Promise.resolve(this.body);
  }
}

global.Response = Response;

// Mock the ReadableStream for testing
class ReadableStream {
  constructor(underlyingSource) {
    this._controller = {
      enqueue: jest.fn(),
      close: jest.fn(),
      error: jest.fn()
    };
    
    if (underlyingSource && typeof underlyingSource.start === 'function') {
      underlyingSource.start({
        enqueue: this._controller.enqueue,
        close: this._controller.close,
        error: this._controller.error
      });
    }
  }
  
  getReader() {
    return {
      read: () => Promise.resolve({ done: true }),
      releaseLock: jest.fn(),
      cancel: jest.fn()
    };
  }
}

global.ReadableStream = ReadableStream;

// Mock TextEncoder and TextDecoder
class TextEncoder {
  encode(str) {
    const encoder = new (require('util').TextEncoder)();
    return encoder.encode(str);
  }
}

class TextDecoder {
  decode(buffer) {
    const decoder = new (require('util').TextDecoder)();
    return decoder.decode(buffer);
  }
}

global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Mock AbortController
class AbortController {
  constructor() {
    this.signal = {
      aborted: false,
      onabort: null,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn()
    };
  }
  
  abort() {
    this.signal.aborted = true;
    if (typeof this.signal.onabort === 'function') {
      this.signal.onabort();
    }
  }
}

global.AbortController = AbortController;
