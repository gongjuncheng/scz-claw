export default {
  async fetch(request) {
    const url = new URL(request.url);

    // 放过静态资源
    if (url.pathname.includes('.') && !url.pathname.startsWith('/api')) {
      return fetch(request);
    }

    const backend = 'http://93.115.101.178:11827' + url.pathname + url.search;

    try {
      const response = await fetch(backend, {
        method: request.method,
        headers: request.headers,
        body: request.method !== 'GET' && request.method !== 'HEAD'
          ? request.body
          : undefined,
      });
      return response;
    } catch (err) {
      return new Response(JSON.stringify({
        error: 'Backend unreachable',
        message: err.message,
        backend: backend
      }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};
