// Cloudflare Pages Functions 反向代理
// 作用：将 HTTPS 前端的 /api/* 请求在服务端转发到后端 HTTP 服务，
//       避免浏览器因"HTTPS 页面不能访问 HTTP 资源"而报错（混合内容限制）。
// 后端地址可通过 Pages 环境变量 BACKEND_URL 覆盖，否则使用默认值。

const DEFAULT_BACKEND = 'http://93.115.101.178:11827';

export default {
  async fetch(request, context) {
    const url = new URL(request.url);

    // 1. 非 /api 路径（静态资源、页面）直接放行
    if (!url.pathname.startsWith('/api')) {
      return fetch(request);
    }

    // 2. 允许通过 Pages 环境变量覆盖后端地址
    const backendBase = (context && context.env && context.env.BACKEND_URL) || DEFAULT_BACKEND;
    const backend = backendBase.replace(/\/$/, '') + url.pathname + url.search;

    // 3. 转发请求头：去掉 host（避免后端收到 Cloudflare 域名），保留鉴权等头部
    const headers = new Headers();
    for (const [k, v] of request.headers.entries()) {
      if (k.toLowerCase() === 'host') continue;
      headers.set(k, v);
    }

    try {
      const response = await fetch(backend, {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
        redirect: 'follow'
      });
      // 透传后端响应，但移除可能冲突的 host 相关头部
      const respHeaders = new Headers(response.headers);
      respHeaders.delete('content-encoding'); // 交由 Cloudflare 重新处理
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: respHeaders
      });
    } catch (err) {
      return new Response(
        JSON.stringify({
          error: 'Backend unreachable',
          message: err.message
        }),
        { status: 502, headers: { 'Content-Type': 'application/json' } }
      );
    }
  }
};
