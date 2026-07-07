// Cloudflare Worker：将前端来的 /api/* 请求在服务端转发到后端 HTTP 服务
// 作用：浏览器(HTTPS) -> Worker(HTTPS) -> 后端(HTTP)，规避"HTTPS 页不能访问 HTTP"的混合内容限制
//
// 部署步骤（Cloudflare 控制台）：
//   1. Workers & Pages -> 创建应用程序 -> Worker -> 新建 Worker
//   2. 删除默认代码，粘贴本文件，保存并部署
//   3. 部署后会得到地址，例如：https://claw-proxy-xxxx.workers.dev
//   4. 把该地址填入前端 website/V1/config.js 的 window.CLAW_API_BASE
//      （即 window.CLAW_API_BASE = 'https://claw-proxy-xxxx.workers.dev';）
//   5. 重新部署 Cloudflare Pages（git push 或控制台重试）
//
// 注：Worker 与 Pages 是两个独立的 Cloudflare 资源，但同账号下即可。

const BACKEND = 'http://93.115.101.178:11827';

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // 只处理 /api 路径；其余路径（理论上不会走到本 Worker）原样透传
    if (!url.pathname.startsWith('/api')) {
      return fetch(request);
    }

    const target = BACKEND + url.pathname + url.search;

    // 透传请求头，去掉 host（避免后端收到 Worker 域名）
    const headers = new Headers();
    for (const [k, v] of request.headers.entries()) {
      if (k.toLowerCase() === 'host') continue;
      headers.set(k, v);
    }

    try {
      const resp = await fetch(target, {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
        redirect: 'follow'
      });
      return resp;
    } catch (e) {
      return new Response(
        JSON.stringify({ error: 'Backend unreachable', message: e.message }),
        { status: 502, headers: { 'Content-Type': 'application/json' } }
      );
    }
  }
};
