// 后端 API 基地址配置
// - 留空 '' ：使用 Cloudflare Pages Functions 代理（相对路径 /api/...）
// - 若 Pages Functions 不可用，可填 Cloudflare Worker / Tunnel 的 HTTPS 地址，例如：
//     window.CLAW_API_BASE = 'https://claw-proxy-xxxx.workers.dev';
//   前端所有 /api 请求会发给该地址（HTTPS），由其服务端转发到后端 HTTP 服务
window.CLAW_API_BASE = '';
