require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 11827;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.use(cors());
app.use(express.json());
const upload = multer({ storage: multer.memoryStorage() });

// ==================== 工具函数 ====================

// TOTP secret 加密密钥（32 字节 hex）。缺失时回退到派生密钥并告警。
const ENC_KEY = process.env.ENCRYPTION_KEY
  ? Buffer.from(process.env.ENCRYPTION_KEY, 'hex')
  : (() => {
      console.warn('⚠️  ENCRYPTION_KEY 未设置，使用默认派生密钥（不安全），请在 .env 中配置');
      return crypto.scryptSync('chunzhi-claw', 'static-salt', 32);
    })();

function encryptSecret(plain) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, iv);
  let enc = cipher.update(plain, 'utf8', 'hex');
  enc += cipher.final('hex');
  return iv.toString('hex') + ':' + enc;
}

function decryptSecret(stored) {
  try {
    const [ivHex, enc] = (stored || '').split(':');
    if (!ivHex || !enc) return stored; // 兼容历史明文
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENC_KEY, Buffer.from(ivHex, 'hex'));
    let dec = decipher.update(enc, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  } catch {
    return stored;
  }
}

// 与前端 encryptPass（XOR + Base64）对应的解密，用于 SMTP 密码
function decryptFrontendPass(enc) {
  try {
    const key = 'claw_2025';
    const buf = Buffer.from(enc, 'base64').toString('binary');
    let out = '';
    for (let i = 0; i < buf.length; i++) {
      out += String.fromCharCode(buf.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return out;
  } catch {
    return enc;
  }
}

// ==================== 中间件 ====================

// 验证 Supabase JWT，并把当前用户挂到 req.user
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未授权：缺少令牌' });
  }
  try {
    const { data: { user }, error } = await supabase.auth.getUser(auth.slice(7));
    if (error || !user) return res.status(401).json({ error: '无效的令牌' });
    req.user = user;
    next();
  } catch (e) {
    res.status(401).json({ error: '令牌验证失败' });
  }
}

const totpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });
const lookupLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

// ==================== TOTP ====================

// 生成 TOTP（必须登录，且只能操作自己的账号）
app.post('/api/totp/generate', requireAuth, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    if (req.user.id !== userId) return res.status(403).json({ error: '无权操作此账号' });

    const secret = speakeasy.generateSecret({
      length: 32,
      name: `Claw:${userId}`,
      issuer: 'ChunzhiClaw'
    });

    await supabase
      .from('profiles')
      .update({ totp_secret: encryptSecret(secret.base32) })
      .eq('id', userId);

    res.json({ qrCode: secret.otpauth_url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 验证并启用 TOTP（必须登录）
app.post('/api/totp/verify', requireAuth, async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return res.status(400).json({ error: 'Missing params' });
    if (req.user.id !== userId) return res.status(403).json({ error: '无权操作此账号' });

    const { data: profile } = await supabase
      .from('profiles')
      .select('totp_secret')
      .eq('id', userId)
      .single();

    if (!profile?.totp_secret) return res.status(400).json({ error: 'TOTP not setup' });

    const verified = speakeasy.totp.verify({
      secret: decryptSecret(profile.totp_secret),
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (verified) {
      await supabase.from('profiles').update({ mfa_enrolled: true }).eq('id', userId);
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Invalid code' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 邮箱 + TOTP 登录（未登录流程，供 auth.html 使用，带速率限制）
app.post('/api/totp/verify-by-email', totpLimiter, async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: 'Missing params' });

    const { data: { users } } = await supabase.auth.admin.listUsers();
    const user = users.find(u => u.email === email);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { data: profile } = await supabase
      .from('profiles')
      .select('totp_secret')
      .eq('id', user.id)
      .single();

    if (!profile?.totp_secret) return res.status(400).json({ error: 'TOTP not setup' });

    const verified = speakeasy.totp.verify({
      secret: decryptSecret(profile.totp_secret),
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (verified) res.json({ success: true, userId: user.id });
    else res.status(400).json({ error: 'Invalid code' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 手机号查邮箱（供登录页转换账号，带速率限制）
app.post('/api/phone-to-email', lookupLimiter, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!/^1[3-9]\d{9}$/.test(phone || '')) {
      return res.status(400).json({ error: 'Invalid phone' });
    }
    const { data: profile } = await supabase
      .from('profiles')
      .select('id')
      .eq('phone', phone)
      .single();

    if (!profile?.id) return res.status(404).json({ error: '该手机号未注册' });

    const { data: { users } } = await supabase.auth.admin.listUsers();
    const u = users?.find(x => x.id === profile.id);
    if (!u?.email) return res.status(404).json({ error: '无法找到关联邮箱' });

    res.json({ email: u.email });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== SMS（由百度云短信服务实现，接口签名保留） ====================

app.post('/api/send-sms-code', async (req, res) => {
  res.json({ status: 0, data: { sessionId: 'pending' } });
});

app.post('/api/verify-sms-code', async (req, res) => {
  res.json({ status: 0 });
});

// ==================== Email（AI 生成 + 发送 + 附件） ====================

// AI 生成邮件正文（DeepSeek / OpenAI 兼容接口）
app.post('/api/email/generate', async (req, res) => {
  try {
    const { subject, content, sender_name } = req.body;
    const apiKey = process.env.DEEPSEEK_API_KEY || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.status(503).json({ error: '未配置 AI 服务（请在 .env 设置 DEEPSEEK_API_KEY）' });
    }
    const baseUrl = (process.env.AI_BASE_URL || 'https://api.deepseek.com/v1').replace(/\/$/, '');
    const model = process.env.AI_MODEL || 'deepseek-chat';
    const sys = '你是一名专业的中文邮件助手，帮助教师撰写正式、得体的邮件。只输出邮件正文，不要包含主题行和问候语前缀。';
    const userMsg = `发件人：${sender_name || '老师'}\n邮件主题：${subject}\n要点/素材：\n${content}`;
    const r = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: sys },
          { role: 'user', content: userMsg }
        ],
        temperature: 0.7
      })
    });
    const d = await r.json();
    if (!r.ok || !d.choices?.[0]?.message?.content) {
      return res.status(502).json({ error: 'AI 服务返回异常：' + (d.error?.message || r.statusText) });
    }
    res.json({ success: true, email_content: d.choices[0].message.content.trim() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 发送邮件（multipart/form-data，含附件）
app.post('/api/email/send', upload.any(), async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.smtp_host || !b.smtp_user || !b.smtp_pass || !b.to || !b.subject) {
      return res.status(400).json({ error: '缺少必要参数' });
    }
    let pass;
    try { pass = decryptFrontendPass(b.smtp_pass); } catch { pass = b.smtp_pass; }

    const transporter = nodemailer.createTransport({
      host: b.smtp_host,
      port: parseInt(b.smtp_port, 10) || 465,
      secure: b.smtp_secure === 'true' || b.smtp_secure === true,
      auth: { user: b.smtp_user, pass }
    });

    const attachments = (req.files || []).map(f => ({
      filename: f.originalname,
      content: f.buffer
    }));

    await transporter.sendMail({
      from: `${b.sender_name || b.smtp_user} <${b.smtp_user}>`,
      to: b.to,
      subject: b.subject,
      html: b.html || '',
      attachments
    });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 生成邮件附件（返回可下载的 data URL）
app.post('/api/email/generate-attachment', async (req, res) => {
  try {
    const { type, description } = req.body;
    const extMap = { doc: 'md', word: 'md', excel: 'csv', ppt: 'md', txt: 'txt' };
    const mimeMap = { doc: 'text/markdown', word: 'text/markdown', excel: 'text/csv', ppt: 'text/markdown', txt: 'text/plain' };
    const ext = extMap[type] || 'txt';
    const mime = mimeMap[type] || 'text/plain';

    let body = '';
    if (type === 'excel') {
      body = '序号,内容\n1,' + (description || '示例内容') + '\n';
    } else {
      body = `# ${(description || 'AI 生成的附件')}\n\n> 由春志Claw生成\n\n${description || '在这里填写内容。'}`;
    }

    const dataUrl = `data:${mime};base64,${Buffer.from(body, 'utf8').toString('base64')}`;
    res.json({ success: true, file_url: dataUrl, filename: `attachment.${ext}` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== Health ====================

app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

// ==================== Server ====================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});
