require('dotenv').config();
const express = require('express');
const cors = require('cors');
const speakeasy = require('speakeasy');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = 11827;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.use(cors());
app.use(express.json());

// ==================== TOTP ====================

// 生成 TOTP
app.post('/api/totp/generate', async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'Missing userId' });

    const secret = speakeasy.generateSecret({
      length: 32,
      name: `Claw:${userId}`,
      issuer: 'ChunzhiClaw'
    });

    await supabase
      .from('profiles')
      .update({ totp_secret: secret.base32 })
      .eq('id', userId);

    // 直接返回 otpauth URL（浏览器原生支持）
    res.json({ qrCode: secret.otpauth_url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 验证 TOTP
app.post('/api/totp/verify', async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return res.status(400).json({ error: 'Missing params' });

    const { data: profile } = await supabase
      .from('profiles')
      .select('totp_secret')
      .eq('id', userId)
      .single();

    if (!profile?.totp_secret) {
      return res.status(400).json({ error: 'TOTP not setup' });
    }

    const verified = speakeasy.totp.verify({
      secret: profile.totp_secret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (verified) {
      await supabase
        .from('profiles')
        .update({ mfa_enrolled: true })
        .eq('id', userId);
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Invalid code' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 邮箱验证 TOTP
app.post('/api/totp/verify-by-email', async (req, res) => {
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

    if (!profile?.totp_secret) {
      return res.status(400).json({ error: 'TOTP not setup' });
    }

    const verified = speakeasy.totp.verify({
      secret: profile.totp_secret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (verified) {
      res.json({ success: true, userId: user.id });
    } else {
      res.status(400).json({ error: 'Invalid code' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== SMS ====================

app.post('/api/send-sms-code', async (req, res) => {
  // 这里接你的短信服务商逻辑
  res.json({ status: 0, data: { sessionId: 'test-session' } });
});

app.post('/api/verify-sms-code', async (req, res) => {
  // 这里接你的短信验证逻辑
  res.json({ status: 0 });
});

// ==================== Server ====================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});
