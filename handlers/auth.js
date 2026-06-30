const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const dynamodb = new AWS.DynamoDB.DocumentClient();

// 配置
const CONFIG = {
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_EXPIRES_IN: 24 * 60 * 60, // 24小时
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60, // 15分钟
  PASSWORD_MIN_LENGTH: 8,
  RATE_LIMIT_WINDOW: 60 * 1000, // 1分钟
  RATE_LIMIT_MAX: 10,
};

// 内存存储（生产环境建议用Redis）
const loginAttempts = new Map();
const rateLimit = new Map();

// ==================== 安全工具 ====================

// 密码哈希（使用PBKDF2，比SHA256更安全）
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = hashPassword(password, storedSalt);
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(storedHash));
}

// JWT实现（带过期时间）
function createToken(payload) {
  const now = Math.floor(Date.now() / 1000);
  const tokenPayload = {
    ...payload,
    iat: now,
    exp: now + CONFIG.JWT_EXPIRES_IN,
  };

  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(tokenPayload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', CONFIG.JWT_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');

  return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
  try {
    const [header, body, signature] = token.split('.');
    if (!header || !body || !signature) return null;

    const expectedSignature = crypto
      .createHmac('sha256', CONFIG.JWT_SECRET)
      .update(`${header}.${body}`)
      .digest('base64url');

    if (signature !== expectedSignature) return null;

    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());

    // 检查过期时间
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

// 速率限制
function checkRateLimit(key) {
  const now = Date.now();
  const windowStart = now - CONFIG.RATE_LIMIT_WINDOW;

  if (!rateLimit.has(key)) {
    rateLimit.set(key, []);
  }

  const requests = rateLimit.get(key).filter((time) => time > windowStart);
  rateLimit.set(key, requests);

  if (requests.length >= CONFIG.RATE_LIMIT_MAX) {
    return false;
  }

  requests.push(now);
  return true;
}

// 登录尝试限制
function checkLoginAttempts(email) {
  const now = Date.now();
  const attempts = loginAttempts.get(email) || { count: 0, lastAttempt: 0 };

  // 检查是否在锁定期间
  if (attempts.count >= CONFIG.MAX_LOGIN_ATTEMPTS) {
    const lockoutEnd = attempts.lastAttempt + CONFIG.LOCKOUT_DURATION * 1000;
    if (now < lockoutEnd) {
      return { allowed: false, remainingTime: Math.ceil((lockoutEnd - now) / 1000) };
    }
    // 锁定期结束，重置计数
    loginAttempts.set(email, { count: 0, lastAttempt: 0 });
  }

  return { allowed: true };
}

function recordLoginAttempt(email, success) {
  const attempts = loginAttempts.get(email) || { count: 0, lastAttempt: 0 };

  if (success) {
    loginAttempts.delete(email);
  } else {
    attempts.count += 1;
    attempts.lastAttempt = Date.now();
    loginAttempts.set(email, attempts);
  }
}

// 输入验证
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePassword(password) {
  if (password.length < CONFIG.PASSWORD_MIN_LENGTH) {
    return { valid: false, error: `密码长度至少${CONFIG.PASSWORD_MIN_LENGTH}位` };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: '密码必须包含大写字母' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, error: '密码必须包含小写字母' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, error: '密码必须包含数字' };
  }
  return { valid: true };
}

// 输入清理
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input.replace(/[<>"'&]/g, (match) => {
    const escapeMap = {
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '&': '&amp;',
    };
    return escapeMap[match];
  });
}

// ==================== CORS ====================

function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Max-Age': '86400',
  };
}

// ==================== 主处理函数 ====================

exports.handler = async (event) => {
  const corsHeaders = getCorsHeaders();

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  const path = event.path;
  const method = event.httpMethod;
  const clientIp = event.requestContext?.identity?.sourceIp || 'unknown';

  // 速率限制检查
  if (!checkRateLimit(`${method}:${path}:${clientIp}`)) {
    return {
      statusCode: 429,
      headers: { ...corsHeaders, 'Retry-After': '60' },
      body: JSON.stringify({ error: 'Too many requests', message: '请稍后再试' }),
    };
  }

  try {
    // ==================== 注册 ====================
    if (path.endsWith('/register') && method === 'POST') {
      const body = JSON.parse(event.body);
      let { email, password, name } = body;

      // 输入清理
      email = sanitizeInput(email?.toLowerCase().trim());
      name = sanitizeInput(name?.trim());

      // 验证输入
      if (!email || !password) {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Validation error', message: '邮箱和密码为必填项' }),
        };
      }

      if (!validateEmail(email)) {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Validation error', message: '邮箱格式不正确' }),
        };
      }

      const passwordValidation = validatePassword(password);
      if (!passwordValidation.valid) {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Validation error', message: passwordValidation.error }),
        };
      }

      // 检查邮箱是否已存在
      const existing = await dynamodb
        .query({
          TableName: 'api-marketplace-users',
          IndexName: 'email-index',
          KeyConditionExpression: 'email = :email',
          ExpressionAttributeValues: { ':email': email },
        })
        .promise();

      if (existing.Items.length > 0) {
        // 不要泄露邮箱是否已注册
        return {
          statusCode: 201,
          headers: corsHeaders,
          body: JSON.stringify({
            message: '注册成功，请查收验证邮件',
            note: '如果该邮箱已注册，我们将发送登录链接',
          }),
        };
      }

      // 创建用户
      const userId = uuidv4();
      const { hash: passwordHash, salt } = hashPassword(password);
      const verificationToken = crypto.randomBytes(32).toString('hex');

      await dynamodb
        .put({
          TableName: 'api-marketplace-users',
          Item: {
            userId,
            email,
            name: name || email.split('@')[0],
            passwordHash,
            passwordSalt: salt,
            balance: 0,
            isVerified: false, // 邮箱验证状态
            verificationToken,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            lastLoginAt: null,
            loginAttempts: 0,
          },
        })
        .promise();

      // 生成令牌（用于验证邮箱）
      const token = createToken({ userId, email, type: 'verification' });

      return {
        statusCode: 201,
        headers: corsHeaders,
        body: JSON.stringify({
          message: '注册成功',
          userId,
          email,
          verificationToken, // 实际项目中应通过邮件发送
        }),
      };
    }

    // ==================== 登录 ====================
    if (path.endsWith('/login') && method === 'POST') {
      const body = JSON.parse(event.body);
      let { email, password } = body;

      // 输入清理
      email = sanitizeInput(email?.toLowerCase().trim());

      // 验证输入
      if (!email || !password) {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Validation error', message: '邮箱和密码为必填项' }),
        };
      }

      // 检查登录尝试限制
      const loginCheck = checkLoginAttempts(email);
      if (!loginCheck.allowed) {
        return {
          statusCode: 429,
          headers: corsHeaders,
          body: JSON.stringify({
            error: 'Account locked',
            message: `登录尝试次数过多，请${loginCheck.remainingTime}秒后再试`,
          }),
        };
      }

      // 查找用户
      const result = await dynamodb
        .query({
          TableName: 'api-marketplace-users',
          IndexName: 'email-index',
          KeyConditionExpression: 'email = :email',
          ExpressionAttributeValues: { ':email': email },
        })
        .promise();

      if (result.Items.length === 0) {
        recordLoginAttempt(email, false);
        return {
          statusCode: 401,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Authentication error', message: '邮箱或密码错误' }),
        };
      }

      const user = result.Items[0];

      // 验证密码
      if (!verifyPassword(password, user.passwordHash, user.passwordSalt)) {
        recordLoginAttempt(email, false);
        return {
          statusCode: 401,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Authentication error', message: '邮箱或密码错误' }),
        };
      }

      // 登录成功
      recordLoginAttempt(email, true);

      // 更新最后登录时间
      await dynamodb
        .update({
          TableName: 'api-marketplace-users',
          Key: { userId: user.userId },
          UpdateExpression: 'SET lastLoginAt = :now, updatedAt = :now',
          ExpressionAttributeValues: {
            ':now': new Date().toISOString(),
          },
        })
        .promise();

      // 生成令牌
      const token = createToken({
        userId: user.userId,
        email: user.email,
        name: user.name,
      });

      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify({
          message: '登录成功',
          token,
          user: {
            userId: user.userId,
            email: user.email,
            name: user.name,
            balance: user.balance,
            isVerified: user.isVerified,
          },
        }),
      };
    }

    // ==================== 获取用户信息 ====================
    if (path.endsWith('/me') && method === 'GET') {
      const authHeader = event.headers?.Authorization || event.headers?.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return {
          statusCode: 401,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Authentication required' }),
        };
      }

      const token = authHeader.replace('Bearer ', '');
      const decoded = verifyToken(token);

      if (!decoded) {
        return {
          statusCode: 401,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Invalid or expired token' }),
        };
      }

      const result = await dynamodb
        .get({
          TableName: 'api-marketplace-users',
          Key: { userId: decoded.userId },
        })
        .promise();

      if (!result.Item) {
        return {
          statusCode: 404,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'User not found' }),
        };
      }

      const user = result.Item;
      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify({
          userId: user.userId,
          email: user.email,
          name: user.name,
          balance: user.balance,
          isVerified: user.isVerified,
          createdAt: user.createdAt,
          lastLoginAt: user.lastLoginAt,
        }),
      };
    }

    // ==================== 修改密码 ====================
    if (path.endsWith('/change-password') && method === 'POST') {
      const authHeader = event.headers?.Authorization || event.headers?.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return {
          statusCode: 401,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Authentication required' }),
        };
      }

      const token = authHeader.replace('Bearer ', '');
      const decoded = verifyToken(token);

      if (!decoded) {
        return {
          statusCode: 401,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Invalid or expired token' }),
        };
      }

      const { currentPassword, newPassword } = JSON.parse(event.body);

      if (!currentPassword || !newPassword) {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Validation error', message: '当前密码和新密码为必填项' }),
        };
      }

      // 验证新密码强度
      const passwordValidation = validatePassword(newPassword);
      if (!passwordValidation.valid) {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Validation error', message: passwordValidation.error }),
        };
      }

      // 获取用户
      const result = await dynamodb
        .get({
          TableName: 'api-marketplace-users',
          Key: { userId: decoded.userId },
        })
        .promise();

      if (!result.Item) {
        return {
          statusCode: 404,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'User not found' }),
        };
      }

      const user = result.Item;

      // 验证当前密码
      if (!verifyPassword(currentPassword, user.passwordHash, user.passwordSalt)) {
        return {
          statusCode: 401,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Authentication error', message: '当前密码错误' }),
        };
      }

      // 更新密码
      const { hash: newHash, salt: newSalt } = hashPassword(newPassword);

      await dynamodb
        .update({
          TableName: 'api-marketplace-users',
          Key: { userId: decoded.userId },
          UpdateExpression: 'SET passwordHash = :hash, passwordSalt = :salt, updatedAt = :now',
          ExpressionAttributeValues: {
            ':hash': newHash,
            ':salt': newSalt,
            ':now': new Date().toISOString(),
          },
        })
        .promise();

      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify({ message: '密码修改成功' }),
      };
    }

    return {
      statusCode: 404,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Not found' }),
    };
  } catch (error) {
    console.error('Auth error:', error);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Internal server error', message: '服务器内部错误' }),
    };
  }
};
