const AWS = require('aws-sdk');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const dynamodb = new AWS.DynamoDB.DocumentClient();

// JWT配置（与auth.js保持一致）
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = 24 * 60 * 60; // 24小时

// 速率限制
const RATE_LIMIT_WINDOW = 60 * 1000; // 1分钟
const RATE_LIMIT_MAX = 60;
const rateLimit = new Map();

// 模型配置
const models = {
  'mimo-v2.5': {
    upstream: 'https://token-plan-cn.xiaomimimo.com/v1/chat/completions',
    provider: 'mimo',
    costPerToken: 0.000002
  },
  'mimo-v2.5-pro': {
    upstream: 'https://token-plan-cn.xiaomimimo.com/v1/chat/completions',
    provider: 'mimo',
    costPerToken: 0.00001
  },
  'gpt-4': {
    upstream: 'https://api.openai.com/v1/chat/completions',
    provider: 'openai',
    costPerToken: 0.00003
  },
  'gpt-3.5-turbo': {
    upstream: 'https://api.openai.com/v1/chat/completions',
    provider: 'openai',
    costPerToken: 0.000002
  }
};

// ==================== JWT工具（与auth.js保持一致）====================

function verifyToken(token) {
  try {
    const [header, body, signature] = token.split('.');
    if (!header || !body || !signature) return null;

    const expectedSignature = crypto
      .createHmac('sha256', JWT_SECRET)
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

// ==================== 速率限制 ====================

function checkRateLimit(key) {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;

  if (!rateLimit.has(key)) {
    rateLimit.set(key, []);
  }

  const requests = rateLimit.get(key).filter((time) => time > windowStart);
  rateLimit.set(key, requests);

  if (requests.length >= RATE_LIMIT_MAX) {
    return false;
  }

  requests.push(now);
  return true;
}

// ==================== 表名工具 ====================

function getTableName(suffix) {
  return `api-marketplace-${suffix}`;
}

// ==================== CORS ====================

function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
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

  // 速率限制
  if (!checkRateLimit(`${clientIp}:${method}:${path}`)) {
    return {
      statusCode: 429,
      headers: { ...corsHeaders, 'Retry-After': '60' },
      body: JSON.stringify({ error: 'Too many requests' }),
    };
  }

  try {
    // 首页
    if (path === '/' && method === 'GET') {
      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Aiko API',
          version: '2.0.0',
          description: '稳定快速的AI模型代理服务',
          endpoints: {
            auth: {
              register: 'POST /auth/register',
              login: 'POST /auth/login',
              me: 'GET /auth/me',
            },
            api: {
              chat: 'POST /chat/completions',
              models: 'GET /models',
              usage: 'GET /usage',
            },
            billing: {
              balance: 'GET /balance',
              topup: 'POST /topup',
            },
          },
        }),
      };
    }

    // 认证检查
    const authHeader = event.headers?.Authorization || event.headers?.authorization;
    let userId = null;
    let userInfo = null;

    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.replace('Bearer ', '');
      const decoded = verifyToken(token);
      if (decoded) {
        userId = decoded.userId;
        userInfo = decoded;
      }
    }

    // 获取模型列表（不需要认证）
    if (path === '/models' && method === 'GET') {
      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          data: Object.entries(models).map(([id, config]) => ({
            id,
            provider: config.provider,
            cost_per_token: config.costPerToken,
          })),
        }),
      };
    }

    // 以下接口需要认证
    if (!userId) {
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Authentication required', message: '请先登录' }),
      };
    }

    // 获取余额
    if (path === '/balance' && method === 'GET') {
      const result = await dynamodb
        .get({
          TableName: getTableName('users'),
          Key: { userId },
        })
        .promise();

      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ balance: result.Item?.balance || 0 }),
      };
    }

    // 充值
    if (path === '/topup' && method === 'POST') {
      const { amount } = JSON.parse(event.body || '{}');
      if (!amount || amount <= 0 || amount > 10000) {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Invalid amount', message: '充值金额必须在1-10000之间' }),
        };
      }

      await dynamodb
        .update({
          TableName: getTableName('users'),
          Key: { userId },
          UpdateExpression: 'SET balance = if_not_exists(balance, :zero) + :amount, updatedAt = :now',
          ExpressionAttributeValues: { ':amount': amount, ':zero': 0, ':now': new Date().toISOString() },
        })
        .promise();

      const result = await dynamodb
        .get({
          TableName: getTableName('users'),
          Key: { userId },
        })
        .promise();

      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ success: true, balance: result.Item.balance, message: '充值成功' }),
      };
    }

    // 使用量统计
    if (path === '/usage' && method === 'GET') {
      const result = await dynamodb
        .scan({
          TableName: getTableName('usage'),
          FilterExpression: 'userId = :userId',
          ExpressionAttributeValues: { ':userId': userId },
        })
        .promise();

      const totalTokens = result.Items.reduce((sum, item) => sum + (item.tokens || 0), 0);
      const totalCost = result.Items.reduce((sum, item) => sum + (item.cost || 0), 0);

      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          totalTokens,
          totalCost,
          requests: result.Items.length,
          byModel: result.Items.reduce((acc, item) => {
            if (!acc[item.model]) {
              acc[item.model] = { tokens: 0, cost: 0, requests: 0 };
            }
            acc[item.model].tokens += item.tokens || 0;
            acc[item.model].cost += item.cost || 0;
            acc[item.model].requests += 1;
            return acc;
          }, {}),
        }),
      };
    }

    // 聊天补全
    if (path === '/chat/completions' && method === 'POST') {
      // 检查余额
      const userResult = await dynamodb
        .get({
          TableName: getTableName('users'),
          Key: { userId },
        })
        .promise();

      if (!userResult.Item || userResult.Item.balance <= 0) {
        return {
          statusCode: 402,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Insufficient balance', message: '余额不足，请先充值' }),
        };
      }

      const body = JSON.parse(event.body || '{}');
      const { model, messages, temperature, max_tokens } = body;

      if (!model || !messages || !Array.isArray(messages)) {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({
            error: 'Validation error',
            message: '缺少必需参数：model和messages',
          }),
        };
      }

      if (!models[model]) {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({
            error: 'Invalid model',
            message: `不支持的模型：${model}`,
            available: Object.keys(models),
          }),
        };
      }

      const modelConfig = models[model];
      const upstreamApiKey = process.env.MIMO_API_KEY;

      if (!upstreamApiKey) {
        return {
          statusCode: 500,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Configuration error', message: 'API密钥未配置' }),
        };
      }

      // 构建请求
      const requestBody = { model, messages };
      if (temperature) requestBody.temperature = temperature;
      if (max_tokens) requestBody.max_tokens = max_tokens;

      // 转发请求
      const startTime = Date.now();
      const response = await axios.post(modelConfig.upstream, requestBody, {
        headers: {
          Authorization: `Bearer ${upstreamApiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 60000,
      });
      const duration = Date.now() - startTime;

      // 计算费用
      const tokensUsed = response.data.usage?.total_tokens || 0;
      const cost = tokensUsed * modelConfig.costPerToken;

      // 扣费
      await dynamodb
        .update({
          TableName: getTableName('users'),
          Key: { userId },
          UpdateExpression: 'SET balance = balance - :cost, updatedAt = :now',
          ExpressionAttributeValues: { ':cost': cost, ':now': new Date().toISOString() },
        })
        .promise();

      // 记录使用量
      await dynamodb
        .put({
          TableName: getTableName('usage'),
          Item: {
            userId,
            timestamp: new Date().toISOString(),
            model,
            tokens: tokensUsed,
            cost,
            duration,
          },
        })
        .promise();

      // 添加自定义响应头
      const responseHeaders = {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'X-Model': model,
        'X-Tokens-Used': tokensUsed.toString(),
        'X-Cost': cost.toFixed(6),
        'X-Duration-Ms': duration.toString(),
      };

      return {
        statusCode: 200,
        headers: responseHeaders,
        body: JSON.stringify(response.data),
      };
    }

    // 创建API Key
    if (path === '/api-keys' && method === 'POST') {
      const { name } = JSON.parse(event.body || '{}');
      const apiKey = `sk-${uuidv4().replace(/-/g, '')}`;

      await dynamodb
        .put({
          TableName: getTableName('api-keys'),
          Item: {
            apiKey,
            userId,
            name: name || '默认密钥',
            createdAt: new Date().toISOString(),
            isActive: true,
          },
        })
        .promise();

      return {
        statusCode: 201,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey, name: name || '默认密钥', message: 'API密钥创建成功' }),
      };
    }

    // 获取API Keys
    if (path === '/api-keys' && method === 'GET') {
      const result = await dynamodb
        .scan({
          TableName: getTableName('api-keys'),
          FilterExpression: 'userId = :userId',
          ExpressionAttributeValues: { ':userId': userId },
        })
        .promise();

      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKeys: result.Items }),
      };
    }

    // 删除API Key
    if (path.startsWith('/api-keys/') && method === 'DELETE') {
      const apiKey = path.split('/api-keys/')[1];

      const keyResult = await dynamodb
        .get({
          TableName: getTableName('api-keys'),
          Key: { apiKey },
        })
        .promise();

      if (!keyResult.Item || keyResult.Item.userId !== userId) {
        return {
          statusCode: 404,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Not found', message: 'API密钥不存在' }),
        };
      }

      await dynamodb
        .delete({
          TableName: getTableName('api-keys'),
          Key: { apiKey },
        })
        .promise();

      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify({ success: true, message: 'API密钥删除成功' }),
      };
    }

    return {
      statusCode: 404,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Not found' }),
    };
  } catch (error) {
    console.error('API error:', error.message);

    if (error.response) {
      return {
        statusCode: error.response.status,
        headers: corsHeaders,
        body: JSON.stringify(error.response.data),
      };
    }

    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Internal server error', message: '服务器内部错误' }),
    };
  }
};

function getTableName(suffix) {
  return `api-marketplace-${suffix}`;
}

function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  };
}

exports.handler = async (event) => {
  const corsHeaders = getCorsHeaders();

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  const path = event.path;
  const method = event.httpMethod;

  try {
    // 首页
    if (path === '/' && method === 'GET') {
      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'AI API Marketplace',
          version: '1.0.0',
          description: '出售你的AI API',
          endpoints: {
            auth: { register: 'POST /auth/register', login: 'POST /auth/login' },
            api: { chat: 'POST /chat/completions', models: 'GET /models', usage: 'GET /usage' },
            billing: { balance: 'GET /balance', topup: 'POST /topup' }
          }
        })
      };
    }

    // 认证检查
    const authHeader = event.headers?.Authorization || event.headers?.authorization;
    let userId = null;
    
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.replace('Bearer ', '');
      const decoded = verifyToken(token);
      if (decoded) userId = decoded.userId;
    }

    // 获取模型列表
    if (path === '/models' && method === 'GET') {
      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          data: Object.entries(models).map(([id, config]) => ({
            id,
            provider: config.provider,
            cost_per_token: config.costPerToken
          }))
        })
      };
    }

    // 获取余额
    if (path === '/balance' && method === 'GET') {
      if (!userId) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: 'Unauthorized' }) };
      }

      const result = await dynamodb.get({
        TableName: getTableName('users'),
        Key: { userId }
      }).promise();

      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ balance: result.Item?.balance || 0 })
      };
    }

    // 充值（简化版，实际应接入支付网关）
    if (path === '/topup' && method === 'POST') {
      if (!userId) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: 'Unauthorized' }) };
      }

      const { amount } = JSON.parse(event.body || '{}');
      if (!amount || amount <= 0) {
        return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'Invalid amount' }) };
      }

      await dynamodb.update({
        TableName: getTableName('users'),
        Key: { userId },
        UpdateExpression: 'SET balance = if_not_exists(balance, :zero) + :amount',
        ExpressionAttributeValues: { ':amount': amount, ':zero': 0 }
      }).promise();

      const result = await dynamodb.get({
        TableName: getTableName('users'),
        Key: { userId }
      }).promise();

      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ success: true, balance: result.Item.balance })
      };
    }

    // 使用量统计
    if (path === '/usage' && method === 'GET') {
      if (!userId) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: 'Unauthorized' }) };
      }

      const result = await dynamodb.scan({
        TableName: getTableName('usage'),
        FilterExpression: 'userId = :userId',
        ExpressionAttributeValues: { ':userId': userId }
      }).promise();

      const totalTokens = result.Items.reduce((sum, item) => sum + (item.tokens || 0), 0);
      const totalCost = result.Items.reduce((sum, item) => sum + (item.cost || 0), 0);

      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ totalTokens, totalCost, requests: result.Items.length })
      };
    }

    // 聊天补全
    if (path === '/chat/completions' && method === 'POST') {
      // API Key认证
      const apiKeyHeader = event.headers?.['x-api-key'];
      let apiKeyUserId = null;

      if (apiKeyHeader) {
        const keyResult = await dynamodb.get({
          TableName: getTableName('api-keys'),
          Key: { apiKey: apiKeyHeader }
        }).promise();

        if (keyResult.Item) {
          apiKeyUserId = keyResult.Item.userId;
        }
      }

      if (!userId && !apiKeyUserId) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: 'Authentication required' }) };
      }

      const effectiveUserId = userId || apiKeyUserId;

      // 检查余额
      const userResult = await dynamodb.get({
        TableName: getTableName('users'),
        Key: { userId: effectiveUserId }
      }).promise();

      if (!userResult.Item || userResult.Item.balance <= 0) {
        return { statusCode: 402, headers: corsHeaders, body: JSON.stringify({ error: 'Insufficient balance' }) };
      }

      const body = JSON.parse(event.body || '{}');
      const { model, messages } = body;

      if (!model || !messages) {
        return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'Missing model or messages' }) };
      }

      if (!models[model]) {
        return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: `Model '${model}' not supported`, available: Object.keys(models) }) };
      }

      const modelConfig = models[model];
      const upstreamApiKey = process.env.MIMO_API_KEY;

      if (!upstreamApiKey) {
        return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: 'API key not configured' }) };
      }

      // 转发请求
      const response = await axios.post(modelConfig.upstream, {
        model,
        messages,
        stream: false
      }, {
        headers: {
          'Authorization': `Bearer ${upstreamApiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 60000
      });

      // 计算费用
      const tokensUsed = response.data.usage?.total_tokens || 0;
      const cost = tokensUsed * modelConfig.costPerToken;

      // 扣费
      await dynamodb.update({
        TableName: getTableName('users'),
        Key: { userId: effectiveUserId },
        UpdateExpression: 'SET balance = balance - :cost',
        ExpressionAttributeValues: { ':cost': cost }
      }).promise();

      // 记录使用量
      await dynamodb.put({
        TableName: getTableName('usage'),
        Item: {
          apiKey: apiKeyHeader || 'direct',
          userId: effectiveUserId,
          timestamp: new Date().toISOString(),
          model,
          tokens: tokensUsed,
          cost
        }
      }).promise();

      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify(response.data)
      };
    }

    // 创建API Key
    if (path === '/api-keys' && method === 'POST') {
      if (!userId) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: 'Unauthorized' }) };
      }

      const { name } = JSON.parse(event.body || '{}');
      const apiKey = `sk-${uuidv4().replace(/-/g, '')}`;

      await dynamodb.put({
        TableName: getTableName('api-keys'),
        Item: {
          apiKey,
          userId,
          name: name || 'Default Key',
          createdAt: new Date().toISOString(),
          isActive: true
        }
      }).promise();

      return {
        statusCode: 201,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey, name: name || 'Default Key' })
      };
    }

    // 获取API Keys
    if (path === '/api-keys' && method === 'GET') {
      if (!userId) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: 'Unauthorized' }) };
      }

      const result = await dynamodb.scan({
        TableName: getTableName('api-keys'),
        FilterExpression: 'userId = :userId',
        ExpressionAttributeValues: { ':userId': userId }
      }).promise();

      return {
        statusCode: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKeys: result.Items })
      };
    }

    // 删除API Key
    if (path.startsWith('/api-keys/') && method === 'DELETE') {
      if (!userId) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: 'Unauthorized' }) };
      }

      const apiKey = path.split('/api-keys/')[1];
      
      // 验证所有权
      const keyResult = await dynamodb.get({
        TableName: getTableName('api-keys'),
        Key: { apiKey }
      }).promise();

      if (!keyResult.Item || keyResult.Item.userId !== userId) {
        return { statusCode: 404, headers: corsHeaders, body: JSON.stringify({ error: 'API key not found' }) };
      }

      await dynamodb.delete({
        TableName: getTableName('api-keys'),
        Key: { apiKey }
      }).promise();

      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify({ success: true })
      };
    }

    return { statusCode: 404, headers: corsHeaders, body: JSON.stringify({ error: 'Not found' }) };

  } catch (error) {
    console.error('API error:', error.message);
    
    if (error.response) {
      return { statusCode: error.response.status, headers: corsHeaders, body: JSON.stringify(error.response.data) };
    }

    return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: 'Internal server error' }) };
  }
};
