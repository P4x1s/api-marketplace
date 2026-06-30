const AWS = require('aws-sdk');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const dynamodb = new AWS.DynamoDB.DocumentClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

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

function getTableName(suffix) {
  return `api-marketplace-${suffix}`;
}

function createToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64');
  return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
  try {
    const [header, body, signature] = token.split('.');
    const expectedSignature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64');
    if (signature !== expectedSignature) return null;
    return JSON.parse(Buffer.from(body, 'base64').toString());
  } catch {
    return null;
  }
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
