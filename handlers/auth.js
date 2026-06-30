const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const dynamodb = new AWS.DynamoDB.DocumentClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// 简单的JWT实现
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
    // 注册
    if (path.endsWith('/register') && method === 'POST') {
      const { email, password, name } = JSON.parse(event.body);
      
      if (!email || !password) {
        return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'Email and password required' }) };
      }

      // 检查邮箱是否已存在
      const existing = await dynamodb.query({
        TableName: 'api-marketplace-users',
        IndexName: 'email-index',
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: { ':email': email }
      }).promise();

      if (existing.Items.length > 0) {
        return { statusCode: 409, headers: corsHeaders, body: JSON.stringify({ error: 'Email already exists' }) };
      }

      const userId = uuidv4();
      const passwordHash = crypto.createHash('sha256').update(password).digest('hex');

      await dynamodb.put({
        TableName: 'api-marketplace-users',
        Item: {
          userId,
          email,
          name: name || email.split('@')[0],
          passwordHash,
          balance: 0,
          createdAt: new Date().toISOString()
        }
      }).promise();

      const token = createToken({ userId, email });
      return { statusCode: 201, headers: corsHeaders, body: JSON.stringify({ token, userId, email }) };
    }

    // 登录
    if (path.endsWith('/login') && method === 'POST') {
      const { email, password } = JSON.parse(event.body);
      
      if (!email || !password) {
        return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'Email and password required' }) };
      }

      const result = await dynamodb.query({
        TableName: 'api-marketplace-users',
        IndexName: 'email-index',
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: { ':email': email }
      }).promise();

      if (result.Items.length === 0) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: 'Invalid credentials' }) };
      }

      const user = result.Items[0];
      const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
      
      if (user.passwordHash !== passwordHash) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: 'Invalid credentials' }) };
      }

      const token = createToken({ userId: user.userId, email: user.email });
      return { statusCode: 200, headers: corsHeaders, body: JSON.stringify({ token, userId: user.userId, email: user.email, balance: user.balance }) };
    }

    return { statusCode: 404, headers: corsHeaders, body: JSON.stringify({ error: 'Not found' }) };

  } catch (error) {
    console.error('Auth error:', error);
    return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: 'Internal server error' }) };
  }
};
