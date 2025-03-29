/**
 * 多功能订阅聚合器 for Cloudflare Workers
 * 支持多种客户端格式：Base64、Clash、Singbox、Surge、Quantumult X、Loon
 * 
 * 功能特点:
 * - 聚合多个订阅源
 * - 多格式转换
 * - 安全的认证机制
 * - 在线配置界面
 */

// 配置对象，集中管理所有设置
const CONFIG = {
  // 认证相关配置
  auth: {
    // 主令牌，用于管理员访问，必须在环境变量中设置
    adminToken: '',
    // 访客令牌，权限受限
    guestToken: '',
    // 令牌有效期（小时）
    tokenExpiry: 24,
  },
  
  // 订阅相关配置
  subscription: {
    // 默认文件名
    fileName: 'nodes',
    // 订阅更新时间（小时）
    updateInterval: 6,
    // 默认订阅容量（TB）
    defaultTotal: 99,
    // 默认过期时间戳（毫秒）- 2099-12-31
    defaultExpiry: 4102329600000,
    // 默认转换后端
    subConverter: 'api.v1.mk',
    // 请求超时时间（毫秒）
    timeout: 5000,
  },
  
  // UI配置
  ui: {
    // 站点标题
    title: '订阅聚合管理器',
    // 主题颜色
    themeColor: '#42b983',
    // 页头图标URL
    favicon: '',
  }
};

// 加载环境变量覆盖默认配置
function loadConfig(env) {
  try {
    // 认证配置
    CONFIG.auth.adminToken = env.ADMIN_TOKEN || CONFIG.auth.adminToken;
    CONFIG.auth.guestToken = env.GUEST_TOKEN || CONFIG.auth.guestToken || generateUUID();
    CONFIG.auth.tokenExpiry = parseInt(env.TOKEN_EXPIRY) || CONFIG.auth.tokenExpiry;
    
    // 订阅配置
    CONFIG.subscription.fileName = env.FILE_NAME || CONFIG.subscription.fileName;
    CONFIG.subscription.updateInterval = parseInt(env.UPDATE_INTERVAL) || CONFIG.subscription.updateInterval;
    CONFIG.subscription.subConverter = env.SUB_CONVERTER || CONFIG.subscription.subConverter;
    CONFIG.subscription.timeout = parseInt(env.TIMEOUT) || CONFIG.subscription.timeout;
    
    // UI配置
    CONFIG.ui.title = env.SITE_TITLE || CONFIG.ui.title;
    CONFIG.ui.themeColor = env.THEME_COLOR || CONFIG.ui.themeColor;
    CONFIG.ui.favicon = env.FAVICON || CONFIG.ui.favicon;
    
    // 验证关键配置
    if (!CONFIG.auth.adminToken || CONFIG.auth.adminToken === 'auto') {
      console.warn('警告: 未设置安全的管理员令牌，请在环境变量中设置 ADMIN_TOKEN');
      // 如果未设置，生成随机令牌并记录到日志
      CONFIG.auth.adminToken = generateUUID();
      console.log('自动生成管理员令牌: ' + CONFIG.auth.adminToken);
    }
    
    return true;
  } catch (error) {
    console.error('加载配置失败:', error);
    return false;
  }
}

/**
 * 辅助函数: 生成UUID v4
 * @returns {string} UUID字符串
 */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/**
 * 辅助函数: MD5 哈希
 * @param {string} input - 输入字符串
 * @returns {Promise<string>} MD5哈希值
 */
async function MD5(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('MD5', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 辅助函数: 双重MD5哈希
 * @param {string} input - 输入字符串
 * @returns {Promise<string>} 双重MD5哈希值
 */
async function MD5MD5(input) {
  return MD5(await MD5(input));
}

/**
 * 辅助函数: Base64解码
 * @param {string} str - Base64编码的字符串
 * @returns {string} 解码后的字符串
 */
function base64Decode(str) {
  try {
    return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  } catch (e) {
    console.error('Base64解码失败:', e);
    return '';
  }
}

/**
 * 辅助函数: 验证是否为有效的Base64编码
 * @param {string} str - 待验证的字符串
 * @returns {boolean} 是否有效
 */
function isValidBase64(str) {
  try {
    return btoa(atob(str)) === str;
  } catch (e) {
    return false;
  }
}
/**
 * 辅助函数: 生成错误响应
 * @param {string} message - 错误消息
 * @param {number} status - HTTP状态码
 * @returns {Response} 响应对象
 */
function errorResponse(message, status = 403) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>错误 - ${CONFIG.ui.title}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background-color: #f5f5f5;
    }
    .error-container {
      background: white;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      max-width: 90%;
      width: 400px;
      text-align: center;
    }
    h2 {
      color: #e74c3c;
      margin-top: 0;
    }
    p {
      color: #444;
      line-height: 1.5;
    }
    .back-button {
      display: inline-block;
      margin-top: 1rem;
      padding: 0.5rem 1rem;
      background-color: #3498db;
      color: white;
      text-decoration: none;
      border-radius: 4px;
      transition: background-color 0.2s;
    }
    .back-button:hover {
      background-color: #2980b9;
    }
  </style>
</head>
<body>
  <div class="error-container">
    <h2>访问错误</h2>
    <p>${message}</p>
    <a href="/" class="back-button">返回首页</a>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}


/**
 * 辅助函数: 格式化字节大小
 * @param {number} bytes - 字节数
 * @returns {string} 格式化后的字符串
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  
  return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * 辅助函数: 安全URL处理
 * @param {string} url - 输入URL
 * @returns {URL|null} 解析后的URL对象或null
 */
function parseURL(url) {
  try {
    // 确保URL包含协议
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    return new URL(url);
  } catch (e) {
    console.error('URL解析失败:', e);
    return null;
  }
}

/**
 * 辅助函数: 生成当前日期的时间戳(当天0点)
 * @returns {number} 时间戳(秒)
 */
function getTodayTimestamp() {
  const currentDate = new Date();
  currentDate.setHours(0, 0, 0, 0);
  return Math.ceil(currentDate.getTime() / 1000);
}
/**
 * 认证验证
 * @param {Request} request - 请求对象
 * @returns {Object} 包含认证结果和令牌信息
 */
async function authenticateRequest(request, env) {
  const url = new URL(request.url);
  const tokenParam = url.searchParams.get('token');
  let token = '';
  let isAdmin = false;
  let isGuest = false;
  
  // 检查请求中的令牌
  if (tokenParam) {
    // URL参数中的令牌
    token = tokenParam;
  } else if (url.pathname.includes('/' + CONFIG.auth.adminToken)) {
    // 令牌在路径中
    token = CONFIG.auth.adminToken;
  } else {
    // 从Cookie中获取令牌
    const cookies = request.headers.get('Cookie') || '';
    const tokenCookie = cookies.split(';').find(c => c.trim().startsWith('token='));
    if (tokenCookie) {
      token = tokenCookie.split('=')[1].trim();
    }
  }
  
  // 验证令牌
  if (token === CONFIG.auth.adminToken) {
    isAdmin = true;
  } else if (token === CONFIG.auth.guestToken) {
    isGuest = true;
  }
  
  return {
    isAuthenticated: isAdmin || isGuest,
    isAdmin,
    isGuest,
    token
  };
}

/**
 * 主要请求处理函数
 */
async function handleRequest(request, env) {
  // 加载配置
  loadConfig(env);
  
  const url = new URL(request.url);
  const auth = await authenticateRequest(request, env);
  
  // 处理根路径访问
  if (url.pathname === '/' || url.pathname === '') {
    // 如果已经认证，显示管理界面
    if (auth.isAuthenticated) {
      return renderDashboard(auth);
    }
    // 未认证，显示登录界面
    return renderLoginPage();
  }
  
  // 处理登录请求
  if (url.pathname === '/login' && request.method === 'POST') {
    return handleLoginRequest(request);
  }
  
  // 处理API请求
  if (url.pathname.startsWith('/api/')) {
    return handleApiRequest(request, auth, env);
  }
  
  // 处理订阅请求
  if (url.pathname.startsWith('/sub/')) {
    return handleSubscriptionRequest(request, url, auth, env);
  }
  
  // 处理静态资源
  if (url.pathname.startsWith('/assets/')) {
    return handleAssetRequest(url.pathname);
  }
  
  // 如果是管理员令牌在路径中，重定向到主页并设置Cookie
  if (auth.isAuthenticated && url.pathname.includes('/' + auth.token)) {
    return Response.redirect(`${url.origin}/`, 302);
  }
  
  // 未找到资源
  return errorResponse('请求的资源不存在', 404);
}

/**
 * 处理登录请求
 */
async function handleLoginRequest(request) {
  try {
    const formData = await request.formData();
    const password = formData.get('password');
    
    if (!password) {
      return errorResponse('请输入密码', 400);
    }
    
    if (password === CONFIG.auth.adminToken) {
      const response = Response.redirect('/', 302);
      response.headers.set('Set-Cookie', `token=${CONFIG.auth.adminToken}; path=/; HttpOnly; SameSite=Lax; Max-Age=${CONFIG.auth.tokenExpiry * 3600}`);
      return response;
    } else if (password === CONFIG.auth.guestToken) {
      const response = Response.redirect('/', 302);
      response.headers.set('Set-Cookie', `token=${CONFIG.auth.guestToken}; path=/; HttpOnly; SameSite=Lax; Max-Age=${CONFIG.auth.tokenExpiry * 3600}`);
      return response;
    }
    
    return errorResponse('密码错误', 401);
  } catch (error) {
    console.error('登录处理失败:', error);
    return errorResponse('服务器内部错误', 500);
  }
}
/**
 * 处理API请求
 */
async function handleApiRequest(request, auth, env) {
  const url = new URL(request.url);
  const endpoint = url.pathname.replace('/api/', '');
  
  // 要求认证的API端点
  if (!auth.isAuthenticated) {
    return new Response(JSON.stringify({ error: '未授权访问' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // 只有管理员可访问的API端点
  if (!auth.isAdmin && ['add-subscription', 'delete-subscription', 'update-config'].includes(endpoint)) {
    return new Response(JSON.stringify({ error: '权限不足' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  switch (endpoint) {
    case 'list-subscriptions':
      return handleListSubscriptions(env);
    case 'add-subscription':
      return handleAddSubscription(request, env);
    case 'delete-subscription':
      return handleDeleteSubscription(request, env);
    case 'update-config':
      return handleUpdateConfig(request, env);
    case 'test-subscription':
      return handleTestSubscription(request);
    default:
      return new Response(JSON.stringify({ error: '未知API端点' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
  }
}

/**
 * 处理API: 列出所有订阅
 */
async function handleListSubscriptions(env) {
  if (!env.SUBLIST) {
    return new Response(JSON.stringify({ 
      error: '未绑定KV空间', 
      message: '请在Worker设置中绑定名为SUBLIST的KV命名空间' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  try {
    // 获取所有订阅键
    const listKeys = await env.SUBLIST.list();
    const subscriptions = [];
    
    // 获取每个订阅的详细信息
    for (const key of listKeys.keys) {
      try {
        const value = await env.SUBLIST.get(key.name);
        if (value) {
          subscriptions.push({
            name: key.name,
            ...JSON.parse(value)
          });
        }
      } catch (error) {
        console.error('取订阅 ' + key.name + ' 失败:', error);
      }
    }
    
    return new Response(JSON.stringify({ 
      success: true, 
      subscriptions 
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('列出订阅失败:', error);
    return new Response(JSON.stringify({ 
      error: '获取订阅列表失败', 
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * 处理API: 添加订阅
 */
async function handleAddSubscription(request, env) {
  if (!env.SUBLIST) {
    return new Response(JSON.stringify({ 
      error: '未绑定KV空间', 
      message: '请在Worker设置中绑定名为SUBLIST的KV命名空间' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  try {
    const { name, url, type, enabled, remark } = await request.json();
    
    if (!name || !url) {
      return new Response(JSON.stringify({ 
        error: '缺少必要参数', 
        message: '名称和URL是必须的' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 验证URL格式
    if (!parseURL(url)) {
      return new Response(JSON.stringify({ 
        error: 'URL格式无效', 
        message: '请输入有效的URL' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 存储订阅
    const subscription = {
      url,
      type: type || 'common',
      enabled: enabled !== false,
      remark: remark || '',
      addedAt: Date.now(),
      lastUpdated: null,
      lastStatus: null
    };
    
    await env.SUBLIST.put(name, JSON.stringify(subscription));
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: '订阅添加成功',
      subscription: {
        name,
        ...subscription
      }
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('添加订阅失败:', error);
    return new Response(JSON.stringify({ 
      error: '添加订阅失败', 
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * 处理API: 删除订阅
 */
async function handleDeleteSubscription(request, env) {
  if (!env.SUBLIST) {
    return new Response(JSON.stringify({ 
      error: '未绑定KV空间', 
      message: '请在Worker设置中绑定名为SUBLIST的KV命名空间' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  try {
    const { name } = await request.json();
    
    if (!name) {
      return new Response(JSON.stringify({ 
        error: '缺少必要参数', 
        message: '订阅名称是必须的' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 检查订阅是否存在
    const exists = await env.SUBLIST.get(name);
    if (!exists) {
      return new Response(JSON.stringify({ 
        error: '订阅不存在', 
        message: '为 ' + name + ' 的订阅不存在' 
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 删除订阅
    await env.SUBLIST.delete(name);
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: '订阅删除成功' 
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('删除订阅失败:', error);
    return new Response(JSON.stringify({ 
      error: '删除订阅失败', 
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
/**
 * 处理API: 更新配置
 */
async function handleUpdateConfig(request, env) {
  try {
    const config = await request.json();
    
    // 更新配置
    if (config.auth) {
      if (config.auth.adminToken) CONFIG.auth.adminToken = config.auth.adminToken;
      if (config.auth.guestToken) CONFIG.auth.guestToken = config.auth.guestToken;
      if (config.auth.tokenExpiry) CONFIG.auth.tokenExpiry = config.auth.tokenExpiry;
    }
    
    if (config.subscription) {
      if (config.subscription.fileName) CONFIG.subscription.fileName = config.subscription.fileName;
      if (config.subscription.updateInterval) CONFIG.subscription.updateInterval = config.subscription.updateInterval;
      if (config.subscription.subConverter) CONFIG.subscription.subConverter = config.subscription.subConverter;
      if (config.subscription.timeout) CONFIG.subscription.timeout = config.subscription.timeout;
    }
    
    if (config.ui) {
      if (config.ui.title) CONFIG.ui.title = config.ui.title;
      if (config.ui.themeColor) CONFIG.ui.themeColor = config.ui.themeColor;
      if (config.ui.favicon) CONFIG.ui.favicon = config.ui.favicon;
    }
    
    // 生成要保存的环境变量
    const envVars = {
      ADMIN_TOKEN: CONFIG.auth.adminToken,
      GUEST_TOKEN: CONFIG.auth.guestToken,
      TOKEN_EXPIRY: CONFIG.auth.tokenExpiry.toString(),
      FILE_NAME: CONFIG.subscription.fileName,
      UPDATE_INTERVAL: CONFIG.subscription.updateInterval.toString(),
      SUB_CONVERTER: CONFIG.subscription.subConverter,
      TIMEOUT: CONFIG.subscription.timeout.toString(),
      SITE_TITLE: CONFIG.ui.title,
      THEME_COLOR: CONFIG.ui.themeColor,
      FAVICON: CONFIG.ui.favicon,
    };
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: '配置更新成功',
      config: CONFIG,
      envVars
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('更新配置失败:', error);
    return new Response(JSON.stringify({ 
      error: '更新配置失败', 
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * 处理API: 测试订阅
 */
async function handleTestSubscription(request) {
  try {
    const { url } = await request.json();
    
    if (!url) {
      return new Response(JSON.stringify({ 
        error: '缺少必要参数', 
        message: 'URL是必须的' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 验证URL
    const parsedURL = parseURL(url);
    if (!parsedURL) {
      return new Response(JSON.stringify({ 
        error: 'URL格式无效', 
        message: '请输入有效的URL' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 获取订阅内容
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.subscription.timeout);
    
    try {
      const response = await fetch(parsedURL.toString(), {
        signal: controller.signal,
        headers: {
          'User-Agent': 'SubManager/1.0'
        }
      });
      
      clearTimeout(timeout);
      
      if (!response.ok) {
        return new Response(JSON.stringify({ 
          error: '获取订阅失败', 
          message: `服务器返回错误代码: ${response.status}` 
        }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const content = await response.text();
      let isBase64 = isValidBase64(content);
      let nodeCount = 0;
      
      // 尝试分析节点数量
      if (isBase64) {
        const decodedContent = base64Decode(content);
        nodeCount = (decodedContent.match(/vmess:\/\//g) || []).length +
                   (decodedContent.match(/trojan:\/\//g) || []).length +
                   (decodedContent.match(/ss:\/\//g) || []).length +
                   (decodedContent.match(/ssr:\/\//g) || []).length;
      } else {
        try {
          // 尝试解析为JSON
          const json = JSON.parse(content);
          if (json.proxies && Array.isArray(json.proxies)) {
            nodeCount = json.proxies.length;
          } else if (json.outbounds && Array.isArray(json.outbounds)) {
            nodeCount = json.outbounds.filter(o => o.type !== 'direct').length;
          }
        } catch (e) {
          // 非JSON格式，尝试其他格式的解析
          nodeCount = (content.match(/vmess:\/\//g) || []).length +
                     (content.match(/trojan:\/\//g) || []).length +
                     (content.match(/ss:\/\//g) || []).length +
                     (content.match(/ssr:\/\//g) || []).length;
        }
      }
      
      return new Response(JSON.stringify({ 
        success: true, 
        message: '测试成功',
        format: isBase64 ? 'Base64' : '其他格式',
        size: content.length,
        sizeFormatted: formatBytes(content.length),
        nodeCount
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      clearTimeout(timeout);
      return new Response(JSON.stringify({ 
        error: '获取订阅失败', 
        message: error.message 
      }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error('测试订阅失败:', error);
    return new Response(JSON.stringify({ 
      error: '测试订阅失败', 
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * 获取文件扩展名
 */
function getFileExtension(format) {
  const formatMap = {
    'base64': 'txt',
    'clash': 'yaml',
    'singbox': 'json',
    'surge': 'conf',
    'surfboard': 'conf',
    'quanx': 'conf',
    'loon': 'conf',
    'shadowrocket': 'conf'
  };
  
  return formatMap[format.toLowerCase()] || 'txt';
}

/**
 * 处理订阅请求
 */
async function handleSubscriptionRequest(request, url, auth, env) {
  if (!env.SUBLIST) {
    return errorResponse('订阅功能未正确配置: 未绑定KV空间', 500);
  }
  
  // /sub/[type]/[filename].[format]?token=xxx
  // 例如: /sub/base64/mysub.txt?token=xxxx
  // 例如: /sub/clash/mysub.yaml
  
  try {
    const pathParts = url.pathname.replace('/sub/', '').split('/');
    
    if (pathParts.length < 2) {
      return errorResponse('订阅格式错误: 格式应为 /sub/[type]/[filename].[format]', 400);
    }
    
    const format = pathParts[0];
    let filenamePart = pathParts[1];
    let filename = filenamePart;
    
    // 如果文件名包含扩展名，提取文件名
    if (filenamePart.includes('.')) {
      filename = filenamePart.split('.')[0];
    }
    
    // 验证请求的格式是否支持
    const supportedFormats = ['base64', 'clash', 'singbox', 'surge', 'surfboard', 'quanx', 'loon', 'shadowrocket'];
    if (!supportedFormats.includes(format.toLowerCase())) {
      return errorResponse('不支持的订阅格式: ' + format, 400);
    }
    
    // 如果客户端要求验证，但未提供令牌，返回错误
    if (!auth.isAuthenticated) {
      return errorResponse('需要授权才能访问订阅', 401);
    }
    
    // 获取所有启用的订阅源
    const listResult = await env.SUBLIST.list();
    const subscriptions = [];
    
    for (const key of listResult.keys) {
      const data = await env.SUBLIST.get(key.name, { type: 'json' });
      if (data && data.enabled) {
        subscriptions.push({
          name: key.name,
          ...data
        });
      }
    }
    
    if (subscriptions.length === 0) {
      return errorResponse('没有可用的订阅源', 404);
    }
    
    // 获取每个订阅的内容并合并
    const contents = [];
    
    for (const sub of subscriptions) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), CONFIG.subscription.timeout);
        
        const response = await fetch(sub.url, {
          signal: controller.signal,
          headers: {
            'User-Agent': 'SubManager/1.0'
          }
        });
        
        clearTimeout(timeout);
        
        if (!response.ok) {
          console.error(`获取订阅 ${sub.name} 失败: ${response.status}`);
          continue;
        }
        
        let content = await response.text();
        
        // 如果内容是Base64且需要解码
        if (isValidBase64(content) && format !== 'base64') {
          content = base64Decode(content);
        }
        
        contents.push(content);
      } catch (error) {
        console.error(`获取订阅 ${sub.name} 失败:`, error);
      }
    }
    
    if (contents.length === 0) {
      return errorResponse('所有订阅源获取失败', 502);
    }
    
    // 合并所有订阅内容
    let mergedContent = '';
    
    // 对于Base64格式，直接合并文本后重新编码
    if (format === 'base64') {
      const decodedContents = [];
      
      for (const content of contents) {
        if (isValidBase64(content)) {
          decodedContents.push(base64Decode(content));
        } else {
          decodedContents.push(content);
        }
      }
      
      mergedContent = btoa(decodedContents.join('\n'));
    } else {
      // 对于其他格式，使用订阅转换API
      try {
        const convertUrl = 'https://' + CONFIG.subscription.subConverter + '/sub?target=' + format + '&url=' + encodeURIComponent(btoa(contents.join('\n')));
        
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), CONFIG.subscription.timeout);
        
        const response = await fetch(convertUrl, {
          signal: controller.signal,
          headers: {
            'User-Agent': 'SubManager/1.0'
          }
        });
        
        clearTimeout(timeout);
        
        if (!response.ok) {
          return errorResponse('订阅格式转换失败: ' + response.status, 502);
        }
        
        mergedContent = await response.text();
      } catch (error) {
        return errorResponse('订阅格式转换失败: ' + error.message, 502);
      }
    }
    
    // 设置Content-Disposition为下载文件
    const fileExtension = getFileExtension(format);
    const contentDisposition = `attachment; filename="${filename}.${fileExtension}"`;
    
    // 设置适当的Content-Type
    let contentType = 'text/plain';
    if (fileExtension === 'yaml') contentType = 'application/yaml';
    if (fileExtension === 'json') contentType = 'application/json';
    
    return new Response(mergedContent, {
      headers: {
        'Content-Type': contentType + '; charset=utf-8',
        'Content-Disposition': contentDisposition,
        'Cache-Control': 'max-age=300', // 缓存5分钟
        'Subscription-UserInfo': `upload=0; download=0; total=${CONFIG.subscription.defaultTotal * 1073741824}; expire=${CONFIG.subscription.defaultExpiry}`
      }
    });
  } catch (error) {
    console.error('处理订阅请求失败:', error);
    return errorResponse('服务器内部错误: ' + error.message, 500);
  }
}
/**
 * 处理静态资源请求
 */
async function handleAssetRequest(path) {
  // 简单的资源路由
  if (path === '/assets/favicon.ico') {
    // 返回网站图标
    return new Response(null, {
      status: 302,
      headers: {
        'Location': CONFIG.ui.favicon || 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png'
      }
    });
  }
  
  // 对于其他资源，返回404
  return new Response('Not Found', { status: 404 });
}

/**
 * 渲染登录页面
 */
function renderLoginPage() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录 - ${CONFIG.ui.title}</title>
  <link rel="icon" href="/assets/favicon.ico" type="image/x-icon">
  <style>
    :root {
      --theme-color: ${CONFIG.ui.themeColor};
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background-color: #f5f5f5;
    }
    .login-container {
      background: white;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      max-width: 90%;
      width: 360px;
      text-align: center;
    }
    h1 {
      color: var(--theme-color);
      margin-top: 0;
      font-size: 1.8rem;
    }
    .form-group {
      margin-bottom: 1.5rem;
    }
    .form-control {
      width: 100%;
      padding: 0.75rem;
      border: 1px solid #ced4da;
      border-radius: 4px;
      transition: border-color 0.15s ease-in-out;
      box-sizing: border-box;
    }
    .form-control:focus {
      border-color: var(--theme-color);
      outline: 0;
      box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25);
    }
    .btn {
      display: block;
      width: 100%;
      padding: 0.75rem;
      background-color: var(--theme-color);
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
      transition: background-color 0.15s ease-in-out;
    }
    .btn:hover {
      background-color: #0056b3;
    }
    .footer {
      margin-top: 2rem;
      color: #6c757d;
      font-size: 0.9rem;
    }
    .footer a {
      color: var(--theme-color);
      text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>${CONFIG.ui.title}</h1>
    <form action="/login" method="POST">
      <div class="form-group">
        <input type="password" class="form-control" name="password" placeholder="请输入访问密码" required>
      </div>
      <button type="submit" class="btn">登录</button>
    </form>
    <div class="footer">
      <p>多功能订阅聚合管理器</p>
    </div>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    }
  });
}

/**
 * 渲染管理仪表板
 */
function renderDashboard(auth) {
  const isAdmin = auth.isAdmin;
  
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${CONFIG.ui.title}</title>
  <link rel="icon" href="/assets/favicon.ico" type="image/x-icon">
  <style>
    :root {
      --theme-color: ${CONFIG.ui.themeColor};
    }
    * {
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 0;
      color: #333;
      background-color: #f9f9f9;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }
    header {
      background-color: var(--theme-color);
      color: white;
      padding: 1rem;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    h1, h2, h3 {
      margin: 0;
    }
    header h1 {
      font-size: 1.5rem;
    }
    .dashboard {
      display: flex;
      flex-wrap: wrap;
      gap: 20px;
      margin-top: 20px;
    }
    .card {
      background-color: white;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
      overflow: hidden;
      flex: 1;
      min-width: 300px;
    }
    .card-header {
      background-color: var(--theme-color);
      color: white;
      padding: 15px;
      font-weight: bold;
    }
    .card-body {
      padding: 15px;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
      padding-bottom: 8px;
      border-bottom: 1px solid #eee;
    }
    .info-row:last-child {
      border-bottom: none;
    }
    .info-label {
      font-weight: bold;
      color: #555;
    }
    .table {
      width: 100%;
      border-collapse: collapse;
    }
    .table th, .table td {
      padding: 12px 15px;
      text-align: left;
      border-bottom: 1px solid #eee;
    }
    .table th {
      background-color: #f5f5f5;
      font-weight: bold;
      color: #333;
    }
    .btn {
      padding: 8px 12px;
      border-radius: 4px;
      background-color: var(--theme-color);
      color: white;
      border: none;
      cursor: pointer;
      font-size: 14px;
      margin-right: 5px;
    }
    .btn-danger {
      background-color: #dc3545;
    }
    .btn-success {
      background-color: #28a745;
    }
    .btn:hover {
      opacity: 0.9;
    }
    .form-container {
      margin-top: 15px;
    }
    .form-group {
      margin-bottom: 15px;
    }
    .form-label {
      display: block;
      margin-bottom: 5px;
      font-weight: bold;
    }
    .form-control {
      width: 100%;
      padding: 8px 12px;
      border: 1px solid #ced4da;
      border-radius: 4px;
    }
    .flex-between {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: bold;
    }
    .badge-success {
      background-color: #d4f7e6;
      color: #0f5132;
    }
    .badge-danger {
      background-color: #f7d7da;
      color: #842029;
    }
    .mb-2 {
      margin-bottom: 10px;
    }
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.5);
      justify-content: center;
      align-items: center;
      z-index: 1000;
    }
    .modal-content {
      background-color: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
      width: 90%;
      max-width: 500px;
    }
    .hidden {
      display: none;
    }
    .nav-tabs {
      display: flex;
      list-style: none;
      padding: 0;
      margin: 0 0 20px 0;
      border-bottom: 1px solid #ddd;
    }
    .nav-tabs li {
      margin-right: 5px;
    }
    .nav-tabs a {
      display: block;
      padding: 10px 15px;
      text-decoration: none;
      color: #555;
      border-bottom: 3px solid transparent;
    }
    .nav-tabs a.active {
      color: var(--theme-color);
      border-bottom-color: var(--theme-color);
    }
    .tab-content > div {
      display: none;
    }
    .tab-content > div.active {
      display: block;
    }
    .subscription-url {
      font-family: monospace;
      background-color: #f8f9fa;
      padding: 10px;
      border-radius: 4px;
      overflow: auto;
    }
    #errorMessage {
      background-color: #f8d7da;
      color: #721c24;
      padding: 10px;
      border-radius: 4px;
      margin-bottom: 15px;
      display: none;
    }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1>${CONFIG.ui.title}</h1>
    </div>
  </header>
  
  <div class="container">
    <div class="nav-tabs">
      <li><a href="#dashboard" class="active">控制面板</a></li>
      <li><a href="#subscriptions">订阅列表</a></li>
      <li><a href="#add-subscription">添加订阅</a></li>
      ${isAdmin ? '<li><a href="#settings">系统设置</a></li>' : ''}
    </div>
    
    <div class="tab-content">
      <div id="dashboard" class="active">
        <div class="dashboard">
          <div class="card">
            <div class="card-header">系统信息</div>
            <div class="card-body">
              <div class="info-row">
                <span class="info-label">版本</span>
                <span>1.0.0</span>
              </div>
              <div class="info-row">
                <span class="info-label">订阅格式</span>
                <span>Base64, Clash, SingBox, Surge, Quan X, Loon</span>
              </div>
              <div class="info-row">
                <span class="info-label">权限模式</span>
                <span>${isAdmin ? '管理员' : '访客'}</span>
              </div>
              <div class="info-row">
                <span class="info-label">转换后端</span>
                <span>${CONFIG.subscription.subConverter}</span>
              </div>
            </div>
          </div>
          
          <div class="card">
            <div class="card-header">订阅用量</div>
            <div class="card-body">
              <div id="usage-loading">加载中...</div>
              <div id="usage-content" class="hidden">
                <div class="info-row">
                  <span class="info-label">订阅源数量</span>
                  <span id="sub-count">-</span>
                </div>
                <div class="info-row">
                  <span class="info-label">已启用源</span>
                  <span id="enabled-count">-</span>
                </div>
                <div class="info-row">
                  <span class="info-label">总节点数</span>
                  <span id="node-count">-</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="card mt-3" style="margin-top: 20px;">
          <div class="card-header">订阅链接</div>
          <div class="card-body">
            <p>使用以下链接将节点添加到您的客户端：</p>
            
            <div class="mb-2">
              <div class="form-label">Base64 (通用格式)</div>
              <div class="subscription-url">
                ${window.location.origin}/sub/base64/nodes.txt?token=${auth.token}
              </div>
            </div>
            
            <div class="mb-2">
              <div class="form-label">Clash</div>
              <div class="subscription-url">
                ${window.location.origin}/sub/clash/nodes.yaml?token=${auth.token}
              </div>
            </div>
            
            <div class="mb-2">
              <div class="form-label">SingBox</div>
              <div class="subscription-url">
                ${window.location.origin}/sub/singbox/nodes.json?token=${auth.token}
              </div>
            </div>
            
            <div class="mb-2">
              <div class="form-label">Surge</div>
              <div class="subscription-url">
                ${window.location.origin}/sub/surge/nodes.conf?token=${auth.token}
              </div>
            </div>
            
            <div class="mb-2">
              <div class="form-label">Quantumult X</div>
              <div class="subscription-url">
                ${window.location.origin}/sub/quanx/nodes.conf?token=${auth.token}
              </div>
            </div>
            
            <div class="mb-2">
              <div class="form-label">Loon</div>
              <div class="subscription-url">
                ${window.location.origin}/sub/loon/nodes.conf?token=${auth.token}
              </div>
            </div>
          </div>
        </div>
      </div>
      <div id="subscriptions" class="hidden">
        <div class="card">
          <div class="card-header flex-between">
            <span>订阅列表</span>
            <button class="btn" onclick="refreshSubscriptions()">刷新</button>
          </div>
          <div class="card-body">
            <div id="subscription-loading">加载中...</div>
            <div id="subscription-table" class="hidden">
              <table class="table">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>URL</th>
                    <th>类型</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody id="subscription-list">
                  <!-- 订阅列表将在这里动态生成 -->
                </tbody>
              </table>
            </div>
            <div id="no-subscriptions" class="hidden">
              <p>没有添加任何订阅源。点击"添加订阅"来添加您的第一个订阅。</p>
            </div>
          </div>
        </div>
      </div>
      
      <div id="add-subscription" class="hidden">
        <div class="card">
          <div class="card-header">添加新订阅</div>
          <div class="card-body">
            <div id="errorMessage"></div>
            
            <div class="form-container">
              <div class="form-group">
                <label class="form-label">订阅名称</label>
                <input type="text" class="form-control" id="subName" placeholder="为订阅源起一个名字" required>
              </div>
              
              <div class="form-group">
                <label class="form-label">订阅地址</label>
                <input type="text" class="form-control" id="subUrl" placeholder="订阅链接地址" required>
              </div>
              
              <div class="form-group">
                <label class="form-label">订阅类型</label>
                <select class="form-control" id="subType">
                  <option value="common">通用订阅</option>
                  <option value="clash">Clash配置</option>
                  <option value="singbox">SingBox配置</option>
                </select>
              </div>
              
              <div class="form-group">
                <label class="form-label">备注</label>
                <input type="text" class="form-control" id="subRemark" placeholder="可选: 添加订阅备注">
              </div>
              
              <div class="form-group">
                <button class="btn" id="testSubscription">测试连接</button>
                <button class="btn btn-success" id="addSubscription" ${isAdmin ? '' : 'disabled'}>
                  添加订阅
                </button>
              </div>
              
              <div id="testResult" class="hidden">
                <div class="card">
                  <div class="card-header">测试结果</div>
                  <div class="card-body">
                    <div class="info-row">
                      <span class="info-label">状态</span>
                      <span id="test-status">-</span>
                    </div>
                    <div class="info-row">
                      <span class="info-label">格式</span>
                      <span id="test-format">-</span>
                    </div>
                    <div class="info-row">
                      <span class="info-label">大小</span>
                      <span id="test-size">-</span>
                    </div>
                    <div class="info-row">
                      <span class="info-label">节点数</span>
                      <span id="test-node-count">-</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      ${isAdmin ? `
      <div id="settings" class="hidden">
        <div class="card">
          <div class="card-header">系统设置</div>
          <div class="card-body">
            <ul class="nav-tabs">
              <li><a href="#basic-settings" class="active">基本设置</a></li>
              <li><a href="#auth-settings">认证设置</a></li>
            </ul>
            
            <div class="tab-content">
              <div id="basic-settings" class="active">
                <div class="form-group">
                  <label class="form-label">站点标题</label>
                  <input type="text" class="form-control" id="siteTitle" value="${CONFIG.ui.title}">
                </div>
                
                <div class="form-group">
                  <label class="form-label">主题颜色</label>
                  <input type="color" class="form-control" id="themeColor" value="${CONFIG.ui.themeColor}">
                </div>
                
                <div class="form-group">
                  <label class="form-label">站点图标</label>
                  <input type="text" class="form-control" id="favicon" value="${CONFIG.ui.favicon}">
                </div>
                
                <div class="form-group">
                  <label class="form-label">订阅转换后端</label>
                  <input type="text" class="form-control" id="subConverter" value="${CONFIG.subscription.subConverter}">
                </div>
                
                <div class="form-group">
                  <label class="form-label">请求超时 (毫秒)</label>
                  <input type="number" class="form-control" id="timeout" value="${CONFIG.subscription.timeout}">
                </div>
              </div>
              
              <div id="auth-settings" class="hidden">
                <div class="form-group">
                  <label class="form-label">管理员令牌</label>
                  <input type="text" class="form-control" id="adminToken" value="${CONFIG.auth.adminToken}">
                </div>
                
                <div class="form-group">
                  <label class="form-label">访客令牌</label>
                  <input type="text" class="form-control" id="guestToken" value="${CONFIG.auth.guestToken}">
                </div>
                
                <div class="form-group">
                  <label class="form-label">令牌有效期 (小时)</label>
                  <input type="number" class="form-control" id="tokenExpiry" value="${CONFIG.auth.tokenExpiry}">
                </div>
              </div>
            </div>
            
            <div class="form-group" style="margin-top: 15px;">
              <button class="btn btn-success" id="saveSettings">保存设置</button>
            </div>
          </div>
        </div>
      </div>
      ` : ''}
    </div>
  </div>
  
  <!-- 删除确认模态框 -->
  <div class="modal" id="deleteModal">
    <div class="modal-content">
      <h3>确认删除</h3>
      <p>您确定要删除此订阅吗？此操作无法撤销。</p>
      <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;">
        <button class="btn" onclick="document.getElementById('deleteModal').style.display='none'">取消</button>
        <button class="btn btn-danger" id="confirmDelete">删除</button>
      </div>
    </div>
  </div>
  
  <script>
    // 全局变量
    let subscriptionList = [];
    let deleteTargetName = '';
    
    // 初始化
    document.addEventListener('DOMContentLoaded', function() {
      // 标签页切换
      document.querySelectorAll('.nav-tabs a').forEach(tab => {
        tab.addEventListener('click', function(e) {
          e.preventDefault();
          
          // 激活标签
          document.querySelectorAll('.nav-tabs a').forEach(t => t.classList.remove('active'));
          this.classList.add('active');
          
          // 显示内容
          const target = this.getAttribute('href').substring(1);
          document.querySelectorAll('.tab-content > div').forEach(div => {
            div.classList.remove('active');
            div.classList.add('hidden');
          });
          document.getElementById(target).classList.remove('hidden');
          document.getElementById(target).classList.add('active');
        });
      });
      
      // 在设置标签页内的标签页切换
      if (document.querySelectorAll('#settings .nav-tabs a').length > 0) {
        document.querySelectorAll('#settings .nav-tabs a').forEach(tab => {
          tab.addEventListener('click', function(e) {
            e.preventDefault();
            
            // 激活标签
            document.querySelectorAll('#settings .nav-tabs a').forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            
            // 显示内容
            const target = this.getAttribute('href').substring(1);
            document.querySelectorAll('#settings .tab-content > div').forEach(div => {
              div.classList.remove('active');
              div.classList.add('hidden');
            });
            document.getElementById(target).classList.remove('hidden');
            document.getElementById(target).classList.add('active');
          });
        });
      }
      
      // 加载订阅列表
      loadSubscriptions();
      
      // 测试订阅按钮
      document.getElementById('testSubscription').addEventListener('click', testSubscription);
      
      // 添加订阅按钮
      if (document.getElementById('addSubscription')) {
        document.getElementById('addSubscription').addEventListener('click', addSubscription);
      }
      
      // 保存设置按钮
      if (document.getElementById('saveSettings')) {
        document.getElementById('saveSettings').addEventListener('click', saveSettings);
      }
      
      // 确认删除按钮
      document.getElementById('confirmDelete').addEventListener('click', function() {
        deleteSubscription(deleteTargetName);
      });
    });
    // 加载订阅列表
    function loadSubscriptions() {
      document.getElementById('subscription-loading').style.display = 'block';
      document.getElementById('subscription-table').classList.add('hidden');
      document.getElementById('no-subscriptions').classList.add('hidden');
      
      document.getElementById('usage-loading').style.display = 'block';
      document.getElementById('usage-content').classList.add('hidden');
      
      fetch('/api/list-subscriptions')
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            subscriptionList = data.subscriptions || [];
            updateSubscriptionTable();
            updateUsageInfo();
          } else {
            showError(data.error || '加载订阅失败');
          }
        })
        .catch(error => {
          console.error('加载订阅失败:', error);
          showError('加载订阅失败: ' + error.message);
        })
        .finally(() => {
          document.getElementById('subscription-loading').style.display = 'none';
          document.getElementById('usage-loading').style.display = 'none';
        });
    }
    
    // 更新订阅表格
    function updateSubscriptionTable() {
      const tableBody = document.getElementById('subscription-list');
      tableBody.innerHTML = '';
      
      if (subscriptionList.length === 0) {
        document.getElementById('subscription-table').classList.add('hidden');
        document.getElementById('no-subscriptions').classList.remove('hidden');
        return;
      }
      
      document.getElementById('subscription-table').classList.remove('hidden');
      document.getElementById('no-subscriptions').classList.add('hidden');
      
      subscriptionList.forEach(sub => {
        const row = document.createElement('tr');
        
        // 名称
        const nameCell = document.createElement('td');
        nameCell.textContent = sub.name;
        row.appendChild(nameCell);
        
        // URL (截断)
        const urlCell = document.createElement('td');
        const shortUrl = shortenUrl(sub.url);
        urlCell.title = sub.url;
        urlCell.textContent = shortUrl;
        row.appendChild(urlCell);
        
        // 类型
        const typeCell = document.createElement('td');
        typeCell.textContent = sub.type || 'common';
        row.appendChild(typeCell);
        
        // 状态
        const statusCell = document.createElement('td');
        const statusBadge = document.createElement('span');
        statusBadge.classList.add('badge');
        
        if (sub.enabled) {
          statusBadge.classList.add('badge-success');
          statusBadge.textContent = '已启用';
        } else {
          statusBadge.classList.add('badge-danger');
          statusBadge.textContent = '已禁用';
        }
        
        statusCell.appendChild(statusBadge);
        row.appendChild(statusCell);
        
        // 操作
        const actionCell = document.createElement('td');
        
        // 测试按钮
        const testBtn = document.createElement('button');
        testBtn.classList.add('btn');
        testBtn.textContent = '测试';
        testBtn.onclick = function() {
          testExistingSubscription(sub.url);
        };
        actionCell.appendChild(testBtn);
        
        // 删除按钮
        const deleteBtn = document.createElement('button');
        deleteBtn.classList.add('btn', 'btn-danger');
        deleteBtn.textContent = '删除';
        deleteBtn.disabled = !${isAdmin};
        deleteBtn.onclick = function() {
          showDeleteConfirmation(sub.name);
        };
        actionCell.appendChild(deleteBtn);
        
        row.appendChild(actionCell);
        tableBody.appendChild(row);
      });
    }
    
    // 更新用量信息
    function updateUsageInfo() {
      document.getElementById('usage-content').classList.remove('hidden');
      
      const totalCount = subscriptionList.length;
      const enabledCount = subscriptionList.filter(sub => sub.enabled).length;
      
      document.getElementById('sub-count').textContent = totalCount;
      document.getElementById('enabled-count').textContent = enabledCount;
      
      // 节点数需要进一步处理，这里只是示例
      document.getElementById('node-count').textContent = '计算中...';
    }
    
    // 测试订阅
    function testSubscription() {
      const url = document.getElementById('subUrl').value.trim();
      if (!url) {
        showError('请输入订阅地址');
        return;
      }
      
      testExistingSubscription(url);
    }
    
    // 测试已有订阅
    function testExistingSubscription(url) {
      document.getElementById('testResult').classList.add('hidden');
      
      // 先显示loading状态
      document.getElementById('test-status').textContent = '测试中...';
      document.getElementById('test-format').textContent = '-';
      document.getElementById('test-size').textContent = '-';
      document.getElementById('test-node-count').textContent = '-';
      document.getElementById('testResult').classList.remove('hidden');
      
      fetch('/api/test-subscription', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url })
      })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            document.getElementById('test-status').textContent = '成功';
            document.getElementById('test-format').textContent = data.format || '未知';
            document.getElementById('test-size').textContent = data.sizeFormatted || '-';
            document.getElementById('test-node-count').textContent = data.nodeCount || '0';
          } else {
            document.getElementById('test-status').textContent = '失败: ' + (data.message || data.error || '未知错误');
            document.getElementById('test-format').textContent = '-';
            document.getElementById('test-size').textContent = '-';
            document.getElementById('test-node-count').textContent = '-';
          }
        })
        .catch(error => {
          document.getElementById('test-status').textContent = '错误: ' + error.message;
        });
    }
    
    // 添加订阅
    function addSubscription() {
      const name = document.getElementById('subName').value.trim();
      const url = document.getElementById('subUrl').value.trim();
      const type = document.getElementById('subType').value;
      const remark = document.getElementById('subRemark').value.trim();
      
      if (!name || !url) {
        showError('请填写订阅名称和地址');
        return;
      }
      
      // 提交到API
      fetch('/api/add-subscription', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name,
          url,
          type,
          remark,
          enabled: true
        })
      })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            // 清空表单
            document.getElementById('subName').value = '';
            document.getElementById('subUrl').value = '';
            document.getElementById('subRemark').value = '';
            document.getElementById('testResult').classList.add('hidden');
            
            // 刷新列表
            loadSubscriptions();
            
            // 切换到订阅列表标签
            document.querySelector('.nav-tabs a[href="#subscriptions"]').click();
          } else {
            showError(data.error || data.message || '添加订阅失败');
          }
        })
        .catch(error => {
          showError('添加订阅失败: ' + error.message);
        });
    }
    
    // 显示删除确认对话框
    function showDeleteConfirmation(name) {
      deleteTargetName = name;
      document.getElementById('deleteModal').style.display = 'flex';
    }
    
    // 删除订阅
    function deleteSubscription(name) {
      fetch('/api/delete-subscription', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name })
      })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            // 刷新列表
            loadSubscriptions();
            // 关闭模态框
            document.getElementById('deleteModal').style.display = 'none';
          } else {
            showError(data.error || data.message || '删除订阅失败');
          }
        })
        .catch(error => {
          showError('删除订阅失败: ' + error.message);
        });
    }
    
    // 保存系统设置
    function saveSettings() {
      const config = {
        auth: {
          adminToken: document.getElementById('adminToken').value,
          guestToken: document.getElementById('guestToken').value,
          tokenExpiry: parseInt(document.getElementById('tokenExpiry').value) || 24
        },
        subscription: {
          subConverter: document.getElementById('subConverter').value,
          timeout: parseInt(document.getElementById('timeout').value) || 5000
        },
        ui: {
          title: document.getElementById('siteTitle').value,
          themeColor: document.getElementById('themeColor').value,
          favicon: document.getElementById('favicon').value
        }
      };
      
      fetch('/api/update-config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(config)
      })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            alert('设置保存成功，部分设置可能需要刷新页面才能生效');
          } else {
            showError(data.error || data.message || '保存设置失败');
          }
        })
        .catch(error => {
          showError('保存设置失败: ' + error.message);
        });
    }
    
    // 刷新订阅列表
    function refreshSubscriptions() {
      loadSubscriptions();
    }
    
    // 显示错误消息
    function showError(message) {
      const errorDiv = document.getElementById('errorMessage');
      errorDiv.textContent = message;
      errorDiv.style.display = 'block';
      
      // 5秒后自动隐藏
      setTimeout(() => {
        errorDiv.style.display = 'none';
      }, 5000);
    }
    
    // 辅助函数：截断URL
        } else if (password === CONFIG.auth.guestToken) {
          const guestCookie = createSessionCookie('guest', CONFIG.auth.guestToken);
          return Response.redirect(`${url.origin}/`, 302, {
            headers: { 'Set-Cookie': guestCookie }
          });
        } else {
          return Response.redirect(`${url.origin}/?error=1`, 302);
        }
      }
      
      // 处理登出请求
      if (path === '/logout') {
        return Response.redirect(`${url.origin}/`, 302, {
          headers: { 'Set-Cookie': 'session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT' }
        });
      }
      
      // 验证认证状态
      const auth = await authenticate(request, env);
      
      // API请求
      if (path.startsWith('/api/')) {
        return handleApiRequest(request, auth, env);
      }
      
      // 订阅请求
      if (path.startsWith('/sub/')) {
        return handleSubscriptionRequest(request, url, auth, env);
      }
      
      // 静态资源
      if (path.startsWith('/assets/')) {
        return handleAssetRequest(path);
      }
      
      // 主页或其他页面 - 若未认证则显示登录页
      if (!auth.isAuthenticated) {
        return renderLoginPage();
      }
      
      // 已认证，显示仪表板
      return renderDashboard(auth);
    } catch (error) {
      console.error('处理请求时出错:', error);
      return new Response(`服务器错误: ${error.message}`, { status: 500 });
    }
  }
};
