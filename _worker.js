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
    return Response.redirect('{url.origin}/', 302);
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
      response.headers.set('Set-Cookie', 'oken=' + CONFIG.auth.adminToken + '; path=/; HttpOnly; SameSite=Lax; Max-Age=' + CONFIG.auth.tokenExpiry * 3600);
      return response;
    } else if (password === CONFIG.auth.guestToken) {
      const response = Response.redirect('/', 302);
      response.headers.set('Set-Cookie', 'oken=' + CONFIG.auth.guestToken + '; path=/; HttpOnly; SameSite=Lax; Max-Age=' + CONFIG.auth.tokenExpiry * 3600);
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
    if (config.adminToken && config.adminToken !== CONFIG.auth.adminToken) {
      // 存储新的管理员令牌
      // 如果有环境变量持久化机制，可以在这里保存
      CONFIG.auth.adminToken = config.adminToken;
    }
    
    if (config.guestToken && config.guestToken !== CONFIG.auth.guestToken) {
      CONFIG.auth.guestToken = config.guestToken;
    }
    
    if (config.tokenExpiry) {
      CONFIG.auth.tokenExpiry = parseInt(config.tokenExpiry);
    }
    
    if (config.subConverter) {
      CONFIG.subscription.subConverter = config.subConverter;
    }
    
    if (config.timeout) {
      CONFIG.subscription.timeout = parseInt(config.timeout);
    }
    
    if (config.updateInterval) {
      CONFIG.subscription.updateInterval = parseInt(config.updateInterval);
    }
    
    if (config.fileName) {
      CONFIG.subscription.fileName = config.fileName;
    }
    
    if (config.title) {
      CONFIG.ui.title = config.title;
    }
    
    if (config.themeColor) {
      CONFIG.ui.themeColor = config.themeColor;
    }
    
    // 如果有配置存储机制，可以在这里保存
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: '配置更新成功',
      config: {
        adminToken: CONFIG.auth.adminToken,
        guestToken: CONFIG.auth.guestToken,
        tokenExpiry: CONFIG.auth.tokenExpiry,
        subConverter: CONFIG.subscription.subConverter,
        timeout: CONFIG.subscription.timeout,
        updateInterval: CONFIG.subscription.updateInterval,
        fileName: CONFIG.subscription.fileName,
        title: CONFIG.ui.title,
        themeColor: CONFIG.ui.themeColor
      }
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
    
    // 测试订阅连接
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, CONFIG.subscription.timeout);
    
    try {
      const response = await fetch(url, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
      });
      
      clearTimeout(timeout);
      
      if (!response.ok) {
        return new Response(JSON.stringify({ 
          error: '订阅获取失败', 
          message: 'TTP错误: ' + response.status + ' ' + response.statusText 
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const contentType = response.headers.get('Content-Type') || '';
      const content = await response.text();
      
      // 尝试检测订阅类型
      let type = 'unknown';
      let nodeCount = 0;
      
      if (content.includes('proxies:') || content.includes('Proxy:')) {
        type = 'clash';
        // 简单计算节点数
        nodeCount = (content.match(/name:/g) || []).length;
      } else if (content.startsWith('ss://') || content.startsWith('ssr://') || 
                content.startsWith('vmess://') || content.startsWith('trojan://')) {
        type = 'shadowsocks';
        // 计算节点数
        nodeCount = content.split('\n').filter(line => 
          line.startsWith('ss://') || 
          line.startsWith('ssr://') || 
          line.startsWith('vmess://') || 
          line.startsWith('trojan://')
        ).length;
      } else if (isValidBase64(content)) {
        // 尝试Base64解码
        const decoded = base64Decode(content);
        if (decoded.startsWith('ss://') || decoded.startsWith('ssr://') || 
            decoded.startsWith('vmess://') || decoded.startsWith('trojan://')) {
          type = 'base64';
          // 计算节点数
          nodeCount = decoded.split('\n').filter(line => 
            line.startsWith('ss://') || 
            line.startsWith('ssr://') || 
            line.startsWith('vmess://') || 
            line.startsWith('trojan://')
          ).length;
        }
      } else if (content.includes('"outbounds"') || content.includes('"dns"')) {
        type = 'singbox';
      }
      
      return new Response(JSON.stringify({ 
        success: true, 
        message: '订阅测试成功',
        details: {
          type,
          size: content.length,
          formattedSize: formatBytes(content.length),
          contentType,
          nodeCount
        }
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (fetchError) {
      clearTimeout(timeout);
      throw fetchError;
    }
  } catch (error) {
    console.error('测试订阅失败:', error);
    return new Response(JSON.stringify({ 
      error: '测试订阅失败', 
      message: error.name === 'AbortError' ? '请求超时' : error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
/**
 * 处理订阅请求
 */
async function handleSubscriptionRequest(request, url, auth, env) {
  if (!env.SUBLIST) {
    return errorResponse('未绑定KV空间', 500);
  }
  
  // 解析请求路径获取订阅信息
  const pathParts = url.pathname.split('/').filter(Boolean);
  
  // 检查路径格式 /sub/{format}/{filename}
  if (pathParts.length < 2) {
    return errorResponse('无效的订阅路径', 400);
  }
  
  const format = pathParts[1].toLowerCase();
  const filename = pathParts[2] || CONFIG.subscription.fileName;
  
  // 验证格式
  const validFormats = [
    'base64', 'clash', 'singbox', 'surge', 'quan', 'quanx', 'loon', 'surfboard', 'raw'
  ];
  
  if (!validFormats.includes(format)) {
    return errorResponse('支持的订阅格式: ' + format, 400);
  }
  
  // 令牌和缓存检查
  let token = '';
  if (auth.isAuthenticated) {
    token = auth.token;
  } else {
    // 检查URL令牌
    token = url.searchParams.get('token') || '';
    if (token !== CONFIG.auth.adminToken && token !== CONFIG.auth.guestToken) {
      return errorResponse('无效的访问令牌', 403);
    }
  }
  
  try {
    // 聚合所有订阅内容
    const subscriptionContent = await aggregateSubscriptions(env);
    
    if (!subscriptionContent) {
      return errorResponse('无可用订阅或所有订阅获取失败', 500);
    }
    
    // 根据请求的格式转换订阅
    const convertedContent = await convertSubscription(subscriptionContent, format);
    
    // 设置适当的Content-Type
    let contentType = 'text/plain; charset=utf-8';
    if (format === 'clash') {
      contentType = 'text/yaml; charset=utf-8';
    } else if (format === 'singbox') {
      contentType = 'application/json; charset=utf-8';
    }
    
    // 设置Content-Disposition为下载文件
    const fileExtension = getFileExtension(format);
    const contentDisposition = 'ttachment; filename="' + filename + '.' + fileExtension + '"';
    
    return new Response(convertedContent, {
      headers: {
        'Content-Type': contentType,
        'Content-Disposition': contentDisposition,
        'Cache-Control': 'private, max-age=3600',
        'Subscription-UserInfo': generateSubscriptionInfo()
      }
    });
  } catch (error) {
    console.error('处理订阅请求失败:', error);
    return errorResponse('阅处理失败: ' + error.message, 500);
  }
}

/**
 * 获取文件扩展名
 */
function getFileExtension(format) {
  switch (format) {
    case 'clash':
      return 'yaml';
    case 'singbox':
      return 'json';
    case 'surge':
      return 'conf';
    case 'quan':
    case 'quanx':
      return 'conf';
    case 'loon':
      return 'conf';
    case 'surfboard':
      return 'conf';
    default:
      return 'txt';
  }
}

/**
 * 生成订阅信息头
 */
function generateSubscriptionInfo() {
  // 生成虚拟的订阅信息
  const uploadUsed = 0;  // 上传已用
  const downloadUsed = 0;  // 下载已用
  const totalUsed = uploadUsed + downloadUsed;  // 总共已用
  const totalBytes = CONFIG.subscription.defaultTotal * 1024 * 1024 * 1024 * 1024;  // 总流量，单位为字节
  const expiryTimestamp = CONFIG.subscription.defaultExpiry / 1000;  // 过期时间戳，秒
  
  // 格式: upload=已上传字节; download=已下载字节; total=总流量字节; expire=过期时间戳
  return 'pload=' + uploadUsed + '; download=' + downloadUsed + '; total=' + totalBytes + '; expire=' + expiryTimestamp;
}

/**
 * 聚合所有订阅内容
 */
async function aggregateSubscriptions(env) {
  // 获取所有订阅
  const listKeys = await env.SUBLIST.list();
  const activeSubscriptions = [];
  
  // 筛选启用的订阅
  for (const key of listKeys.keys) {
    try {
      const value = await env.SUBLIST.get(key.name);
      if (value) {
        const subscription = JSON.parse(value);
        if (subscription.enabled) {
          activeSubscriptions.push({
            name: key.name,
            ...subscription
          });
        }
      }
    } catch (error) {
      console.error('取订阅 ' + key.name + ' 详情失败:', error);
    }
  }
  
  if (activeSubscriptions.length === 0) {
    return null;
  }
  
  // 并行获取所有订阅内容
  const subscriptionContents = await Promise.allSettled(
    activeSubscriptions.map(async (sub) => {
      try {
        // 设置请求超时
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.subscription.timeout);
        
        const response = await fetch(sub.url, {
          signal: controller.signal,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
          }
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error('TTP error: ' + response.status);
        }
        
        const content = await response.text();
        
        // 更新订阅状态
        sub.lastUpdated = Date.now();
        sub.lastStatus = 'success';
        await env.SUBLIST.put(sub.name, JSON.stringify(sub));
        
        return { name: sub.name, content, type: sub.type };
      } catch (error) {
        // 更新订阅失败状态
        sub.lastUpdated = Date.now();
        sub.lastStatus = 'error';
        sub.lastError = error.message;
        await env.SUBLIST.put(sub.name, JSON.stringify(sub));
        
        throw error;
      }
    })
  );
  
  // 收集成功获取的订阅内容
  const successfulContents = [];
  
  for (let i = 0; i < subscriptionContents.length; i++) {
    const result = subscriptionContents[i];
    if (result.status === 'fulfilled') {
      successfulContents.push(result.value);
    } else {
      console.error('取订阅 ' + activeSubscriptions[i].name + ' 内容失败:', result.reason);
    }
  }
  
  if (successfulContents.length === 0) {
    return null;
  }
  
  // 合并所有订阅
  return mergeSubscriptions(successfulContents);
}
/**
 * 合并多个订阅内容
 */
function mergeSubscriptions(subscriptions) {
  if (subscriptions.length === 0) {
    return '';
  }
  
  if (subscriptions.length === 1) {
    return subscriptions[0].content;
  }
  
  let mergedContent = '';
  const nodesByType = {
    base64: [],
    text: []
  };
  
  // 根据类型分类处理
  for (const sub of subscriptions) {
    const content = sub.content.trim();
    
    // 如果是Base64编码
    if (isValidBase64(content)) {
      const decoded = base64Decode(content);
      
      if (decoded) {
        nodesByType.base64.push({ 
          name: sub.name, 
          content: decoded.split('\n').filter(line => line.trim() !== '')
        });
      }
    } else if (content.startsWith('ss://') || content.startsWith('ssr://') || 
               content.startsWith('vmess://') || content.startsWith('trojan://')) {
      // 直接的节点文本
      nodesByType.text.push({ 
        name: sub.name, 
        content: content.split('\n').filter(line => line.trim() !== '')
      });
    } else {
      // 未知格式，作为文本处理
      nodesByType.text.push({ 
        name: sub.name, 
        content: content.split('\n').filter(line => line.trim() !== '')
      });
    }
  }
  
  // 合并所有节点
  const allNodes = [];
  
  // 处理文本格式的节点
  for (const sub of nodesByType.text) {
    allNodes.push(...sub.content);
  }
  
  // 处理Base64格式的节点
  for (const sub of nodesByType.base64) {
    allNodes.push(...sub.content);
  }
  
  // 去除重复节点
  const uniqueNodes = [...new Set(allNodes)];
  
  // 合并为文本
  mergedContent = uniqueNodes.join('\n');
  
  return mergedContent;
}

/**
 * 转换订阅格式
 */
async function convertSubscription(content, targetFormat) {
  if (targetFormat === 'raw') {
    return content;
  }
  
  if (targetFormat === 'base64') {
    // 检查内容是否已经是Base64编码
    if (isValidBase64(content)) {
      return content;
    }
    return btoa(content);
  }
  
  // 使用订阅转换API
  try {
    const convertUrl = 'ttps://' + CONFIG.subscription.subConverter + '/sub?target=' + targetFormat + '&url=' + encodeURIComponent(btoa(content));
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.subscription.timeout);
    
    const response = await fetch(convertUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      }
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      throw new Error('换API返回错误: ' + response.status);
    }
    
    return await response.text();
  } catch (error) {
    console.error('转换订阅失败:', error);
    throw new Error('换订阅失败: ' + error.message);
  }
}

/**
 * 处理静态资源请求
 */
async function handleAssetRequest(pathname) {
  // 提取资源类型和路径
  const assetPath = pathname.replace('/assets/', '');
  
  // 基于资源类型设置Content-Type
  let contentType = 'text/plain';
  
  if (assetPath.endsWith('.js')) {
    contentType = 'application/javascript';
  } else if (assetPath.endsWith('.css')) {
    contentType = 'text/css';
  } else if (assetPath.endsWith('.png')) {
    contentType = 'image/png';
  } else if (assetPath.endsWith('.jpg') || assetPath.endsWith('.jpeg')) {
    contentType = 'image/jpeg';
  } else if (assetPath.endsWith('.svg')) {
    contentType = 'image/svg+xml';
  } else if (assetPath.endsWith('.json')) {
    contentType = 'application/json';
  }
  
  // 静态资源映射
  const assets = {
        'style.css': `      /* 全局样式 */
      :root {
        --primary-color: ${CONFIG.ui.themeColor};
        --primary-dark: ${CONFIG.ui.themeColor}dd;
        --primary-light: ${CONFIG.ui.themeColor}33;
        --text-color: #333;
        --bg-color: #f5f5f5;
        --card-color: #fff;
        --border-color: #eee;
        --error-color: #e74c3c;
        --success-color: #2ecc71;
      }
      
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }
      
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: var(--text-color);
        background-color: var(--bg-color);
        line-height: 1.6;
        display: flex;
        flex-direction: column;
        min-height: 100vh;
      }
      
      header {
        background-color: var(--primary-color);
        color: white;
        padding: 1rem;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      
      main {
        flex: 1;
        padding: 2rem;
        max-width: 1200px;
        margin: 0 auto;
        width: 100%;
      }
      
      footer {
        background-color: #333;
        color: white;
        text-align: center;
        padding: 1rem;
        margin-top: auto;
        font-size: 0.9rem;
      }
      
      h1, h2, h3 {
        margin-bottom: 1rem;
      }
      
      a {
        color: var(--primary-color);
        text-decoration: none;
      }
      
      a:hover {
        text-decoration: underline;
      }
      
      button, .button {
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        cursor: pointer;
        font-size: 1rem;
        transition: background-color 0.2s;
      }
      
      button:hover, .button:hover {
        background-color: var(--primary-dark);
      }
      
      button:disabled, .button:disabled {
        background-color: #ccc;
        cursor: not-allowed;
      }
      
      input, select, textarea {
        width: 100%;
        padding: 0.5rem;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        font-size: 1rem;
        margin-bottom: 1rem;
      }
      
      .card {
        background-color: var(--card-color);
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        padding: 1.5rem;
        margin-bottom: 1.5rem;
      }
      
      .alert {
        padding: 0.75rem 1rem;
        border-radius: 4px;
        margin-bottom: 1rem;
      }
      
      .alert-success {
        background-color: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
      }
      
      .alert-error {
        background-color: #f8d7da;
        color: #721c24;
        border: 1px solid #f5c6cb;
      }
      
      .table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 1rem;
      }
      
      .table th, .table td {
        padding: 0.75rem;
        border-bottom: 1px solid var(--border-color);
        text-align: left;
      }
      
      .table th {
        background-color: #f8f9fa;
      }
      
      .table tr:hover {
        background-color: #f5f5f5;
      }
      
      /* 表单布局 */
      .form-group {
        margin-bottom: 1rem;
      }
      
      .form-label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: 500;
      }
      
      /* 布局工具类 */
      .flex {
        display: flex;
      }
      
      .flex-between {
        justify-content: space-between;
      }
      
      .flex-center {
        justify-content: center;
        align-items: center;
      }
      
      .mt-2 {
        margin-top: 0.5rem;
      }
      
      .mt-4 {
        margin-top: 1rem;
      }
      
      .mb-4 {
        margin-bottom: 1rem;
      }
      
      /* 组件 */
      .tag {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 500;
        margin-right: 0.5rem;
      }
      
      .tag-success {
        background-color: var(--success-color);
        color: white;
      }
      
      .tag-error {
        background-color: var(--error-color);
        color: white;
      }
      
      .tag-primary {
        background-color: var(--primary-color);
        color: white;
      }
      
      /* 响应式 */
      @media (max-width: 768px) {
        main {
          padding: 1rem;
        }
        
        .card {
          padding: 1rem;
        }
      }
    `,

        'app.js': `
      // 主应用脚本
      document.addEventListener('DOMContentLoaded', () => {
        // 初始化应用
        initApp();
      });
      
      // 应用状态
      const state = {
        subscriptions: [],
        loading: false,
        notification: null,
        activeTab: 'subscriptions'
      };
      
      // 初始化应用
      function initApp() {
        // 获取订阅列表
        fetchSubscriptions();
        
        // 注册事件监听器
        registerEventListeners();
        
        // 处理导航标签
        handleTabs();
      }
      
      // 获取订阅列表
      async function fetchSubscriptions() {
        try {
          state.loading = true;
          updateUI();
          
          const response = await fetch('/api/list-subscriptions');
          const data = await response.json();
          
          if (data.error) {
            showNotification(data.error, 'error');
            return;
          }
          
          state.subscriptions = data.subscriptions || [];
          updateUI();
        } catch (error) {
          showNotification('获取订阅列表失败: ' + error.message, 'error');
        } finally {
          state.loading = false;
          updateUI();
        }
      }
      
      // 添加订阅
      async function addSubscription(event) {
        event.preventDefault();
        
        const nameInput = document.querySelector('#subscription-name');
        const urlInput = document.querySelector('#subscription-url');
        const typeSelect = document.querySelector('#subscription-type');
        const remarkInput = document.querySelector('#subscription-remark');
        
        const name = nameInput.value.trim();
        const url = urlInput.value.trim();
        const type = typeSelect.value;
        const remark = remarkInput.value.trim();
        
        if (!name || !url) {
          showNotification('名称和URL是必填项', 'error');
          return;
        }
        
        try {
          state.loading = true;
          updateUI();
          
          const response = await fetch('/api/add-subscription', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, url, type, remark, enabled: true })
          });
          
          const data = await response.json();
          
          if (data.error) {
            showNotification(data.error, 'error');
            return;
          }
          
          showNotification('订阅添加成功', 'success');
          
          // 重置表单
          nameInput.value = '';
          urlInput.value = '';
          remarkInput.value = '';
          
          // 刷新订阅列表
          fetchSubscriptions();
        } catch (error) {
          showNotification('添加订阅失败: ' + error.message, 'error');
        } finally {
          state.loading = false;
          updateUI();
        }
      }
      
      // 删除订阅
      async function deleteSubscription(name) {
        if (!confirm('定要删除订阅 "' + name + '" 吗?')) {
          return;
        }
        
        try {
          state.loading = true;
          updateUI();
          
          const response = await fetch('/api/delete-subscription', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
          });
          
          const data = await response.json();
          
          if (data.error) {
            showNotification(data.error, 'error');
            return;
          }
          
          showNotification('订阅删除成功', 'success');
          
          // 刷新订阅列表
          fetchSubscriptions();
        } catch (error) {
          showNotification('删除订阅失败: ' + error.message, 'error');
        } finally {
          state.loading = false;
          updateUI();
        }
      }
    `
  };

  // 返回请求的资源内容
  if (assets[assetPath]) {
    return new Response(assets[assetPath], {
      headers: { 'Content-Type': contentType }
    });
  }
  
  // 资源不存在
  return new Response('Not Found', { status: 404 });
}
/**
 * 渲染登录页面
 */
function renderLoginPage() {
  const html = '  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - ' + CONFIG.ui.title + '</title>
    <link rel="icon" href="' + CONFIG.ui.favicon || 'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🌐</text></svg>' + '">
    <style>
      :root {
        --primary-color: ' + CONFIG.ui.themeColor + ';
        --bg-color: #f9f9f9;
        --text-color: #333;
        --border-color: #ddd;
        --card-bg: #fff;
        --shadow-color: rgba(0,0,0,0.05);
      }
      
      @media (prefers-color-scheme: dark) {
        :root {
          --bg-color: #121212;
          --text-color: #eee;
          --border-color: #333;
          --card-bg: #1e1e1e;
          --shadow-color: rgba(0,0,0,0.3);
        }
      }
      
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }
      
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: var(--bg-color);
        color: var(--text-color);
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        padding: 1rem;
      }
      
      .login-container {
        background-color: var(--card-bg);
        border-radius: 8px;
        box-shadow: 0 4px 15px var(--shadow-color);
        padding: 2rem;
        width: 100%;
        max-width: 400px;
        transition: all 0.3s ease;
      }
      
      .login-header {
        text-align: center;
        margin-bottom: 2rem;
      }
      
      .login-title {
        font-size: 1.8rem;
        color: var(--primary-color);
        margin-bottom: 0.5rem;
      }
      
      .login-subtitle {
        font-size: 0.9rem;
        color: var(--text-color);
        opacity: 0.7;
      }
      
      .login-form {
        display: flex;
        flex-direction: column;
      }
      
      .form-group {
        margin-bottom: 1.5rem;
      }
      
      .form-label {
        display: block;
        margin-bottom: 0.5rem;
        font-size: 0.9rem;
        font-weight: 500;
      }
      
      .form-input {
        width: 100%;
        padding: 0.75rem 1rem;
        font-size: 1rem;
        background-color: var(--bg-color);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        transition: border-color 0.3s ease;
        color: var(--text-color);
      }
      
      .form-input:focus {
        outline: none;
        border-color: var(--primary-color);
      }
      
      .submit-btn {
        background-color: var(--primary-color);
        color: white;
        border: none;
        border-radius: 4px;
        padding: 0.75rem 1rem;
        font-size: 1rem;
        cursor: pointer;
        transition: background-color 0.3s ease;
      }
      
      .submit-btn:hover {
        background-color: var(--primary-color-dark, var(--primary-color));
        opacity: 0.9;
      }
      
      .version-info {
        text-align: center;
        font-size: 0.8rem;
        margin-top: 2rem;
        color: var(--text-color);
        opacity: 0.5;
      }
    </style>
  </head>
  <body>
    <div class="login-container">
      <div class="login-header">
        <h1 class="login-title">' + CONFIG.ui.title + '</h1>
        <p class="login-subtitle">请输入令牌访问</p>
      </div>
      
      <form class="login-form" action="/login" method="POST">
        <div class="form-group">
          <label for="password" class="form-label">访问令牌</label>
          <input type="password" id="password" name="password" class="form-input" placeholder="请输入访问令牌" required>
        </div>
        
        <button type="submit" class="submit-btn">登录</button>
      </form>
      
      <div class="version-info">
        订阅聚合器 - version 2.0
      </div>
    </div>
  </body>
  </html>
  ';
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

/**
 * 渲染管理面板
 */
function renderDashboard(auth) {
  const isAdmin = auth.isAdmin;
  
  const html = '  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>' + CONFIG.ui.title + ' - 控制面板</title>
    <link rel="icon" href="' + CONFIG.ui.favicon || 'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🌐</text></svg>' + '">
    <link rel="stylesheet" href="/assets/style.css">
    <script src="/assets/app.js" defer></script>
  </head>
  <body>
    <header>
      <h1>' + CONFIG.ui.title + '</h1>
    </header>
    
    <main>
      <div class="flex flex-between mb-4">
        <div>
          <h2>订阅管理</h2>
        </div>
        <div>
          <button id="logout-btn" class="button">退出登录</button>
        </div>
      </div>
      
      <div class="card">
        <h3>我的订阅</h3>
        <div class="mt-4">
          <div class="flex flex-between">
            <div>
              <p>订阅链接（支持多种客户端格式）：</p>
            </div>
            <div>
              <a href="/sub/clash/' + CONFIG.subscription.fileName + '" target="_blank" class="button">Clash</a>
              <a href="/sub/singbox/' + CONFIG.subscription.fileName + '" target="_blank" class="button">SingBox</a>
              <a href="/sub/surge/' + CONFIG.subscription.fileName + '" target="_blank" class="button">Surge</a>
              <a href="/sub/quanx/' + CONFIG.subscription.fileName + '" target="_blank" class="button">QuantumultX</a>
              <a href="/sub/base64/' + CONFIG.subscription.fileName + '" target="_blank" class="button">通用</a>
            </div>
          </div>
          <div class="mt-4">
            <div class="alert">
              <p><strong>注意：</strong> 请使用合适的代理客户端订阅链接，如有疑问请参考帮助文档。</p>
            </div>
          </div>
        </div>
      </div>
      
      <div class="card">
        <h3>订阅源列表</h3>
        <div id="subscription-list-container">
          <div class="loading">加载中...</div>
        </div>
      </div>
      
      ' + 'isAdmin ? '
      <div class="card">
        <h3>添加订阅源</h3>
        <form id="add-subscription-form">
          <div class="form-group">
            <label class="form-label" for="subscription-name">名称</label>
            <input type="text" id="subscription-name" placeholder="给订阅起个名字" required>
          </div>
          
          <div class="form-group">
            <label class="form-label" for="subscription-url">URL</label>
            <input type="url" id="subscription-url" placeholder="订阅链接" required>
          </div>
          
          <div class="form-group">
            <label class="form-label" for="subscription-type">类型</label>
            <select id="subscription-type">
              <option value="base64">通用/Base64</option>
              <option value="clash">Clash</option>
              <option value="singbox">SingBox</option>
            </select>
          </div>
          
          <div class="form-group">
            <label class="form-label" for="subscription-remark">备注</label>
            <textarea id="subscription-remark" placeholder="可选备注信息"></textarea>
          </div>
          
          <button type="submit" class="button">添加订阅</button>
        </form>
      </div>
      
      <div class="card">
        <h3>测试订阅</h3>
        <form id="test-subscription-form">
          <div class="form-group">
            <label class="form-label" for="test-url">URL</label>
            <input type="url" id="test-url" placeholder="输入订阅链接进行测试" required>
          </div>
          
          <button type="submit" class="button">测试连接</button>
        </form>
        
        <div id="test-result" class="mt-4"></div>
      </div>
      `: ''}
    </main>
    
    <footer>
      <p>© ${new Date().getFullYear()} ${CONFIG.ui.title} | Powered by Cloudflare Workers</p>
    </footer>
    
    <div id="notification-container"></div>
    
    <template id="subscription-list-template">
      <table class="table">
        <thead>
          <tr>
            <th>名称</th>
            <th>URL</th>
            <th>状态</th>
            <th>更新时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {{ROWS}}
        </tbody>
      </table>
    </template>
    
    <template id="subscription-row-template">
      <tr>
        <td>{{NAME}}</td>
        <td class="subscription-url">{{URL}}</td>
        <td>
          <span class="tag {{STATUS_CLASS}}">{{STATUS}}</span>
        </td>
        <td>{{UPDATED}}</td>
        <td>
          <button class="button toggle-subscription" data-name="{{NAME}}" data-enabled="{{ENABLED}}">
            {{TOGGLE_TEXT}}
          </button>
          <button class="button delete-subscription" data-name="{{NAME}}">删除</button>
        </td>
      </tr>
    </template>
    
    <script>
      // 退出登录
      document.getElementById('logout-btn').addEventListener('click', function() {
        document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
        window.location.href = '/';
      });
      
      // 显示通知
      function showNotification(message, type = 'info') {
        const container = document.getElementById('notification-container');
        const notification = document.createElement('div');
        notification.className = 'notification ' + type;
        notification.textContent = message;
        
        container.appendChild(notification);
        
        setTimeout(() => {
          notification.style.opacity = '0';
          setTimeout(() => {
            container.removeChild(notification);
          }, 300);
        }, 3000);
      }
      
      // 加载订阅列表
      async function loadSubscriptions() {
        const container = document.getElementById('subscription-list-container');
        
        try {
          const response = await fetch('/api/list-subscriptions');
          const data = await response.json();
          
          if (!data.success) {
            container.innerHTML = '<div class="alert alert-error">' + data.message + '</div>';
            return;
          }
          
          const subscriptions = data.subscriptions || [];
          
          if (subscriptions.length === 0) {
            container.innerHTML = '<div class="alert">还没有订阅源，请添加一个新的订阅。</div>';
            return;
          }
          
          const template = document.getElementById('subscription-list-template').innerHTML;
          let rows = '';
          
          for (const sub of subscriptions) {
            const rowTemplate = document.getElementById('subscription-row-template').innerHTML;
            const statusClass = sub.lastStatus === 'success' ? 'tag-success' : 'tag-error';
            const status = sub.lastStatus === 'success' ? '正常' : '失败';
            const updated = sub.lastUpdated ? new Date(sub.lastUpdated).toLocaleString() : '从未';
            const toggleText = sub.enabled ? '禁用' : '启用';
            
            rows += rowTemplate
              .replace('{{NAME}}', sub.name)
              .replace('{{URL}}', sub.url)
              .replace('{{STATUS_CLASS}}', statusClass)
              .replace('{{STATUS}}', status)
              .replace('{{UPDATED}}', updated)
              .replace('{{ENABLED}}', sub.enabled)
              .replace('{{TOGGLE_TEXT}}', toggleText)
              .replaceAll('{{NAME}}', sub.name);
          }
          
          container.innerHTML = template.replace('{{ROWS}}', rows);
          
          // 添加事件监听器
          document.querySelectorAll('.toggle-subscription').forEach(btn => {
            btn.addEventListener('click', toggleSubscription);
          });
          
          document.querySelectorAll('.delete-subscription').forEach(btn => {
            btn.addEventListener('click', deleteSubscriptionHandler);
          });
        } catch (error) {
          container.innerHTML = '<div class="alert alert-error">加载失败：' + error.message + '</div>';
        }
      }
      
      // 处理订阅开关
      async function toggleSubscription(event) {
        const btn = event.target;
        const name = btn.dataset.name;
        const enabled = btn.dataset.enabled !== 'true';
        
        try {
          const response = await fetch('/api/update-subscription', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, enabled })
          });
          
          const data = await response.json();
          
          if (!data.success) {
            showNotification(data.message || '操作失败', 'error');
            return;
          }
          
          showNotification(`订阅 ${name} ${enabled ? '已启用' : '已禁用'}`, 'success');
          loadSubscriptions();
        } catch (error) {
          showNotification('作失败: ' + error.message, 'error');
        }
      }
      
      // 处理删除订阅
      async function deleteSubscriptionHandler(event) {
        const btn = event.target;
        const name = btn.dataset.name;
        
        if (!confirm('定要删除订阅 "' + name + '" 吗？')) {
          return;
        }
        
        try {
          const response = await fetch('/api/delete-subscription', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
          });
          
          const data = await response.json();
          
          if (!data.success) {
            showNotification(data.message || '删除失败', 'error');
            return;
          }
          
          showNotification('阅 ' + name + ' 已删除', 'success');
          loadSubscriptions();
        } catch (error) {
          showNotification('除失败: ' + error.message, 'error');
        }
      }
      
      // 添加订阅表单处理
      if (document.getElementById('add-subscription-form')) {
        document.getElementById('add-subscription-form').addEventListener('submit', async function(event) {
          event.preventDefault();
          
          const name = document.getElementById('subscription-name').value.trim();
          const url = document.getElementById('subscription-url').value.trim();
          const type = document.getElementById('subscription-type').value;
          const remark = document.getElementById('subscription-remark').value.trim();
          
          if (!name || !url) {
            showNotification('名称和URL不能为空', 'error');
            return;
          }
          
          try {
            const response = await fetch('/api/add-subscription', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ name, url, type, remark, enabled: true })
            });
            
            const data = await response.json();
            
            if (!data.success) {
              showNotification(data.message || '添加失败', 'error');
              return;
            }
            
            showNotification('订阅添加成功', 'success');
            
            // 重置表单
            event.target.reset();
            
            // 刷新列表
            loadSubscriptions();
          } catch (error) {
            showNotification('加失败: ' + error.message, 'error');
          }
        });
      }
      
      // 测试订阅表单处理
      if (document.getElementById('test-subscription-form')) {
        document.getElementById('test-subscription-form').addEventListener('submit', async function(event) {
          event.preventDefault();
          
          const url = document.getElementById('test-url').value.trim();
          const resultContainer = document.getElementById('test-result');
          
          if (!url) {
            showNotification('请输入URL', 'error');
            return;
          }
          
          try {
            resultContainer.innerHTML = '<div class="loading">测试中...</div>';
            
            const response = await fetch('/api/test-subscription', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ url })
            });
            
            const data = await response.json();
            
            if (!data.success) {
              resultContainer.innerHTML = 'div class="alert alert-error">' + data.message || '测试失败' + '</div>';
              return;
            }
            
            const details = data.details;
            resultContainer.innerHTML = '              <div class="alert alert-success">
                <h4>测试成功</h4>
                <p>订阅类型: ' + details.type || '未知' + '</p>
                <p>节点数量: ' + details.nodeCount || '未知' + '</p>
                <p>文件大小: ' + details.formattedSize || '未知' + '</p>
              </div>
            ';
          } catch (error) {
            resultContainer.innerHTML = 'div class="alert alert-error">测试失败: ' + error.message + '</div>';
          }
        });
      }
      
      // 页面加载完成后执行
      document.addEventListener('DOMContentLoaded', function() {
        loadSubscriptions();
      });
    </script>
  </body>
  </html>
  `;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

/**
 * 渲染订阅列表页面
 */
async function renderSubscriptionList(env) {
  if (!env.SUBLIST) {
    return errorResponse('未绑定KV空间', 500);
  }
  
  try {
    // 获取所有订阅
    const listKeys = await env.SUBLIST.list();
    const subscriptions = [];
    
    for (const key of listKeys.keys) {
      try {
        const value = await env.SUBLIST.get(key.name);
        if (value) {
          const sub = JSON.parse(value);
          if (sub.enabled) {
            subscriptions.push({
              name: key.name,
              ...sub
            });
          }
        }
      } catch (error) {
        console.error('取订阅 ' + key.name + ' 详情失败:', error);
      }
    }
    
    // 订阅列表展示页面
    const html = '    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>订阅列表 - ' + CONFIG.ui.title + '</title>
      <link rel="icon" href="' + CONFIG.ui.favicon || 'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🌐</text></svg>' + '">
      <link rel="stylesheet" href="/assets/style.css">
    </head>
    <body>
      <header>
        <h1>' + CONFIG.ui.title + ' - 订阅列表</h1>
      </header>
      
      <main>
        <div class="card">
          <h3>可用订阅格式</h3>
          <div class="mt-4">
            <ul>
              <li><a href="/sub/clash/all">Clash 配置</a></li>
              <li><a href="/sub/singbox/all">SingBox 配置</a></li>
              <li><a href="/sub/surge/all">Surge 配置</a></li>
              <li><a href="/sub/quanx/all">QuantumultX 配置</a></li>
              <li><a href="/sub/loon/all">Loon 配置</a></li>
              <li><a href="/sub/base64/all">通用格式 (Base64)</a></li>
              <li><a href="/sub/raw/all">原始格式 (Raw)</a></li>
            </ul>
            
            <div class="mt-4">
              <a href="/dashboard" class="button">前往管理面板</a>
            </div>
          </div>
        </div>
        
        <div class="card">
          <h3>可用订阅列表</h3>
          ' + 'subscriptions.length > 0 ? '
            <table class="table mt-4">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>描述</th>
                  <th>状态</th>
                  <th>更新时间</th>
                </tr>
              </thead>
              <tbody>
                ${subscriptions.map(sub => '                  <tr>
                    <td>' + sub.name + '</td>
                    <td>' + sub.remark || '-' + '</td>
                    <td>
                      <span class="tag ' + sub.lastStatus === 'success' ? 'tag-success' : 'tag-error' + '">
                        ' + sub.lastStatus === 'success' ? '正常' : '失败' + '
                      </span>
                    </td>
                    <td>' + sub.lastUpdated ? new Date(sub.lastUpdated).toLocaleString() : '从未' + '</td>
                  </tr>
                ').join('')}
              </tbody>
            </table>
          ': '<div class="alert">暂无可用订阅</div>'}
        </div>
      </main>
      
      <footer>
        <p>© ' + new Date().getFullYear() + ' ' + CONFIG.ui.title + ' | Powered by Cloudflare Workers</p>
      </footer>
    </body>
    </html>
    ';
    
    return new Response(html, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  } catch (error) {
    console.error('渲染订阅列表失败:', error);
    return errorResponse('渲染订阅列表失败', 500);
  }
}
/**
 * API处理函数 - 获取订阅列表
 */
async function handleApiListSubscriptions(env) {
  if (!env.SUBLIST) {
    return jsonResponse({ error: '未绑定KV空间' }, 500);
  }
  
  try {
    const listKeys = await env.SUBLIST.list();
    const subscriptions = [];
    
    for (const key of listKeys.keys) {
      try {
        const value = await env.SUBLIST.get(key.name);
        if (value) {
          const sub = JSON.parse(value);
          subscriptions.push({
            name: key.name,
            ...sub
          });
        }
      } catch (error) {
        console.error('取订阅 ' + key.name + ' 详情失败:', error);
      }
    }
    
    return jsonResponse({
      success: true,
      subscriptions
    });
  } catch (error) {
    console.error('获取订阅列表失败:', error);
    return jsonResponse({ error: '获取订阅列表失败' }, 500);
  }
}

/**
 * API处理函数 - 添加订阅
 */
async function handleApiAddSubscription(request, env) {
  if (!env.SUBLIST) {
    return jsonResponse({ error: '未绑定KV空间' }, 500);
  }
  
  try {
    const data = await request.json();
    
    if (!data.name || !data.url) {
      return jsonResponse({ error: '名称和URL是必填项' }, 400);
    }
    
    // 检查名称是否已存在
    const existing = await env.SUBLIST.get(data.name);
    if (existing) {
      return jsonResponse({ error: '订阅名称已存在' }, 400);
    }
    
    // 验证URL
    try {
      new URL(data.url);
    } catch (e) {
      return jsonResponse({ error: '无效的URL格式' }, 400);
    }
    
    // 创建订阅对象
    const subscription = {
      url: data.url,
      type: data.type || 'base64',
      remark: data.remark || '',
      enabled: data.enabled !== false,
      createTime: Date.now(),
      lastUpdated: null,
      lastStatus: null,
      lastError: null
    };
    
    await env.SUBLIST.put(data.name, JSON.stringify(subscription));
    
    return jsonResponse({
      success: true,
      message: '订阅添加成功'
    });
  } catch (error) {
    console.error('添加订阅失败:', error);
    return jsonResponse({ error: '添加订阅失败' }, 500);
  }
}

/**
 * API处理函数 - 删除订阅
 */
async function handleApiDeleteSubscription(request, env) {
  if (!env.SUBLIST) {
    return jsonResponse({ error: '未绑定KV空间' }, 500);
  }
  
  try {
    const data = await request.json();
    
    if (!data.name) {
      return jsonResponse({ error: '订阅名称是必填项' }, 400);
    }
    
    // 检查订阅是否存在
    const existing = await env.SUBLIST.get(data.name);
    if (!existing) {
      return jsonResponse({ error: '订阅不存在' }, 404);
    }
    
    await env.SUBLIST.delete(data.name);
    
    return jsonResponse({
      success: true,
      message: '订阅删除成功'
    });
  } catch (error) {
    console.error('删除订阅失败:', error);
    return jsonResponse({ error: '删除订阅失败' }, 500);
  }
}

/**
 * API处理函数 - 更新订阅
 */
async function handleApiUpdateSubscription(request, env) {
  if (!env.SUBLIST) {
    return jsonResponse({ error: '未绑定KV空间' }, 500);
  }
  
  try {
    const data = await request.json();
    
    if (!data.name) {
      return jsonResponse({ error: '订阅名称是必填项' }, 400);
    }
    
    // 检查订阅是否存在
    const existingValue = await env.SUBLIST.get(data.name);
    if (!existingValue) {
      return jsonResponse({ error: '订阅不存在' }, 404);
    }
    
    const existing = JSON.parse(existingValue);
    
    // 更新订阅
    const subscription = {
      ...existing,
      url: data.url || existing.url,
      type: data.type || existing.type,
      remark: data.remark !== undefined ? data.remark : existing.remark,
      enabled: data.enabled !== undefined ? data.enabled : existing.enabled
    };
    
    await env.SUBLIST.put(data.name, JSON.stringify(subscription));
    
    return jsonResponse({
      success: true,
      message: '订阅更新成功'
    });
  } catch (error) {
    console.error('更新订阅失败:', error);
    return jsonResponse({ error: '更新订阅失败' }, 500);
  }
}

/**
 * API处理函数 - 测试订阅
 */
async function handleApiTestSubscription(request) {
  try {
    const data = await request.json();
    
    if (!data.url) {
      return jsonResponse({ error: '订阅URL是必填项' }, 400);
    }
    
    try {
      new URL(data.url);
    } catch (e) {
      return jsonResponse({ error: '无效的URL格式' }, 400);
    }
    
    // 获取订阅内容
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.subscription.timeout);
    
    const response = await fetch(data.url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      }
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      return jsonResponse({ 
        error: '取订阅失败: HTTP ' + response.status + ' ' + response.statusText 
      }, 400);
    }
    
    const content = await response.text();
    
    // 检测订阅类型和节点数量
    let type = 'unknown';
    let nodeCount = 0;
    
    if (content.startsWith('proxies:') || content.includes('\nproxies:')) {
      type = 'clash';
      // 简单计算节点数量
      nodeCount = (content.match(/- {name|type}/g) || []).length;
    } else if (content.startsWith('{') && content.includes('"outbounds"')) {
      type = 'singbox';
      // 简单计算节点数量
      nodeCount = (content.match(/"tag"|"type"/g) || []).length / 2;
    } else if (isValidBase64(content)) {
      type = 'base64';
      const decoded = base64Decode(content);
      if (decoded) {
        const lines = decoded.split('\n').filter(line => line.trim() !== '');
        nodeCount = lines.length;
      }
    } else if (content.includes('vmess://') || content.includes('ss://') || 
               content.includes('ssr://') || content.includes('trojan://')) {
      type = 'plaintext';
      const lines = content.split('\n')
          .filter(line => line.trim().startsWith('vmess://') || 
                          line.trim().startsWith('ss://') || 
                          line.trim().startsWith('ssr://') || 
                          line.trim().startsWith('trojan://'));
      nodeCount = lines.length;
    }
    
    // 计算大小
    const bytes = new TextEncoder().encode(content).length;
    let formattedSize;
    
    if (bytes < 1024) {
      formattedSize = '{bytes} B';
    } else if (bytes < 1024 * 1024) {
      formattedSize = '{(bytes / 1024).toFixed(2)} KB';
    } else {
      formattedSize = '{(bytes / (1024 * 1024)).toFixed(2)} MB';
    }
    
    return jsonResponse({
      success: true,
      message: '订阅测试成功',
      details: {
        type,
        nodeCount,
        size: bytes,
        formattedSize
      }
    });
  } catch (error) {
    return jsonResponse({ 
      error: '试订阅失败: ' + error.message 
    }, 500);
  }
}

/**
 * 工具函数 - 创建JSON响应
 */
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    },
    status
  });
}

/**
 * 工具函数 - 创建错误响应
 */
function errorResponse(message, status = 400) {
  return new Response(message, {
    status: status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

/**
 * 工具函数 - Base64解码
 */
function base64Decode(str) {
  try {
    return atob(str);
  } catch (e) {
    return null;
  }
}

/**
 * 工具函数 - 检查字符串是否是有效的Base64
 */
function isValidBase64(str) {
  if (!str || typeof str !== 'string') {
    return false;
  }
  
  // 移除可能的尾部换行
  const trimmed = str.trim();
  
  // 长度必须是4的倍数（允许末尾的=填充）
  if (trimmed.length % 4 !== 0 && !trimmed.endsWith('=') && !trimmed.endsWith('==')) {
    return false;
  }
  
  // 只能包含Base64字符
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  if (!base64Regex.test(trimmed)) {
    return false;
  }
  
  // 尝试解码
  try {
    atob(trimmed);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * 处理API请求路由
 */
async function handleApiRequest(request, url, auth, env) {
  if (!auth.isAuthenticated) {
    return jsonResponse({ error: '未授权访问' }, 401);
  }
  
  const apiPath = url.pathname.replace('/api/', '');
  
  // API路由
  if (apiPath === 'list-subscriptions') {
    return handleApiListSubscriptions(env);
  } else if (apiPath === 'add-subscription') {
    if (!auth.isAdmin) {
      return jsonResponse({ error: '需要管理员权限' }, 403);
    }
    return handleApiAddSubscription(request, env);
  } else if (apiPath === 'delete-subscription') {
    if (!auth.isAdmin) {
      return jsonResponse({ error: '需要管理员权限' }, 403);
    }
    return handleApiDeleteSubscription(request, env);
  } else if (apiPath === 'update-subscription') {
    if (!auth.isAdmin) {
      return jsonResponse({ error: '需要管理员权限' }, 403);
    }
    return handleApiUpdateSubscription(request, env);
  } else if (apiPath === 'test-subscription') {
    if (!auth.isAdmin) {
      return jsonResponse({ error: '需要管理员权限' }, 403);
    }
    return handleApiTestSubscription(request);
  }
  
  return jsonResponse({ error: '不支持的API' }, 404);
}

/**
 * 处理登录请求
 */
async function handleLoginRequest(request, env) {
  if (request.method !== 'POST') {
    return errorResponse('方法不允许', 405);
  }
  
  try {
    const formData = await request.formData();
    const password = formData.get('password');
    
    if (!password) {
      return Response.redirect('/');
    }
    
    let isValid = false;
    let isAdmin = false;
    
    // 验证密码
    if (password === CONFIG.auth.adminToken) {
      isValid = true;
      isAdmin = true;
    } else if (password === CONFIG.auth.guestToken) {
      isValid = true;
    }
    
    if (!isValid) {
      return Response.redirect('/');
    }
    
    // 创建响应并设置Cookie
    const response = Response.redirect('/dashboard');
    const expiryDate = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24小时后过期
    
    // 创建加密的token
    const token = await generateAuthToken(password, isAdmin, env);
    
    response.headers.set('Set-Cookie', 'oken=' + token + '; Path=/; Expires=' + expiryDate.toUTCString() + '; HttpOnly; SameSite=Strict');
    
    return response;
  } catch (error) {
    console.error('处理登录请求失败:', error);
    return errorResponse('处理登录请求失败', 500);
  }
}

/**
 * 生成身份验证Token
 */
async function generateAuthToken(password, isAdmin, env) {
  const payload = {
    p: password,
    a: isAdmin ? 1 : 0,
    t: Date.now()
  };
  
  // 简单加密
  const token = btoa(JSON.stringify(payload));
  return token;
}

/**
 * 验证身份
 */
async function authenticate(request, env) {
  // 默认为未授权
  const authResult = {
    isAuthenticated: false,
    isAdmin: false,
    token: null
  };
  
  // 从Cookie中获取令牌
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) {
    return authResult;
  }
  
  const cookies = cookieHeader.split(';').map(cookie => cookie.trim());
  const tokenCookie = cookies.find(cookie => cookie.startsWith('token='));
  
  if (!tokenCookie) {
    return authResult;
  }
  
  const token = tokenCookie.split('=')[1];
  
  try {
    // 解析令牌
    const decodedToken = JSON.parse(atob(token));
    
    // 验证令牌
    if (decodedToken.p === CONFIG.auth.adminToken) {
      authResult.isAuthenticated = true;
      authResult.isAdmin = true;
      authResult.token = token;
    } else if (decodedToken.p === CONFIG.auth.guestToken) {
      authResult.isAuthenticated = true;
      authResult.token = token;
    }
    
    return authResult;
  } catch (error) {
    return authResult;
  }
}

/**
 * 主函数 - 处理请求
 */
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // 鉴权
  const auth = await authenticate(request, env);

  // 处理登录请求
  if (path === '/login') {
    return handleLoginRequest(request, env);
  }
  
  // 处理订阅请求
  if (path.startsWith('/sub/')) {
    return handleSubscriptionRequest(request, url, auth, env);
  }
  
  // 处理静态资源
  if (path.startsWith('/assets/')) {
    return handleAssetRequest(path);
  }
  
  // 处理API请求
  if (path.startsWith('/api/')) {
    return handleApiRequest(request, url, auth, env);
  }
  
  // 路由
  if (path === '/' || path === '/index.html') {
    // 已登录用户重定向到控制面板
    if (auth.isAuthenticated) {
      return Response.redirect('/dashboard');
    }
    return renderLoginPage();
  } else if (path === '/dashboard') {
    if (!auth.isAuthenticated) {
      return Response.redirect('/');
    }
    return renderDashboard(auth);
  } else if (path === '/sublist') {
    return renderSubscriptionList(env);
  }
  
  // 404
  return new Response('Not Found', { status: 404 });
}

// 注册Worker处理程序
export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (error) {
      console.error('未处理的错误:', error);
      return new Response('务器内部错误: ' + error.message, { status: 500 });
    }
  }
};
