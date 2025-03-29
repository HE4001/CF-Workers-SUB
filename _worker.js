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
 * 处理登录请求
 * @param {Request} request - 请求对象
 * @returns {Response} 响应对象
 */
async function handleLoginRequest(request) {
  const url = new URL(request.url);
  const password = url.searchParams.get('password');
  
  if (!password) {
    return errorResponse('请输入密码');
  }
  
  // 验证密码
  const hashedPassword = await MD5MD5(password);
  const adminPasswordHash = await MD5MD5(CONFIG.auth.adminToken);
  
  if (hashedPassword !== adminPasswordHash) {
    return errorResponse('密码错误');
  }
  
  // 生成令牌
  const token = generateUUID();
  const expiryDate = new Date();
  expiryDate.setHours(expiryDate.getHours() + CONFIG.auth.tokenExpiry);
  
  // 设置Cookie
  const response = new Response(null, {
    status: 302,
    headers: {
      'Location': '/',
      'Set-Cookie': `token=${token}; Path=/; Expires=${expiryDate.toUTCString()}; HttpOnly; SameSite=Strict`
    }
  });
  
  return response;
}

/**
 * 渲染登录页面
 * @returns {Response} 响应对象
 */
function renderLoginPage() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="login-container">
    <h1>登录</h1>
    <form action="/login" method="get">
      <div class="form-group">
        <label for="password">密码</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">登录</button>
    </form>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}

/**
 * 渲染仪表盘页面
 * @param {Object} data - 数据对象
 * @param {boolean} isAdmin - 是否为管理员
 * @returns {Response} 响应对象
 */
function renderDashboard(data, isAdmin) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>仪表盘 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="dashboard-container">
    <h1>仪表盘</h1>
    ${isAdmin ? `
    <div class="admin-section">
      <h2>管理员功能</h2>
      <ul>
        <li><a href="/subscriptions">管理订阅</a></li>
        <li><a href="/settings">系统设置</a></li>
      </ul>
    </div>
    ` : ''}
    <div class="user-section">
      <h2>用户信息</h2>
      <p>欢迎回来！</p>
    </div>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}

/**
 * 渲染订阅列表页面
 * @param {Array} subscriptions - 订阅列表
 * @param {boolean} isAdmin - 是否为管理员
 * @returns {Response} 响应对象
 */
function renderSubscriptionList(subscriptions, isAdmin) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>订阅列表 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="subscription-container">
    <h1>订阅列表</h1>
    ${subscriptions.length > 0 ? `
    <table>
      <thead>
        <tr>
          <th>名称</th>
          <th>状态</th>
          <th>最后更新</th>
          ${isAdmin ? '<th>操作</th>' : ''}
        </tr>
      </thead>
      <tbody>
        ${subscriptions.map(sub => `
        <tr>
          <td>${sub.name}</td>
          <td class="${sub.lastStatus === 'success' ? 'tag-success' : 'tag-error'}">${sub.lastStatus}</td>
          <td>${sub.lastUpdated ? new Date(sub.lastUpdated).toLocaleString() : '从未'}</td>
          ${isAdmin ? `
          <td>
            <a href="/subscriptions/${sub.id}/edit">编辑</a>
            <a href="/subscriptions/${sub.id}/delete">删除</a>
          </td>
          ` : ''}
        </tr>
        `).join('')}
      </tbody>
    </table>
    ` : `
    <p>暂无订阅</p>
    `}
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}
/**
 * 处理订阅请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权访问此订阅');
  }
  
  // 返回订阅内容
  return new Response(subscription.content, {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
    },
  });
}

/**
 * 处理订阅转换请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionConvertRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  const format = url.searchParams.get('format') || 'clash';
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权访问此订阅');
  }
  
  // 转换订阅格式
  const convertedContent = await convertSubscription(subscription.content, format);
  if (!convertedContent) {
    return errorResponse('订阅转换失败');
  }
  
  // 返回转换后的内容
  return new Response(convertedContent, {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
    },
  });
}

/**
 * 转换订阅格式
 * @param {string} content - 订阅内容
 * @param {string} format - 目标格式
 * @returns {Promise<string>} 转换后的内容
 */
async function convertSubscription(content, format) {
  const url = `https://${CONFIG.subscription.subConverter}/sub?target=${format}&url=${encodeURIComponent(content)}`;
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      timeout: CONFIG.subscription.timeout,
    });
    
    if (!response.ok) {
      throw new Error(`转换失败: ${response.statusText}`);
    }
    
    return await response.text();
  } catch (error) {
    console.error('订阅转换失败:', error);
    return null;
  }
}

/**
 * 处理订阅更新请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionUpdateRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权更新此订阅');
  }
  
  // 更新订阅内容
  const updatedContent = await updateSubscription(subscriptionId);
  if (!updatedContent) {
    return errorResponse('订阅更新失败');
  }
  
  // 返回更新后的内容
  return new Response(updatedContent, {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
    },
  });
}

/**
 * 更新订阅内容
 * @param {string} subscriptionId - 订阅ID
 * @returns {Promise<string>} 更新后的内容
 */
async function updateSubscription(subscriptionId) {
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return null;
  }
  
  try {
    const response = await fetch(subscription.url, {
      method: 'GET',
      timeout: CONFIG.subscription.timeout,
    });
    
    if (!response.ok) {
      throw new Error(`更新失败: ${response.statusText}`);
    }
    
    const content = await response.text();
    await saveSubscription(subscriptionId, content);
    
    return content;
  } catch (error) {
    console.error('订阅更新失败:', error);
    return null;
  }
}
/**
 * 处理订阅编辑请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionEditRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权编辑此订阅');
  }
  
  // 渲染编辑页面
  return renderSubscriptionEditPage(subscription);
}

/**
 * 渲染订阅编辑页面
 * @param {Object} subscription - 订阅信息
 * @returns {Response} 响应对象
 */
function renderSubscriptionEditPage(subscription) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>编辑订阅 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="subscription-edit-container">
    <h1>编辑订阅</h1>
    <form action="/subscriptions/${subscription.id}/save" method="post">
      <div class="form-group">
        <label for="name">名称</label>
        <input type="text" id="name" name="name" value="${subscription.name}" required>
      </div>
      <div class="form-group">
        <label for="url">URL</label>
        <input type="url" id="url" name="url" value="${subscription.url}" required>
      </div>
      <div class="form-group">
        <label for="owner">所有者</label>
        <input type="text" id="owner" name="owner" value="${subscription.owner}" required>
      </div>
      <button type="submit">保存</button>
    </form>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}

/**
 * 处理订阅保存请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionSaveRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取表单数据
  const formData = await request.formData();
  const name = formData.get('name');
  const url = formData.get('url');
  const owner = formData.get('owner');
  
  if (!name || !url || !owner) {
    return errorResponse('缺少必要字段');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权保存此订阅');
  }
  
  // 保存订阅信息
  await saveSubscription(subscriptionId, {
    ...subscription,
    name,
    url,
    owner
  });
  
  // 重定向到订阅列表
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/subscriptions',
    },
  });
}
/**
 * 处理订阅删除请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionDeleteRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权删除此订阅');
  }
  
  // 删除订阅
  await deleteSubscription(subscriptionId);
  
  // 重定向到订阅列表
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/subscriptions',
    },
  });
}

/**
 * 处理订阅列表请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionListRequest(request, auth) {
  // 获取所有订阅
  const subscriptions = await listSubscriptions();
  
  // 过滤用户可见的订阅
  const visibleSubscriptions = subscriptions.filter(subscription => 
    auth.isAdmin || subscription.owner === auth.token
  );
  
  // 渲染订阅列表页面
  return renderSubscriptionListPage(visibleSubscriptions);
}

/**
 * 渲染订阅列表页面
 * @param {Array} subscriptions - 订阅列表
 * @returns {Response} 响应对象
 */
function renderSubscriptionListPage(subscriptions) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>订阅列表 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="subscription-list-container">
    <h1>订阅列表</h1>
    <table>
      <thead>
        <tr>
          <th>名称</th>
          <th>URL</th>
          <th>所有者</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        ${subscriptions.map(subscription => `
          <tr>
            <td>${subscription.name}</td>
            <td>${subscription.url}</td>
            <td>${subscription.owner}</td>
            <td>
              <a href="/subscriptions/${subscription.id}/edit">编辑</a>
              <a href="/subscriptions/${subscription.id}/delete" onclick="return confirm('确定删除吗？')">删除</a>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}
/**
 * 处理订阅创建请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionCreateRequest(request, auth) {
  // 获取表单数据
  const formData = await request.formData();
  const name = formData.get('name');
  const url = formData.get('url');
  const owner = formData.get('owner');
  
  if (!name || !url || !owner) {
    return errorResponse('缺少必要字段');
  }
  
  // 检查权限
  if (!auth.isAdmin && owner !== auth.token) {
    return errorResponse('无权创建此订阅');
  }
  
  // 创建订阅
  const subscriptionId = await createSubscription({
    name,
    url,
    owner
  });
  
  // 重定向到订阅列表
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/subscriptions',
    },
  });
}

/**
 * 渲染订阅创建页面
 * @returns {Response} 响应对象
 */
function renderSubscriptionCreatePage() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>创建订阅 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="subscription-create-container">
    <h1>创建订阅</h1>
    <form action="/subscriptions/create" method="post">
      <div class="form-group">
        <label for="name">名称</label>
        <input type="text" id="name" name="name" required>
      </div>
      <div class="form-group">
        <label for="url">URL</label>
        <input type="url" id="url" name="url" required>
      </div>
      <div class="form-group">
        <label for="owner">所有者</label>
        <input type="text" id="owner" name="owner" required>
      </div>
      <button type="submit">创建</button>
    </form>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}

/**
 * 处理订阅详情请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionDetailRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权查看此订阅');
  }
  
  // 渲染订阅详情页面
  return renderSubscriptionDetailPage(subscription);
}

/**
 * 渲染订阅详情页面
 * @param {Object} subscription - 订阅信息
 * @returns {Response} 响应对象
 */
function renderSubscriptionDetailPage(subscription) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>订阅详情 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="subscription-detail-container">
    <h1>订阅详情</h1>
    <div class="subscription-info">
      <p><strong>名称:</strong> ${subscription.name}</p>
      <p><strong>URL:</strong> ${subscription.url}</p>
      <p><strong>所有者:</strong> ${subscription.owner}</p>
    </div>
    <div class="actions">
      <a href="/subscriptions/${subscription.id}/edit">编辑</a>
      <a href="/subscriptions/${subscription.id}/delete" onclick="return confirm('确定删除吗？')">删除</a>
    </div>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}
/**
 * 处理订阅导出请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionExportRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权导出此订阅');
  }
  
  // 导出订阅为 JSON
  const json = JSON.stringify(subscription, null, 2);
  
  return new Response(json, {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': `attachment; filename="${subscription.name}.json"`
    },
  });
}

/**
 * 处理订阅导入请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionImportRequest(request, auth) {
  // 获取上传的文件
  const formData = await request.formData();
  const file = formData.get('file');
  
  if (!file) {
    return errorResponse('请选择要导入的文件');
  }
  
  // 读取文件内容
  const text = await file.text();
  let subscription;
  try {
    subscription = JSON.parse(text);
  } catch (e) {
    return errorResponse('文件格式错误');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权导入此订阅');
  }
  
  // 创建订阅
  const subscriptionId = await createSubscription(subscription);
  
  // 重定向到订阅列表
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/subscriptions',
    },
  });
}

/**
 * 渲染订阅导入页面
 * @returns {Response} 响应对象
 */
function renderSubscriptionImportPage() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>导入订阅 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="subscription-import-container">
    <h1>导入订阅</h1>
    <form action="/subscriptions/import" method="post" enctype="multipart/form-data">
      <div class="form-group">
        <label for="file">选择文件</label>
        <input type="file" id="file" name="file" accept=".json" required>
      </div>
      <button type="submit">导入</button>
    </form>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}
/**
 * 处理订阅编辑请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionEditRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权编辑此订阅');
  }
  
  // 获取表单数据
  const formData = await request.formData();
  const name = formData.get('name');
  const url = formData.get('url');
  const owner = formData.get('owner');
  
  if (!name || !url || !owner) {
    return errorResponse('缺少必要字段');
  }
  
  // 更新订阅
  await updateSubscription(subscriptionId, {
    name,
    url,
    owner
  });
  
  // 重定向到订阅列表
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/subscriptions',
    },
  });
}

/**
 * 渲染订阅编辑页面
 * @param {Object} subscription - 订阅信息
 * @returns {Response} 响应对象
 */
function renderSubscriptionEditPage(subscription) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>编辑订阅 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="subscription-edit-container">
    <h1>编辑订阅</h1>
    <form action="/subscriptions/${subscription.id}/edit" method="post">
      <div class="form-group">
        <label for="name">名称</label>
        <input type="text" id="name" name="name" value="${subscription.name}" required>
      </div>
      <div class="form-group">
        <label for="url">URL</label>
        <input type="url" id="url" name="url" value="${subscription.url}" required>
      </div>
      <div class="form-group">
        <label for="owner">所有者</label>
        <input type="text" id="owner" name="owner" value="${subscription.owner}" required>
      </div>
      <button type="submit">保存</button>
    </form>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}

/**
 * 处理订阅搜索请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionSearchRequest(request, auth) {
  const url = new URL(request.url);
  const query = url.searchParams.get('q');
  
  if (!query) {
    return errorResponse('缺少搜索关键词');
  }
  
  // 获取所有订阅
  const subscriptions = await listSubscriptions();
  
  // 过滤用户可见的订阅
  const visibleSubscriptions = subscriptions.filter(subscription => 
    (auth.isAdmin || subscription.owner === auth.token) &&
    (subscription.name.includes(query) || subscription.url.includes(query))
  );
  
  // 渲染订阅列表页面
  return renderSubscriptionListPage(visibleSubscriptions);
}
/**
 * 处理订阅删除请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionDeleteRequest(request, auth) {
  const url = new URL(request.url);
  const subscriptionId = url.pathname.split('/')[2];
  
  if (!subscriptionId) {
    return errorResponse('缺少订阅ID');
  }
  
  // 获取订阅信息
  const subscription = await getSubscription(subscriptionId);
  if (!subscription) {
    return errorResponse('订阅不存在');
  }
  
  // 检查权限
  if (!auth.isAdmin && subscription.owner !== auth.token) {
    return errorResponse('无权删除此订阅');
  }
  
  // 删除订阅
  await deleteSubscription(subscriptionId);
  
  // 重定向到订阅列表
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/subscriptions',
    },
  });
}

/**
 * 渲染订阅列表页面
 * @param {Array} subscriptions - 订阅列表
 * @returns {Response} 响应对象
 */
function renderSubscriptionListPage(subscriptions) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>订阅列表 - ${CONFIG.ui.title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="subscription-list-container">
    <h1>订阅列表</h1>
    <div class="actions">
      <a href="/subscriptions/create">创建订阅</a>
      <a href="/subscriptions/import">导入订阅</a>
    </div>
    <table>
      <thead>
        <tr>
          <th>名称</th>
          <th>URL</th>
          <th>所有者</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        ${subscriptions.map(subscription => `
          <tr>
            <td>${subscription.name}</td>
            <td>${subscription.url}</td>
            <td>${subscription.owner}</td>
            <td>
              <a href="/subscriptions/${subscription.id}">查看</a>
              <a href="/subscriptions/${subscription.id}/edit">编辑</a>
              <a href="/subscriptions/${subscription.id}/delete" onclick="return confirm('确定删除吗？')">删除</a>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
  });
}

/**
 * 处理订阅列表请求
 * @param {Request} request - 请求对象
 * @param {Object} auth - 认证信息
 * @returns {Response} 响应对象
 */
async function handleSubscriptionListRequest(request, auth) {
  // 获取所有订阅
  const subscriptions = await listSubscriptions();
  
  // 过滤用户可见的订阅
  const visibleSubscriptions = subscriptions.filter(subscription => 
    auth.isAdmin || subscription.owner === auth.token
  );
  
  // 渲染订阅列表页面
  return renderSubscriptionListPage(visibleSubscriptions);
}
