// 主入口
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const userAgent = (request.headers.get('User-Agent') || 'null').toLowerCase();
    
    // 初始化配置
    const config = await initializeConfig(env, url);
    
    // 验证访问权限
    if (!await isAuthorized(url, config)) {
      return handleUnauthorized(request, env, config, url, userAgent);
    }
    
    // 处理订阅请求
    return handleSubscription(request, env, config, url, userAgent);
  }
};

// --- 工具函数模块 ---

/**
 * 双重 MD5 加密
 * @param {string} text 输入文本
 * @returns {Promise<string>} 加密后的哈希值
 */
async function MD5MD5(text) {
  const encoder = new TextEncoder();
  const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHex = Array.from(new Uint8Array(firstPass))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
  return Array.from(new Uint8Array(secondPass))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toLowerCase();
}

/**
 * Base64 解码
 * @param {string} str Base64 编码字符串
 * @returns {string} 解码后的字符串
 */
function base64Decode(str) {
  try {
    const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
    return new TextDecoder('utf-8').decode(bytes);
  } catch (e) {
    console.error('Base64 解码失败:', e);
    return '';
  }
}

/**
 * 验证 Base64 字符串有效性
 * @param {string} str 输入字符串
 * @returns {boolean} 是否为有效 Base64
 */
function isValidBase64(str) {
  if (!str || typeof str !== 'string') return false;
  const cleanStr = str.replace(/\s/g, '');
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(cleanStr);
}

/**
 * 分割并清理订阅链接
 * @param {string} envadd 原始订阅数据
 * @returns {string[]} 清理后的链接数组
 */
function ADD(envadd) {
  if (!envadd) return [];
  const addtext = envadd.replace(/[	"'|\r\n]+/g, ',').replace(/,+/g, ',');
  let cleanedText = addtext;
  if (addtext.startsWith(',')) cleanedText = addtext.slice(1);
  if (addtext.endsWith(',')) cleanedText = cleanedText.slice(0, -1);
  return cleanedText ? cleanedText.split(',').filter(Boolean) : [];
}

// --- 配置初始化和权限验证 ---

/**
 * 初始化配置
 * @param {Object} env 环境变量
 * @param {URL} url 请求 URL
 * @returns {Promise<Object>} 配置对象
 */
async function initializeConfig(env, url) {
  const mytoken = env.TOKEN || 'auto';
  const guestToken = env.GUESTTOKEN || env.GUEST || await MD5MD5(mytoken);
  
  return {
    mytoken,
    botToken: env.TGTOKEN || '',
    chatId: env.TGID || '',
    tgEnabled: parseInt(env.TG || '0'),
    subConverter: env.SUBAPI || 'SUBAPI.cmliussss.net',
    subProtocol: (env.SUBAPI || '').includes('http://') ? 'http' : 'https',
    subConfig: env.SUBCONFIG || 'https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini',
    fileName: env.SUBNAME || 'CF-Workers-SUB',
    subUpdateTime: parseInt(env.SUBUPTIME || '6'),
    total: 99 * 1099511627776, // 99TB
    timestamp: 4102329600000, // 2099-12-31
    guestToken
  };
}

/**
 * 生成每日动态 Fake Token
 * @param {string} mytoken 主 Token
 * @returns {Promise<string>} Fake Token
 */
async function generateFakeToken(mytoken) {
  const currentDate = new Date();
  currentDate.setHours(0, 0, 0, 0);
  const timeTemp = Math.ceil(currentDate.getTime() / 1000);
  return await MD5MD5(`${mytoken}${timeTemp}`);
}

/**
 * 验证请求权限
 * @param {URL} url 请求 URL
 * @param {Object} config 配置对象
 * @returns {Promise<boolean>} 是否授权
 */
async function isAuthorized(url, config) {
  const token = url.searchParams.get('token');
  const fakeToken = await generateFakeToken(config.mytoken);
  const path = url.pathname;
  
  return token && [config.mytoken, fakeToken, config.guestToken].includes(token) ||
    path === `/${config.mytoken}` || path.includes(`/${config.mytoken}?`);
}

/**
 * 处理未授权请求
 * @param {Request} request 请求对象
 * @param {Object} env 环境变量
 * @param {Object} config 配置对象
 * @param {URL} url 请求 URL
 * @param {string} userAgent 用户代理
 * @returns {Promise<Response>} 响应对象
 */
async function handleUnauthorized(request, env, config, url, userAgent) {
  if (config.tgEnabled === 1 && url.pathname !== '/' && url.pathname !== '/favicon.ico') {
    await sendMessage(config, `#异常访问 ${config.fileName}`, 
      request.headers.get('CF-Connecting-IP'), 
      `UA: ${userAgent}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`);
  }
  
  if (env.URL302) return Response.redirect(env.URL302, 302);
  if (env.URL) return await proxyURL(env.URL, url);
  
  return new Response(nginx(), {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=UTF-8' }
  });
}

/**
 * 返回未授权页面
 * @returns {string} HTML 页面内容
 */
function nginx() {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>访问受限</title>
      <style>body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }</style>
    </head>
    <body>
      <h1>访问受限通知</h1>
      <p>我们很抱歉，您暂时无法访问此网站。</p>
      <p>如果您认为这是一个错误，请联系我们的支持团队寻求帮助：<a href="mailto:support@example.com">support@example.com</a></p>
    </body>
    </html>
  `;
}

/**
 * 发送 Telegram 通知
 * @param {Object} config 配置对象
 * @param {string} type 消息类型
 * @param {string} ip 用户 IP
 * @param {string} add_data 附加数据
 * @returns {Promise<Response|void>} 请求响应
 */
async function sendMessage(config, type, ip, add_data = "") {
  if (!config.botToken || !config.chatId) return;
  
  const msg = `${type}\nIP: ${ip}\n${add_data}`;
  const url = `https://api.telegram.org/bot${config.botToken}/sendMessage?chat_id=${config.chatId}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
  
  try {
    return await fetch(url, { method: 'get' });
  } catch (error) {
    console.error('Telegram 通知发送失败:', error);
  }
}

// --- 订阅处理 ---

/**
 * 处理订阅请求
 * @param {Request} request 请求对象
 * @param {Object} env 环境变量
 * @param {Object} config 配置对象
 * @param {URL} url 请求 URL
 * @param {string} userAgent 用户代理
 * @returns {Promise<Response>} 订阅响应
 */
async function handleSubscription(request, env, config, url, userAgent) {
  try {
    const links = await fetchLinks(env);
    const subscriptionData = await processSubscription(links, request, userAgent, config, url);
    
    return new Response(subscriptionData, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Profile-Update-Interval': `${config.subUpdateTime}`,
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      }
    });
  } catch (error) {
    console.error('订阅处理失败:', error);
    return new Response('服务暂不可用，请稍后重试', { 
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }
}

/**
 * 获取订阅链接
 * @param {Object} env 环境变量
 * @returns {Promise<string[]>} 订阅链接数组
 */
async function fetchLinks(env) {
  let mainData = env.LINK || '';
  
  if (env.LINKSUB) {
    const additionalLinks = ADD(env.LINKSUB);
    if (additionalLinks.length > 0) {
      mainData += (mainData ? '\n' : '') + additionalLinks.join('\n');
    }
  }
  
  return ADD(mainData);
}

/**
 * 处理订阅数据
 * @param {string[]} links 订阅链接数组
 * @param {Request} request 请求对象
 * @param {string} userAgent 用户代理
 * @param {Object} config 配置对象
 * @param {URL} url 请求 URL
 * @returns {Promise<string>} 订阅内容
 */
async function processSubscription(links, request, userAgent, config, url) {
  if (!links || links.length === 0) {
    return '没有可用的订阅链接';
  }
  
  const subscriptionFormat = determineSubscriptionFormat(userAgent, url.searchParams);
  const [subscriptionContent, subUrls] = await getSUB(links, request, subscriptionFormat, userAgent);
  
  // 处理空内容情况
  if (!subscriptionContent.length && !subUrls) {
    return '无法获取订阅内容';
  }
  
  const uniqueContent = deduplicateLinks(subscriptionContent.join('\n'));
  
  if (subscriptionFormat === 'base64') {
    return btoa(uniqueContent);
  } else {
    if (!subUrls) {
      return '无法获取订阅内容';
    }
    
    const subConverterUrl = generateSubConverterUrl(subscriptionFormat, subUrls, config);
    const response = await fetch(subConverterUrl, {
      headers: {
        'User-Agent': `v2rayN/6.45 cmliu/CF-Workers-SUB ${subscriptionFormat}(${userAgent})`
      },
      timeout: 5000
    }).catch(error => {
      console.error('订阅转换请求失败:', error);
      throw new Error('订阅转换服务不可用');
    });
    
    if (!response.ok) {
      throw new Error(`订阅转换失败: ${response.status}`);
    }
    
    let content = await response.text();
    if (subscriptionFormat === 'clash') {
      content = await clashFix(content);
    }
    
    return content;
  }
}

/**
 * 确定订阅格式
 * @param {string} userAgent 用户代理
 * @param {URLSearchParams} searchParams 查询参数
 * @returns {string} 订阅格式
 */
function determineSubscriptionFormat(userAgent, searchParams) {
  if (searchParams.has('clash') || userAgent.includes('clash')) return 'clash';
  if (searchParams.has('sb') || userAgent.includes('sing-box')) return 'singbox';
  return 'base64';
}

/**
 * 生成订阅转换 URL
 * @param {string} format 目标格式
 * @param {string} subUrls 订阅 URL
 * @param {Object} config 配置对象
 * @returns {string} 转换 URL
 */
function generateSubConverterUrl(format, subUrls, config) {
  const target = format === 'clash' ? 'clash' : 'singbox';
  return `${config.subProtocol}://${config.subConverter}/sub?target=${target}&url=${encodeURIComponent(subUrls)}&insert=false&config=${encodeURIComponent(config.subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
}

/**
 * 去重订阅链接
 * @param {string} text 订阅文本
 * @returns {string} 去重后的文本
 */
function deduplicateLinks(text) {
  if (!text) return '';
  
  const lines = text.split('\n')
    .map(line => line.trim())
    .filter(line => line && line.includes('://'));
  
  return [...new Set(lines)].join('\n');
}

/**
 * 获取订阅内容
 * @param {string[]} api 订阅 API 数组
 * @param {Request} request 请求对象
 * @param {string} ua 订阅格式
 * @param {string} userAgentHeader 用户代理头
 * @returns {Promise<[string[], string]>} 订阅内容和 URL
 */
async function getSUB(api, request, ua, userAgentHeader) {
  if (!api || !api.length) return [[], ''];
  
  const uniqueApi = [...new Set(api)];
  const fetchPromises = uniqueApi.map(url => 
    fetchWithTimeout(url, request, ua, userAgentHeader, 3000)
      .catch(err => ({ status: 'error', value: null, apiUrl: url }))
  );
  
  const results = await Promise.allSettled(fetchPromises);
  
  let newApi = [];
  let subUrls = '';
  
  for (const result of results) {
    if (result.status === 'fulfilled') {
      const { status, value, apiUrl } = result.value;
      
      if (status === 'fulfilled' && value) {
        if (value.includes('proxies:')) {
          subUrls += subUrls ? `|${apiUrl}` : apiUrl;
        } else if (value.includes('://')) {
          newApi.push(value);
        } else if (isValidBase64(value)) {
          try {
            const decoded = base64Decode(value);
            if (decoded) newApi.push(decoded);
          } catch (e) {
            console.error('Base64 解码失败:', e);
          }
        }
      }
    }
  }
  
  return [ADD(newApi.join('\n')), subUrls];
}

/**
 * 带超时功能的 Fetch 请求
 * @param {string} url 请求 URL
 * @param {Request} request 原始请求
 * @param {string} ua 订阅格式
 * @param {string} userAgentHeader 用户代理头
 * @param {number} timeout 超时时间（毫秒）
 * @returns {Promise<Object>} 请求结果
 */
async function fetchWithTimeout(url, request, ua, userAgentHeader, timeout) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await getUrl(request, url, ua, userAgentHeader, { signal: controller.signal });
    const text = await response.text();
    clearTimeout(timeoutId);
    return { status: 'fulfilled', value: text, apiUrl: url };
  } catch (error) {
    clearTimeout(timeoutId);
    console.error(`获取订阅失败 (${url}):`, error);
    return { status: 'error', value: null, apiUrl: url };
  }
}

/**
 * 执行 HTTP 请求
 * @param {Request} request 原始请求
 * @param {string} targetUrl 目标 URL
 * @param {string} ua 订阅格式
 * @param {string} userAgentHeader 用户代理头
 * @param {Object} options 请求选项
 * @returns {Promise<Response>} 响应对象
 */
async function getUrl(request, targetUrl, ua, userAgentHeader, options = {}) {
  const newHeaders = new Headers();
  newHeaders.set("User-Agent", `v2rayN/6.45 cmliu/CF-Workers-SUB ${ua}(${userAgentHeader})`);
  
  const modifiedRequest = new Request(targetUrl, {
    method: "GET",
    headers: newHeaders,
    redirect: "follow",
    ...options
  });
  
  return await fetch(modifiedRequest);
}

/**
 * 修复 Clash 订阅内容
 * @param {string} content 原始内容
 * @returns {Promise<string>} 修复后的内容
 */
async function clashFix(content) {
  // 这里可以根据需求实现 Clash 配置修复
  // 例如修改端口、DNS设置等
  return content;
}

/**
 * 代理 URL 请求
 * @param {string} targetUrl 目标 URL
 * @param {URL} url 请求 URL
 * @returns {Promise<Response>} 响应对象
 */
async function proxyURL(targetUrl, url) {
  try {
    return await fetch(targetUrl);
  } catch (error) {
    console.error('代理请求失败:', error);
    return new Response('代理服务暂不可用', { status: 502 });
  }
}
