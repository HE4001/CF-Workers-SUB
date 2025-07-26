/**
 * CF Workers SUB - 完整优化版本
 * 环境变量：TOKEN (管理员令牌), LINK (默认订阅链接)
 * KV存储：配置、缓存、统计、日志等所有其他数据
 * 基于 Cloudflare Workers KV 最佳实践设计
 */

// KV 存储键名常量
const KV_KEYS = {
  // 核心配置
  APP_CONFIG: 'app_config',
  USER_LINKS: 'user_links',
  
  // 缓存数据
  PROCESSED_NODES: 'processed_nodes',
  SUBSCRIPTION_CACHE: 'sub_cache',
  
  // 统计数据
  ACCESS_STATS: 'access_stats',
  SYSTEM_LOGS: 'system_logs',
  
  // 认证相关
  AUTH_CONFIG: 'auth_config',
  
  // 转换缓存前缀
  CACHE_PREFIX: 'cache_',
  CONVERT_PREFIX: 'convert_'
};

// 默认配置
const DEFAULT_CONFIG = {
  subName: 'CF-Workers-SUB',
  subUptime: 6,
  subApi: 'SUBAPI.cmliussss.net',
  subConfig: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini',
  guestToken: '',
  url302: '',
  url: '',
  tgToken: '',
  tgId: '',
  enableCache: true,
  enableStats: true,
  enableLogs: true,
  theme: 'auto',
  language: 'zh-CN',
  maxNodes: 500,
  enableDedup: true,
  sortBySpeed: false
};

export default {
  async fetch(request, env, ctx) {
    try {
      const router = new Router(env);
      return await router.handle(request, ctx);
    } catch (error) {
      console.error('Worker error:', error);
      await logError(env, error, request);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};

/**
 * 主路由处理器
 */
class Router {
  constructor(env) {
    this.env = env;
    this.config = new ConfigManager(env);
    this.auth = new AuthManager(env);
    this.subscription = new SubscriptionManager(env);
    this.stats = new StatsManager(env);
  }

  async handle(request, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // 健康检查
    if (path === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        timestamp: Date.now(),
        version: '2.0.0'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // CORS 处理
    if (method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }

    // 获取认证状态
    const authResult = await this.auth.authenticate(request);
    
    // 路由分发
    switch (true) {
      case path === '/' || path === '/dashboard':
        return this.handleRoot(request, authResult);
      
      case path === '/admin':
        return this.handleAdmin(request, authResult);
        
      case path.startsWith('/api/'):
        return this.handleAPI(request, authResult);
        
      case path.startsWith('/sub') || path.startsWith('/subscription'):
        return this.handleSubscription(request, authResult, ctx);
        
      default:
        return this.handleNotFound(authResult);
    }
  }

  async handleRoot(request, authResult) {
    if (!authResult.isAuthenticated) {
      const config = await this.config.get();
      if (config.url302) {
        return Response.redirect(config.url302, 302);
      }
      return new Response('Unauthorized - Please provide valid token', { status: 401 });
    }
    
    return new Response('CF Workers SUB - Dashboard', { status: 200 });
  }

  async handleAdmin(request, authResult) {
    if (!authResult.isAdmin) {
      return new Response('Admin access required', { status: 403 });
    }
    
    return new Response('CF Workers SUB - Admin Panel', { status: 200 });
  }

  async handleAPI(request, authResult) {
    const url = new URL(request.url);
    const apiPath = url.pathname.replace('/api', '');
    
    // 添加 CORS 头
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };
    
    try {
      let response;
      
      switch (apiPath) {
        case '/config':
          response = await this.handleConfigAPI(request, authResult);
          break;
        case '/links':
          response = await this.handleLinksAPI(request, authResult);
          break;
        case '/stats':
          response = await this.handleStatsAPI(request, authResult);
          break;
        case '/nodes':
          response = await this.handleNodesAPI(request, authResult);
          break;
        case '/logs':
          response = await this.handleLogsAPI(request, authResult);
          break;
        case '/cache/clear':
          response = await this.handleCacheClearAPI(request, authResult);
          break;
        default:
          response = new Response(JSON.stringify({
            success: false,
            error: 'API endpoint not found'
          }), { 
            status: 404,
            headers: { 'Content-Type': 'application/json' }
          });
      }
      
      // 添加 CORS 头到响应
      Object.entries(corsHeaders).forEach(([key, value]) => {
        response.headers.set(key, value);
      });
      
      return response;
    } catch (error) {
      console.error('API Error:', error);
      return new Response(JSON.stringify({
        success: false,
        error: error.message
      }), {
        status: 500,
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
  }

  async handleSubscription(request, authResult, ctx) {
    try {
      // 记录访问统计
      ctx.waitUntil(this.stats.recordAccess(request));
      
      return await this.subscription.generate(request, authResult);
    } catch (error) {
      console.error('Subscription error:', error);
      ctx.waitUntil(logError(this.env, error, request));
      return new Response('Subscription service error', { status: 500 });
    }
  }

  async handleNotFound(authResult) {
    const config = await this.config.get();
    if (!authResult.isAuthenticated && config.url302) {
      return Response.redirect(config.url302, 302);
    }
    return new Response('Not Found', { status: 404 });
  }

  // API 处理方法
  async handleConfigAPI(request, authResult) {
    if (!authResult.isAdmin) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Admin access required'
      }), { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method === 'GET') {
      const config = await this.config.get();
      return new Response(JSON.stringify({
        success: true,
        config: config
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method === 'POST') {
      try {
        const newConfig = await request.json();
        const updatedConfig = await this.config.update(newConfig);
        
        return new Response(JSON.stringify({
          success: true,
          config: updatedConfig,
          message: '配置已更新'
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        return new Response(JSON.stringify({
          success: false,
          error: error.message
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    return new Response(JSON.stringify({
      success: false,
      error: 'Method not allowed'
    }), { 
      status: 405,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async handleLinksAPI(request, authResult) {
    if (!authResult.isAuthenticated) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Authentication required'
      }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method === 'GET') {
      const links = await this.getUserLinks();
      return new Response(JSON.stringify({
        success: true,
        links: links
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method === 'POST' && authResult.isAdmin) {
      try {
        const { links } = await request.json();
        
        await this.env.KV.put(KV_KEYS.USER_LINKS, JSON.stringify({
          links: links.filter(link => link && link.trim()),
          lastUpdate: Date.now(),
          updatedBy: authResult.token
        }));
        
        return new Response(JSON.stringify({
          success: true,
          message: '链接已保存'
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        return new Response(JSON.stringify({
          success: false,
          error: error.message
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    return new Response(JSON.stringify({
      success: false,
      error: 'Method not allowed'
    }), { 
      status: 405,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async handleStatsAPI(request, authResult) {
    if (!authResult.isAuthenticated) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Authentication required'
      }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const stats = await this.stats.get();
    
    // 处理敏感信息
    const publicStats = {
      totalAccess: stats.totalAccess,
      lastAccess: stats.lastAccess,
      clientStats: stats.clientStats,
      dailyStats: Object.keys(stats.dailyStats || {})
        .slice(-7) // 只显示最近7天
        .reduce((acc, key) => {
          acc[key] = stats.dailyStats[key];
          return acc;
        }, {})
    };

    // 管理员可以看到更多信息
    if (authResult.isAdmin) {
      publicStats.ipStats = stats.ipStats;
      publicStats.startTime = stats.startTime;
    }

    return new Response(JSON.stringify({
      success: true,
      stats: publicStats
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async handleNodesAPI(request, authResult) {
    if (!authResult.isAuthenticated) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Authentication required'
      }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const stored = await this.env.KV.get(KV_KEYS.PROCESSED_NODES);
      const nodeData = stored ? JSON.parse(stored) : { nodes: [], count: 0 };
      
      return new Response(JSON.stringify({
        success: true,
        count: nodeData.count || 0,
        lastUpdate: nodeData.lastUpdate,
        summary: {
          total: nodeData.count || 0,
          protocols: this.analyzeProtocols(nodeData.nodes || [])
        }
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  async handleLogsAPI(request, authResult) {
    if (!authResult.isAdmin) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Admin access required'
      }), { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const logs = await this.config.getLogs();
      return new Response(JSON.stringify({
        success: true,
        logs: logs.slice(0, 50) // 只返回最近50条
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  async handleCacheClearAPI(request, authResult) {
    if (!authResult.isAdmin) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Admin access required'
      }), { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      // 清除缓存逻辑
      await this.clearCache();
      
      return new Response(JSON.stringify({
        success: true,
        message: '缓存已清除'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  async clearCache() {
    // 由于 KV 没有批量删除功能，这里只清除主要缓存键
    const cacheKeys = [
      KV_KEYS.PROCESSED_NODES,
      KV_KEYS.SUBSCRIPTION_CACHE
    ];
    
    for (const key of cacheKeys) {
      try {
        await this.env.KV.delete(key);
      } catch (error) {
        console.error(`Error deleting cache key ${key}:`, error);
      }
    }
  }

  analyzeProtocols(nodes) {
    const protocols = {};
    
    nodes.forEach(node => {
      if (node.startsWith('vmess://')) protocols.vmess = (protocols.vmess || 0) + 1;
      else if (node.startsWith('vless://')) protocols.vless = (protocols.vless || 0) + 1;
      else if (node.startsWith('trojan://')) protocols.trojan = (protocols.trojan || 0) + 1;
      else if (node.startsWith('ss://')) protocols.shadowsocks = (protocols.shadowsocks || 0) + 1;
      else if (node.startsWith('ssr://')) protocols.shadowsocksr = (protocols.shadowsocksr || 0) + 1;
      else protocols.other = (protocols.other || 0) + 1;
    });
    
    return protocols;
  }

  async getUserLinks() {
    try {
      const stored = await this.env.KV.get(KV_KEYS.USER_LINKS);
      if (stored) {
        const data = JSON.parse(stored);
        return data.links || [];
      }
    } catch (error) {
      console.error('Error getting user links:', error);
    }
    
    // 返回环境变量中的默认链接
    return this.env.LINK ? this.env.LINK.trim().split('\n').filter(Boolean) : [];
  }
}

/**
 * 配置管理器
 */
class ConfigManager {
  constructor(env) {
    this.env = env;
  }

  async get() {
    try {
      const stored = await this.env.KV.get(KV_KEYS.APP_CONFIG);
      if (stored) {
        const config = JSON.parse(stored);
        return { ...DEFAULT_CONFIG, ...config };
      }
    } catch (error) {
      console.error('Error loading config:', error);
    }
    
    return DEFAULT_CONFIG;
  }

  async update(newConfig) {
    try {
      const currentConfig = await this.get();
      const updatedConfig = { ...currentConfig, ...newConfig };
      
      await this.env.KV.put(KV_KEYS.APP_CONFIG, JSON.stringify(updatedConfig));
      
      // 记录配置更新日志
      await this.logConfigChange(newConfig);
      
      return updatedConfig;
    } catch (error) {
      console.error('Error updating config:', error);
      throw error;
    }
  }

  async logConfigChange(changes) {
    try {
      const logs = await this.getLogs();
      logs.unshift({
        timestamp: Date.now(),
        type: 'config_update',
        changes: changes,
        userAgent: 'system'
      });
      
      // 只保留最近100条日志
      if (logs.length > 100) {
        logs.splice(100);
      }
      
      await this.env.KV.put(KV_KEYS.SYSTEM_LOGS, JSON.stringify(logs));
    } catch (error) {
      console.error('Error logging config change:', error);
    }
  }

  async getLogs() {
    try {
      const stored = await this.env.KV.get(KV_KEYS.SYSTEM_LOGS);
      return stored ? JSON.parse(stored) : [];
    } catch (error) {
      console.error('Error getting logs:', error);
      return [];
    }
  }
}

/**
 * 认证管理器
 */
class AuthManager {
  constructor(env) {
    this.env = env;
  }

  async authenticate(request) {
    const url = new URL(request.url);
    let token = url.searchParams.get('token') || 
                url.pathname.split('/')[1] ||
                request.headers.get('Authorization')?.replace('Bearer ', '');

    // 处理路径中的 token
    if (!token && url.pathname !== '/' && !url.pathname.startsWith('/api')) {
      const pathParts = url.pathname.split('/');
      if (pathParts.length > 1 && pathParts[1].length > 10) {
        token = pathParts[1];
      }
    }

    const config = await this.getAuthConfig();
    
    return {
      isAuthenticated: this.isValidToken(token, config),
      isAdmin: token === this.env.TOKEN,
      isGuest: token === config.guestToken && config.guestToken && token,
      token: token
    };
  }

  isValidToken(token, config) {
    if (!token) return false;
    return token === this.env.TOKEN || 
           (config.guestToken && token === config.guestToken);
  }

  async getAuthConfig() {
    try {
      const stored = await this.env.KV.get(KV_KEYS.AUTH_CONFIG);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.error('Error getting auth config:', error);
    }
    
    return {
      guestToken: '',
      tokenExpiry: null,
      lastAuth: null
    };
  }

  async updateAuthConfig(config) {
    try {
      await this.env.KV.put(KV_KEYS.AUTH_CONFIG, JSON.stringify({
        ...config,
        lastAuth: Date.now()
      }));
    } catch (error) {
      console.error('Error updating auth config:', error);
      throw error;
    }
  }
}

/**
 * 订阅管理器
 */
class SubscriptionManager {
  constructor(env) {
    this.env = env;
  }

  async generate(request, authResult) {
    if (!authResult.isAuthenticated) {
      return new Response('Unauthorized - Please provide valid token', { status: 401 });
    }

    const url = new URL(request.url);
    const format = this.detectFormat(url);
    const config = await this.getConfig();
    
    // 生成缓存键
    const cacheKey = `${KV_KEYS.CONVERT_PREFIX}${format}_${this.generateCacheHash(request)}`;

    // 尝试从缓存获取
    if (config.enableCache) {
      const cached = await this.getFromCache(cacheKey);
      if (cached) {
        return this.createResponse(cached, format);
      }
    }

    // 生成新的订阅内容
    const content = await this.generateSubscriptionContent(format, url);
    
    // 缓存结果
    if (config.enableCache && content) {
      await this.saveToCache(cacheKey, content, config.subUptime * 3600);
    }
    
    return this.createResponse(content, format);
  }

  detectFormat(url) {
    const path = url.pathname.toLowerCase();
    const target = url.searchParams.get('target');
    
    if (target) {
      return target.toLowerCase();
    }
    
    if (path.includes('clash')) return 'clash';
    if (path.includes('singbox') || path.includes('sing-box')) return 'singbox';
    if (path.includes('surge')) return 'surge';
    if (path.includes('quan') || path.includes('quantumult')) return 'quan';
    if (path.includes('loon')) return 'loon';
    if (path.includes('ss')) return 'ss';
    
    return 'base64'; // 默认格式
  }

  async generateSubscriptionContent(format, url) {
    try {
      // 获取所有订阅链接
      const links = await this.getAllSubscriptionLinks();
      
      if (links.length === 0) {
        throw new Error('No subscription links configured');
      }
      
      // 获取并处理节点
      const nodes = await this.fetchAndProcessNodes(links);
      
      if (nodes.length === 0) {
        throw new Error('No valid nodes found');
      }
      
      // 根据格式转换
      switch (format) {
        case 'clash':
          return await this.convertToClash(nodes, url);
        case 'singbox':
        case 'sing-box':
          return await this.convertToSingBox(nodes, url);
        case 'surge':
          return await this.convertToSurge(nodes, url);
        case 'quan':
        case 'quantumult':
          return await this.convertToQuantumult(nodes, url);
        case 'loon':
          return await this.convertToLoon(nodes, url);
        case 'ss':
          return this.convertToSS(nodes);
        default:
          return this.convertToBase64(nodes);
      }
    } catch (error) {
      console.error('Error generating subscription:', error);
      throw error;
    }
  }

  async getAllSubscriptionLinks() {
    // 获取用户添加的链接
    const userLinks = await this.getUserLinks();
    
    // 获取环境变量中的默认链接
    const defaultLinks = this.env.LINK ? 
      this.env.LINK.trim().split('\n').filter(Boolean) : [];
    
    // 合并并去重
    const allLinks = [...new Set([...defaultLinks, ...userLinks])];
    
    return allLinks.filter(link => link && link.trim());
  }

  async getUserLinks() {
    try {
      const stored = await this.env.KV.get(KV_KEYS.USER_LINKS);
      if (stored) {
        const data = JSON.parse(stored);
        return data.links || [];
      }
    } catch (error) {
      console.error('Error getting user links:', error);
    }
    return [];
  }

  async fetchAndProcessNodes(links) {
    const allNodes = [];
    const config = await this.getConfig();
    const errors = [];
    
    for (const link of links) {
      try {
        const nodes = await this.fetchNodesFromLink(link);
        allNodes.push(...nodes);
      } catch (error) {
        console.error(`Error fetching from ${link}:`, error);
        errors.push({ link, error: error.message });
      }
    }
    
    // 去重和过滤
    let uniqueNodes = config.enableDedup ? 
      this.deduplicateNodes(allNodes) : allNodes;
    
    // 限制节点数量
    if (config.maxNodes && uniqueNodes.length > config.maxNodes) {
      uniqueNodes = uniqueNodes.slice(0, config.maxNodes);
    }
    
    // 保存处理后的节点到 KV
    await this.saveProcessedNodes(uniqueNodes, errors);
    
    return uniqueNodes;
  }

  async fetchNodesFromLink(link) {
    if (link.startsWith('http')) {
      // 处理订阅链接
      const response = await fetch(link, {
        headers: {
          'User-Agent': 'CF-Workers-SUB/2.0'
        },
        cf: {
          cacheTtl: 300,
          cacheEverything: true
        }
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const content = await response.text();
      return this.parseSubscriptionContent(content);
    } else {
      // 处理单个节点链接
      return [link];
    }
  }

  parseSubscriptionContent(content) {
    try {
      // 尝试 Base64 解码
      let decoded;
      try {
        decoded = atob(content.trim());
      } catch {
        decoded = content;
      }
      
      return decoded.split('\n')
        .map(line => line.trim())
        .filter(line => line && this.isValidNodeLink(line));
    } catch (error) {
      console.error('Error parsing subscription content:', error);
      return [];
    }
  }

  isValidNodeLink(line) {
    const protocols = ['vmess://', 'vless://', 'trojan://', 'ss://', 'ssr://', 'hysteria://', 'tuic://'];
    return protocols.some(protocol => line.startsWith(protocol));
  }

  deduplicateNodes(nodes) {
    const seen = new Set();
    return nodes.filter(node => {
      const key = this.generateNodeKey(node);
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  generateNodeKey(node) {
    try {
      if (node.startsWith('vmess://')) {
        const config = JSON.parse(atob(node.substring(8)));
        return `vmess:${config.add}:${config.port}:${config.id || config.uuid}`;
      } else if (node.startsWith('vless://')) {
        const url = new URL(node);
        return `vless:${url.hostname}:${url.port}:${url.username}`;
      } else if (node.startsWith('trojan://')) {
        const url = new URL(node);
        return `trojan:${url.hostname}:${url.port}:${url.username}`;
      } else if (node.startsWith('ss://')) {
        const url = new URL(node);
        return `ss:${url.hostname}:${url.port}:${url.username}`;
      }
      return node;
    } catch (error) {
      return node;
    }
  }

  convertToBase64(nodes) {
    return btoa(nodes.join('\n'));
  }

  async convertToClash(nodes, url) {
    const config = await this.getConfig();
    
    // 构建转换 URL
    const conversionUrl = new URL(`https://${config.subApi}/sub`);
    conversionUrl.searchParams.set('target', 'clash');
    conversionUrl.searchParams.set('url', btoa(nodes.join('\n')));
    conversionUrl.searchParams.set('config', config.subConfig);
    
    // 传递其他参数
    for (const [key, value] of url.searchParams.entries()) {
      if (!['target', 'url', 'config'].includes(key)) {
        conversionUrl.searchParams.set(key, value);
      }
    }
    
    try {
      const response = await fetch(conversionUrl.toString(), {
        cf: {
          cacheTtl: 300,
          cacheEverything: true
        }
      });
      
      if (response.ok) {
        return await response.text();
      }
    } catch (error) {
      console.error('Conversion API error:', error);
    }
    
    // 如果 API 失败，返回基本的 Clash 配置
    return this.generateBasicClashConfig(nodes);
  }

  async convertToSingBox(nodes, url) {
    const config = await this.getConfig();
    
    const conversionUrl = new URL(`https://${config.subApi}/sub`);
    conversionUrl.searchParams.set('target', 'singbox');
    conversionUrl.searchParams.set('url', btoa(nodes.join('\n')));
    
    for (const [key, value] of url.searchParams.entries()) {
      if (!['target', 'url'].includes(key)) {
        conversionUrl.searchParams.set(key, value);
      }
    }
    
    try {
      const response = await fetch(conversionUrl.toString());
      if (response.ok) {
        return await response.text();
      }
    } catch (error) {
      console.error('SingBox conversion error:', error);
    }
    
    return this.generateBasicSingBoxConfig(nodes);
  }

  async convertToSurge(nodes, url) {
    const config = await this.getConfig();
    
    const conversionUrl = new URL(`https://${config.subApi}/sub`);
    conversionUrl.searchParams.set('target', 'surge');
    conversionUrl.searchParams.set('url', btoa(nodes.join('\n')));
    
    for (const [key, value] of url.searchParams.entries()) {
      if (!['target', 'url'].includes(key)) {
        conversionUrl.searchParams.set(key, value);
      }
    }
    
    try {
      const response = await fetch(conversionUrl.toString());
      if (response.ok) {
        return await response.text();
      }
    } catch (error) {
      console.error('Surge conversion error:', error);
    }
    
    return this.generateBasicSurgeConfig(nodes);
  }

  async convertToQuantumult(nodes, url) {
    const config = await this.getConfig();
    
    const conversionUrl = new URL(`https://${config.subApi}/sub`);
    conversionUrl.searchParams.set('target', 'quan');
    conversionUrl.searchParams.set('url', btoa(nodes.join('\n')));
    
    try {
      const response = await fetch(conversionUrl.toString());
      if (response.ok) {
        return await response.text();
      }
    } catch (error) {
      console.error('Quantumult conversion error:', error);
    }
    
    return this.convertToBase64(nodes);
  }

  async convertToLoon(nodes, url) {
    const config = await this.getConfig();
    
    const conversionUrl = new URL(`https://${config.subApi}/sub`);
    conversionUrl.searchParams.set('target', 'loon');
    conversionUrl.searchParams.set('url', btoa(nodes.join('\n')));
    
    try {
      const response = await fetch(conversionUrl.toString());
      if (response.ok) {
        return await response.text();
      }
    } catch (error) {
      console.error('Loon conversion error:', error);
    }
    
    return this.convertToBase64(nodes);
  }

  convertToSS(nodes) {
    const ssNodes = nodes.filter(node => node.startsWith('ss://'));
    return btoa(ssNodes.join('\n'));
  }

  generateBasicClashConfig(nodes) {
    const config = {
      port: 7890,
      'socks-port': 7891,
      'allow-lan': false,
      mode: 'rule',
      'log-level': 'info',
      'external-controller': '127.0.0.1:9090',
      proxies: [],
      'proxy-groups': [
        {
          name: '🚀 节点选择',
          type: 'select',
          proxies: ['♻️ 自动选择', '🔯 故障转移', 'DIRECT']
        },
        {
          name: '♻️ 自动选择',
          type: 'url-test',
          proxies: [],
          url: 'http://www.gstatic.com/generate_204',
          interval: 300
        },
        {
          name: '🔯 故障转移',
          type: 'fallback',
          proxies: [],
          url: 'http://www.gstatic.com/generate_204',
          interval: 300
        }
      ],
      rules: [
        'DOMAIN-SUFFIX,local,DIRECT',
        'IP-CIDR,127.0.0.0/8,DIRECT',
        'IP-CIDR,172.16.0.0/12,DIRECT',
        'IP-CIDR,192.168.0.0/16,DIRECT',
        'IP-CIDR,10.0.0.0/8,DIRECT',
        'GEOIP,CN,DIRECT',
        'MATCH,🚀 节点选择'
      ]
    };
    
    return `# Clash Config Generated by CF-Workers-SUB
# Update: ${new Date().toISOString()}
# Node Count: ${nodes.length}

port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies: []

proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - 🔯 故障转移
      - DIRECT

  - name: ♻️ 自动选择
    type: url-test
    proxies: []
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

  - name: 🔯 故障转移
    type: fallback
    proxies: []
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

rules:
  - DOMAIN-SUFFIX,local,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT
  - IP-CIDR,172.16.0.0/12,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择`;
  }

  generateBasicSingBoxConfig(nodes) {
    const config = {
      log: {
        level: 'info',
        timestamp: true
      },
      inbounds: [
        {
          type: 'mixed',
          listen: '127.0.0.1',
          listen_port: 7890
        }
      ],
      outbounds: [
        {
          type: 'selector',
          tag: 'proxy',
          outbounds: ['auto']
        },
        {
          type: 'urltest',
          tag: 'auto',
          outbounds: [],
          url: 'http://www.gstatic.com/generate_204',
          interval: '10m'
        },
        {
          type: 'direct',
          tag: 'direct'
        },
        {
          type: 'block',
          tag: 'block'
        }
      ],
      route: {
        rules: [
          {
            geoip: 'cn',
            outbound: 'direct'
          },
          {
            geosite: 'cn',
            outbound: 'direct'
          }
        ],
        auto_detect_interface: true
      }
    };
    
    return JSON.stringify(config, null, 2);
  }

  generateBasicSurgeConfig(nodes) {
    return `# Surge Config Generated by CF-Workers-SUB
# Update: ${new Date().toISOString()}
# Node Count: ${nodes.length}

[General]
loglevel = notify
dns-server = 223.5.5.5, 114.114.114.114
skip-proxy = localhost, *.local, captive.apple.com
bypass-tun = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12

[Proxy]
DIRECT = direct

[Proxy Group]
Proxy = select, DIRECT

[Rule]
GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed
`;
  }

  async getConfig() {
    const configManager = new ConfigManager(this.env);
    return await configManager.get();
  }

  generateCacheHash(request) {
    const url = new URL(request.url);
    const key = `${url.pathname}${url.search}`;
    return btoa(key).replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
  }

  async getFromCache(key) {
    try {
      return await this.env.KV.get(key);
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async saveToCache(key, content, ttl = 3600) {
    try {
      await this.env.KV.put(key, content, { expirationTtl: ttl });
    } catch (error) {
      console.error('Cache save error:', error);
    }
  }

  async saveProcessedNodes(nodes, errors = []) {
    try {
      const data = {
        nodes: nodes,
        count: nodes.length,
        errors: errors,
        lastUpdate: Date.now(),
        timestamp: new Date().toISOString()
      };
      
      await this.env.KV.put(KV_KEYS.PROCESSED_NODES, JSON.stringify(data));
    } catch (error) {
      console.error('Error saving processed nodes:', error);
    }
  }

  createResponse(content, format) {
    const headers = {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=300',
      'Access-Control-Allow-Origin': '*'
    };

    if (format === 'clash') {
      headers['Content-Type'] = 'application/yaml; charset=utf-8';
      headers['Content-Disposition'] = 'attachment; filename=clash.yaml';
    } else if (format === 'singbox' || format === 'sing-box') {
      headers['Content-Type'] = 'application/json; charset=utf-8';
      headers['Content-Disposition'] = 'attachment; filename=singbox.json';
    } else if (format === 'surge') {
      headers['Content-Type'] = 'text/plain; charset=utf-8';
      headers['Content-Disposition'] = 'attachment; filename=surge.conf';
    }

    return new Response(content, { headers });
  }
}

/**
 * 统计管理器
 */
class StatsManager {
  constructor(env) {
    this.env = env;
  }

  async recordAccess(request) {
    try {
      const config = await this.getConfig();
      if (!config.enableStats) return;
      
      const stats = await this.get();
      const now = new Date();
      const today = now.toISOString().split('T')[0];
      
      // 更新统计数据
      stats.totalAccess = (stats.totalAccess || 0) + 1;
      stats.lastAccess = Date.now();
      
      // 每日统计
      if (!stats.dailyStats) stats.dailyStats = {};
      stats.dailyStats[today] = (stats.dailyStats[today] || 0) + 1;
      
      // 客户端统计
      const userAgent = request.headers.get('User-Agent') || 'Unknown';
      const clientType = this.detectClientType(userAgent);
      
      if (!stats.clientStats) stats.clientStats = {};
      stats.clientStats[clientType] = (stats.clientStats[clientType] || 0) + 1;
      
      // IP 统计 (简化版)
      const ip = request.headers.get('CF-Connecting-IP') || 'Unknown';
      if (!stats.ipStats) stats.ipStats = {};
      const ipKey = this.hashIP(ip); // 对 IP 进行哈希处理以保护隐私
      stats.ipStats[ipKey] = (stats.ipStats[ipKey] || 0) + 1;
      
      // 清理旧数据
      this.cleanupOldStats(stats);
      
      await this.save(stats);
    } catch (error) {
      console.error('Error recording access:', error);
    }
  }

  async get() {
    try {
      const stored = await this.env.KV.get(KV_KEYS.ACCESS_STATS);
      return stored ? JSON.parse(stored) : this.getDefaultStats();
    } catch (error) {
      console.error('Error getting stats:', error);
      return this.getDefaultStats();
    }
  }

  async save(stats) {
    try {
      await this.env.KV.put(KV_KEYS.ACCESS_STATS, JSON.stringify(stats));
    } catch (error) {
      console.error('Error saving stats:', error);
    }
  }

  getDefaultStats() {
    return {
      totalAccess: 0,
      lastAccess: null,
      dailyStats: {},
      clientStats: {},
      ipStats: {},
      startTime: Date.now()
    };
  }

  detectClientType(userAgent) {
    const ua = userAgent.toLowerCase();
    
    if (ua.includes('clash')) return 'Clash';
    if (ua.includes('surge')) return 'Surge';
    if (ua.includes('quantumult')) return 'QuantumultX';
    if (ua.includes('shadowrocket')) return 'Shadowrocket';
    if (ua.includes('sing-box')) return 'SingBox';
    if (ua.includes('v2ray')) return 'V2Ray';
    if (ua.includes('curl')) return 'cURL';
    if (ua.includes('wget')) return 'Wget';
    if (ua.includes('loon')) return 'Loon';
    if (ua.includes('stash')) return 'Stash';
    
    return 'Other';
  }

  hashIP(ip) {
    // 简单的 IP 哈希函数以保护隐私
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
      const char = ip.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // 转换为32位整数
    }
    return Math.abs(hash).toString(36);
  }

  cleanupOldStats(stats) {
    // 清理30天前的每日统计
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 30);
    const cutoffStr = cutoffDate.toISOString().split('T')[0];
    
    for (const date in stats.dailyStats) {
      if (date < cutoffStr) {
        delete stats.dailyStats[date];
      }
    }
    
    // 限制 IP 统计数量
    const ipEntries = Object.entries(stats.ipStats || {});
    if (ipEntries.length > 1000) {
      // 保留访问次数最多的1000个IP
      const sorted = ipEntries.sort((a, b) => b[1] - a[1]);
      stats.ipStats = Object.fromEntries(sorted.slice(0, 1000));
    }
  }

  async getConfig() {
    const configManager = new ConfigManager(this.env);
    return await configManager.get();
  }
}

// 工具函数
async function logError(env, error, request) {
  try {
    const logs = await env.KV.get(KV_KEYS.SYSTEM_LOGS);
    const logArray = logs ? JSON.parse(logs) : [];
    
    logArray.unshift({
      timestamp: Date.now(),
      type: 'error',
      error: error.message,
      stack: error.stack,
      url: request.url,
      userAgent: request.headers.get('User-Agent'),
      ip: request.headers.get('CF-Connecting-IP')
    });
    
    // 只保留最近100条错误日志
    if (logArray.length > 100) {
      logArray.splice(100);
    }
    
    await env.KV.put(KV_KEYS.SYSTEM_LOGS, JSON.stringify(logArray));
  } catch (logError) {
    console.error('Failed to log error:', logError);
  }
}
