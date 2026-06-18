const express = require('express')
const router = express.Router()
const ldapService = require('../services/ldapService')
const userService = require('../services/userService')
const apiKeyService = require('../services/apiKeyService')
const logger = require('../utils/logger')
const config = require('../../config/config')
const inputValidator = require('../utils/inputValidator')
const { RateLimiterRedis } = require('rate-limiter-flexible')
const redis = require('../models/redis')
const { authenticateUser, authenticateUserOrAdmin, requireAdmin } = require('../middleware/auth')
const accountGroupService = require('../services/accountGroupService')
const permissionGroupService = require('../services/permissionGroupService')
const resourceVisibilityService = require('../services/resourceVisibilityService')
const claudeAccountService = require('../services/account/claudeAccountService')
const claudeConsoleAccountService = require('../services/account/claudeConsoleAccountService')
const geminiAccountService = require('../services/account/geminiAccountService')
const geminiApiAccountService = require('../services/account/geminiApiAccountService')
const openaiAccountService = require('../services/account/openaiAccountService')
const openaiResponsesAccountService = require('../services/account/openaiResponsesAccountService')
const azureOpenaiAccountService = require('../services/account/azureOpenaiAccountService')
const droidAccountService = require('../services/account/droidAccountService')
const bedrockAccountService = require('../services/account/bedrockAccountService')

const USER_ACCOUNT_SERVICES = {
  claude: {
    list: () => claudeAccountService.getAllAccounts(),
    create: (data) => claudeAccountService.createAccount(data),
    get: (id) => claudeAccountService.getAccount(id),
    update: (id, data) => claudeAccountService.updateAccount(id, data),
    delete: (id) => claudeAccountService.deleteAccount(id)
  },
  'claude-console': {
    list: () => claudeConsoleAccountService.getAllAccounts(),
    create: (data) => claudeConsoleAccountService.createAccount(data),
    get: (id) => claudeConsoleAccountService.getAccount(id),
    update: (id, data) => claudeConsoleAccountService.updateAccount(id, data),
    delete: (id) => claudeConsoleAccountService.deleteAccount(id)
  },
  gemini: {
    list: () => geminiAccountService.getAllAccounts(),
    create: (data) => geminiAccountService.createAccount(data),
    get: (id) => geminiAccountService.getAccount(id),
    update: (id, data) => geminiAccountService.updateAccount(id, data),
    delete: (id) => geminiAccountService.deleteAccount(id)
  },
  'gemini-api': {
    list: () => geminiApiAccountService.getAllAccounts(true),
    create: (data) => geminiApiAccountService.createAccount(data),
    get: (id) => geminiApiAccountService.getAccount(id),
    update: (id, data) => geminiApiAccountService.updateAccount(id, data),
    delete: (id) => geminiApiAccountService.deleteAccount(id)
  },
  openai: {
    list: () => openaiAccountService.getAllAccounts(),
    create: (data) => openaiAccountService.createAccount(data),
    get: (id) => openaiAccountService.getAccount(id),
    update: (id, data) => openaiAccountService.updateAccount(id, data),
    delete: (id) => openaiAccountService.deleteAccount(id)
  },
  'openai-responses': {
    list: () => openaiResponsesAccountService.getAllAccounts(true),
    create: (data) => openaiResponsesAccountService.createAccount(data),
    get: (id) => openaiResponsesAccountService.getAccount(id),
    update: (id, data) => openaiResponsesAccountService.updateAccount(id, data),
    delete: (id) => openaiResponsesAccountService.deleteAccount(id)
  },
  'azure-openai': {
    list: () => azureOpenaiAccountService.getAllAccounts(),
    create: (data) => azureOpenaiAccountService.createAccount(data),
    get: (id) => azureOpenaiAccountService.getAccount(id),
    update: (id, data) => azureOpenaiAccountService.updateAccount(id, data),
    delete: (id) => azureOpenaiAccountService.deleteAccount(id)
  },
  droid: {
    list: () => droidAccountService.getAllAccounts(),
    create: (data) => droidAccountService.createAccount(data),
    get: (id) => droidAccountService.getAccount(id),
    update: (id, data) => droidAccountService.updateAccount(id, data),
    delete: (id) => droidAccountService.deleteAccount(id)
  },
  bedrock: {
    list: async () => {
      const result = await bedrockAccountService.getAllAccounts()
      return result.success ? result.data : []
    },
    create: async (data) => {
      const result = await bedrockAccountService.createAccount(data)
      if (!result.success) {
        throw new Error(result.error || 'Failed to create Bedrock account')
      }
      return result.data
    },
    get: async (id) => {
      const result = await bedrockAccountService.getAccount(id)
      return result.success ? result.data : null
    },
    update: async (id, data) => {
      const result = await bedrockAccountService.updateAccount(id, data)
      if (!result.success) {
        throw new Error(result.error || 'Failed to update Bedrock account')
      }
      return result.data
    },
    delete: async (id) => {
      const result = await bedrockAccountService.deleteAccount(id)
      if (!result.success) {
        throw new Error(result.error || 'Failed to delete Bedrock account')
      }
      return result
    }
  }
}

function getUserActor(req) {
  return {
    id: req.user.id,
    username: req.user.username,
    type: 'user'
  }
}

function normalizeAccountListResult(result) {
  if (Array.isArray(result)) {
    return result
  }
  if (result?.success && Array.isArray(result.data)) {
    return result.data
  }
  return []
}

function getUserAuthMode() {
  const configuredMode = config.userManagement.authMode
  return String(configuredMode || (config.ldap?.enabled ? 'ldap' : 'local')).toLowerCase()
}

async function validateUserAccountBindings(userId, payload) {
  const bindings = [
    ['claude', payload.claudeAccountId],
    ['claude-console', payload.claudeConsoleAccountId],
    ['gemini', payload.geminiAccountId],
    ['openai', payload.openaiAccountId],
    ['azure-openai', payload.azureOpenaiAccountId],
    ['bedrock', payload.bedrockAccountId],
    ['droid', payload.droidAccountId]
  ]

  for (const [accountType, rawValue] of bindings) {
    if (!rawValue || typeof rawValue !== 'string') {
      continue
    }
    if (rawValue.startsWith('group:')) {
      const group = await accountGroupService.getGroup(rawValue.slice('group:'.length))
      await resourceVisibilityService.assertCanUseAccountGroup(userId, group)
      continue
    }

    let effectiveType = accountType
    let accountId = rawValue
    if (rawValue.startsWith('console:')) {
      effectiveType = 'claude-console'
      accountId = rawValue.slice('console:'.length)
    } else if (rawValue.startsWith('responses:')) {
      effectiveType = 'openai-responses'
      accountId = rawValue.slice('responses:'.length)
    } else if (rawValue.startsWith('api:')) {
      effectiveType = 'gemini-api'
      accountId = rawValue.slice('api:'.length)
    }

    await resourceVisibilityService.assertCanUseAccount(userId, effectiveType, accountId)
  }
}

// 🚦 配置登录速率限制
// 只基于IP地址限制，避免攻击者恶意锁定特定账户

// 延迟初始化速率限制器，确保 Redis 已连接
let ipRateLimiter = null
let strictIpRateLimiter = null

// 初始化速率限制器函数
function initRateLimiters() {
  if (!ipRateLimiter) {
    try {
      const redisClient = redis.getClientSafe()

      // IP地址速率限制 - 正常限制
      ipRateLimiter = new RateLimiterRedis({
        storeClient: redisClient,
        keyPrefix: 'login_ip_limiter',
        points: 30, // 每个IP允许30次尝试
        duration: 900, // 15分钟窗口期
        blockDuration: 900 // 超限后封禁15分钟
      })

      // IP地址速率限制 - 严格限制（用于检测暴力破解）
      strictIpRateLimiter = new RateLimiterRedis({
        storeClient: redisClient,
        keyPrefix: 'login_ip_strict',
        points: 100, // 每个IP允许100次尝试
        duration: 3600, // 1小时窗口期
        blockDuration: 3600 // 超限后封禁1小时
      })
    } catch (error) {
      logger.error('❌ 初始化速率限制器失败:', error)
      // 速率限制器初始化失败时继续运行，但记录错误
    }
  }
  return { ipRateLimiter, strictIpRateLimiter }
}

// 🔐 用户登录端点
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown'

    // 初始化速率限制器（如果尚未初始化）
    const limiters = initRateLimiters()

    // 检查IP速率限制 - 基础限制
    if (limiters.ipRateLimiter) {
      try {
        await limiters.ipRateLimiter.consume(clientIp)
      } catch (rateLimiterRes) {
        const retryAfter = Math.round(rateLimiterRes.msBeforeNext / 1000) || 900
        logger.security(`🚫 Login rate limit exceeded for IP: ${clientIp}`)
        res.set('Retry-After', String(retryAfter))
        return res.status(429).json({
          error: 'Too many requests',
          message: `Too many login attempts from this IP. Please try again later.`
        })
      }
    }

    // 检查IP速率限制 - 严格限制（防止暴力破解）
    if (limiters.strictIpRateLimiter) {
      try {
        await limiters.strictIpRateLimiter.consume(clientIp)
      } catch (rateLimiterRes) {
        const retryAfter = Math.round(rateLimiterRes.msBeforeNext / 1000) || 3600
        logger.security(`🚫 Strict rate limit exceeded for IP: ${clientIp} - possible brute force`)
        res.set('Retry-After', String(retryAfter))
        return res.status(429).json({
          error: 'Too many requests',
          message: 'Too many login attempts detected. Access temporarily blocked.'
        })
      }
    }

    if (!username || !password) {
      return res.status(400).json({
        error: 'Missing credentials',
        message: 'Username and password are required'
      })
    }

    // 验证输入格式
    let validatedUsername
    try {
      validatedUsername = inputValidator.validateUsername(username)
      inputValidator.validatePassword(password)
    } catch (validationError) {
      return res.status(400).json({
        error: 'Invalid input',
        message: validationError.message
      })
    }

    // 检查用户管理是否启用
    if (!config.userManagement.enabled) {
      return res.status(503).json({
        error: 'Service unavailable',
        message: 'User management is not enabled'
      })
    }

    const authMode = getUserAuthMode()
    if (!['local', 'ldap'].includes(authMode)) {
      return res.status(503).json({
        error: 'Service unavailable',
        message: `Unsupported user authentication mode: ${authMode}`
      })
    }

    if (authMode === 'ldap' && (!config.ldap || !config.ldap.enabled)) {
      return res.status(503).json({
        error: 'Service unavailable',
        message: 'LDAP authentication is not enabled'
      })
    }

    const authResult =
      authMode === 'ldap'
        ? await ldapService.authenticateUserCredentials(validatedUsername, password)
        : await userService.authenticateLocalUserCredentials(validatedUsername, password)

    if (!authResult.success) {
      // 登录失败
      logger.info(`🚫 Failed login attempt for user: ${validatedUsername} from IP: ${clientIp}`)
      return res.status(401).json({
        error: 'Authentication failed',
        message: authResult.message
      })
    }

    // 登录成功
    logger.info(`✅ User login successful: ${validatedUsername} from IP: ${clientIp}`)

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: authResult.user.id,
        username: authResult.user.username,
        email: authResult.user.email,
        displayName: authResult.user.displayName,
        firstName: authResult.user.firstName,
        lastName: authResult.user.lastName,
        role: authResult.user.role
      },
      sessionToken: authResult.sessionToken,
      authMode
    })
  } catch (error) {
    logger.error('❌ User login error:', error)
    res.status(500).json({
      error: 'Login error',
      message: 'Internal server error during login'
    })
  }
})

// 🚪 用户登出端点
router.post('/logout', authenticateUser, async (req, res) => {
  try {
    await userService.invalidateUserSession(req.user.sessionToken)

    logger.info(`👋 User logout: ${req.user.username}`)

    res.json({
      success: true,
      message: 'Logout successful'
    })
  } catch (error) {
    logger.error('❌ User logout error:', error)
    res.status(500).json({
      error: 'Logout error',
      message: 'Internal server error during logout'
    })
  }
})

// 👤 获取当前用户信息
router.get('/profile', authenticateUser, async (req, res) => {
  try {
    const user = await userService.getUserById(req.user.id)
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User profile not found'
      })
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isActive: user.isActive,
        createdAt: user.createdAt,
        lastLoginAt: user.lastLoginAt,
        apiKeyCount: user.apiKeyCount,
        totalUsage: user.totalUsage
      },
      config: {
        authMode: getUserAuthMode(),
        maxApiKeysPerUser: config.userManagement.maxApiKeysPerUser,
        allowUserDeleteApiKeys: config.userManagement.allowUserDeleteApiKeys
      }
    })
  } catch (error) {
    logger.error('❌ Get user profile error:', error)
    res.status(500).json({
      error: 'Profile error',
      message: 'Failed to retrieve user profile'
    })
  }
})

// 🔐 当前用户修改本地密码
router.patch('/profile/password', authenticateUser, async (req, res) => {
  try {
    if (getUserAuthMode() !== 'local') {
      return res.status(400).json({
        error: 'Unsupported operation',
        message: 'Password changes are only available in local auth mode'
      })
    }

    const { currentPassword, newPassword } = req.body
    inputValidator.validatePassword(currentPassword)
    inputValidator.validatePassword(newPassword)

    const authResult = await userService.authenticateLocalUserCredentials(
      req.user.username,
      currentPassword
    )
    if (!authResult.success) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Current password is incorrect'
      })
    }

    await userService.updateLocalUserPassword(req.user.id, newPassword)
    res.json({ success: true, message: 'Password updated successfully' })
  } catch (error) {
    logger.error('❌ Change user password error:', error)
    res.status(error.statusCode || 400).json({
      error: 'Password update error',
      message: error.message || 'Failed to update password'
    })
  }
})

// 🔑 获取用户的API Keys
router.get('/api-keys', authenticateUser, async (req, res) => {
  try {
    const { includeDeleted = 'false' } = req.query
    const apiKeys = await apiKeyService.getUserApiKeys(req.user.id, includeDeleted === 'true')

    // 移除敏感信息并格式化usage数据
    const safeApiKeys = apiKeys.map((key) => {
      // Flatten usage structure for frontend compatibility
      let flatUsage = {
        requests: 0,
        inputTokens: 0,
        outputTokens: 0,
        totalCost: 0
      }

      if (key.usage && key.usage.total) {
        flatUsage = {
          requests: key.usage.total.requests || 0,
          inputTokens: key.usage.total.inputTokens || 0,
          outputTokens: key.usage.total.outputTokens || 0,
          totalCost: key.totalCost || 0
        }
      }

      return {
        id: key.id,
        name: key.name,
        description: key.description,
        tokenLimit: key.tokenLimit,
        isActive: key.isActive,
        createdAt: key.createdAt,
        lastUsedAt: key.lastUsedAt,
        expiresAt: key.expiresAt,
        usage: flatUsage,
        dailyCost: key.dailyCost,
        dailyCostLimit: key.dailyCostLimit,
        totalCost: key.totalCost,
        totalCostLimit: key.totalCostLimit,
        // 不返回实际的key值，只返回前缀和后几位
        keyPreview: key.key
          ? `${key.key.substring(0, 8)}...${key.key.substring(key.key.length - 4)}`
          : null,
        // Include deletion fields for deleted keys
        isDeleted: key.isDeleted,
        deletedAt: key.deletedAt,
        deletedBy: key.deletedBy,
        deletedByType: key.deletedByType,
        claudeAccountId: key.claudeAccountId || '',
        claudeConsoleAccountId: key.claudeConsoleAccountId || '',
        geminiAccountId: key.geminiAccountId || '',
        openaiAccountId: key.openaiAccountId || '',
        azureOpenaiAccountId: key.azureOpenaiAccountId || '',
        bedrockAccountId: key.bedrockAccountId || '',
        droidAccountId: key.droidAccountId || ''
      }
    })

    res.json({
      success: true,
      apiKeys: safeApiKeys,
      total: safeApiKeys.length
    })
  } catch (error) {
    logger.error('❌ Get user API keys error:', error)
    res.status(500).json({
      error: 'API Keys error',
      message: 'Failed to retrieve API keys'
    })
  }
})

// 🔑 创建新的API Key
router.post('/api-keys', authenticateUser, async (req, res) => {
  try {
    const {
      name,
      description,
      tokenLimit,
      expiresAt,
      dailyCostLimit,
      totalCostLimit,
      claudeAccountId,
      claudeConsoleAccountId,
      geminiAccountId,
      openaiAccountId,
      azureOpenaiAccountId,
      bedrockAccountId,
      droidAccountId,
      permissions
    } = req.body

    if (!name || !name.trim()) {
      return res.status(400).json({
        error: 'Missing name',
        message: 'API key name is required'
      })
    }

    if (
      totalCostLimit !== undefined &&
      totalCostLimit !== null &&
      totalCostLimit !== '' &&
      (Number.isNaN(Number(totalCostLimit)) || Number(totalCostLimit) < 0)
    ) {
      return res.status(400).json({
        error: 'Invalid total cost limit',
        message: 'Total cost limit must be a non-negative number'
      })
    }

    // 检查用户API Key数量限制
    const userApiKeys = await apiKeyService.getUserApiKeys(req.user.id)
    if (userApiKeys.length >= config.userManagement.maxApiKeysPerUser) {
      return res.status(400).json({
        error: 'API key limit exceeded',
        message: `You can only have up to ${config.userManagement.maxApiKeysPerUser} API keys`
      })
    }

    await validateUserAccountBindings(req.user.id, {
      claudeAccountId,
      claudeConsoleAccountId,
      geminiAccountId,
      openaiAccountId,
      azureOpenaiAccountId,
      bedrockAccountId,
      droidAccountId
    })

    // 创建API Key数据
    const apiKeyData = {
      name: name.trim(),
      description: description?.trim() || '',
      userId: req.user.id,
      userUsername: req.user.username,
      tokenLimit: tokenLimit || null,
      expiresAt: expiresAt || null,
      dailyCostLimit: dailyCostLimit || null,
      totalCostLimit: totalCostLimit || null,
      createdBy: 'user',
      permissions: permissions || 'all',
      claudeAccountId: claudeAccountId || null,
      claudeConsoleAccountId: claudeConsoleAccountId || null,
      geminiAccountId: geminiAccountId || null,
      openaiAccountId: openaiAccountId || null,
      azureOpenaiAccountId: azureOpenaiAccountId || null,
      bedrockAccountId: bedrockAccountId || null,
      droidAccountId: droidAccountId || null
    }

    const newApiKey = await apiKeyService.createApiKey(apiKeyData)

    // 更新用户API Key数量
    await userService.updateUserApiKeyCount(req.user.id, userApiKeys.length + 1)

    logger.info(`🔑 User ${req.user.username} created API key: ${name}`)

    res.status(201).json({
      success: true,
      message: 'API key created successfully',
      apiKey: {
        id: newApiKey.id,
        name: newApiKey.name,
        description: newApiKey.description,
        key: newApiKey.apiKey, // 只在创建时返回完整key
        tokenLimit: newApiKey.tokenLimit,
        expiresAt: newApiKey.expiresAt,
        dailyCostLimit: newApiKey.dailyCostLimit,
        totalCostLimit: newApiKey.totalCostLimit,
        createdAt: newApiKey.createdAt
      }
    })
  } catch (error) {
    logger.error('❌ Create user API key error:', error)
    res.status(error.statusCode || 500).json({
      error: 'API Key creation error',
      message: error.message || 'Failed to create API key'
    })
  }
})

// 🗑️ 删除API Key
router.delete('/api-keys/:keyId', authenticateUser, async (req, res) => {
  try {
    const { keyId } = req.params

    // 检查是否允许用户删除自己的API Keys
    if (!config.userManagement.allowUserDeleteApiKeys) {
      return res.status(403).json({
        error: 'Operation not allowed',
        message:
          'Users are not allowed to delete their own API keys. Please contact an administrator.'
      })
    }

    // 检查API Key是否属于当前用户
    const existingKey = await apiKeyService.getApiKeyById(keyId)
    if (!existingKey || existingKey.userId !== req.user.id) {
      return res.status(404).json({
        error: 'API key not found',
        message: 'API key not found or you do not have permission to access it'
      })
    }

    await apiKeyService.deleteApiKey(keyId, req.user.username, 'user')

    // 更新用户API Key数量
    const userApiKeys = await apiKeyService.getUserApiKeys(req.user.id)
    await userService.updateUserApiKeyCount(req.user.id, userApiKeys.length)

    logger.info(`🗑️ User ${req.user.username} deleted API key: ${existingKey.name}`)

    res.json({
      success: true,
      message: 'API key deleted successfully'
    })
  } catch (error) {
    logger.error('❌ Delete user API key error:', error)
    res.status(500).json({
      error: 'API Key deletion error',
      message: 'Failed to delete API key'
    })
  }
})

// 📊 获取用户使用统计
router.get('/usage-stats', authenticateUser, async (req, res) => {
  try {
    const { period = 'week', model } = req.query

    // 获取用户的API Keys (including deleted ones for complete usage stats)
    const userApiKeys = await apiKeyService.getUserApiKeys(req.user.id, true)
    const apiKeyIds = userApiKeys.map((key) => key.id)

    if (apiKeyIds.length === 0) {
      return res.json({
        success: true,
        stats: {
          totalRequests: 0,
          totalInputTokens: 0,
          totalOutputTokens: 0,
          totalCost: 0,
          dailyStats: [],
          modelStats: []
        }
      })
    }

    // 获取使用统计
    const stats = await apiKeyService.getAggregatedUsageStats(apiKeyIds, { period, model })

    res.json({
      success: true,
      stats
    })
  } catch (error) {
    logger.error('❌ Get user usage stats error:', error)
    res.status(500).json({
      error: 'Usage stats error',
      message: 'Failed to retrieve usage statistics'
    })
  }
})

// 👁️ 获取当前用户可见账号
router.get('/accounts', authenticateUser, async (req, res) => {
  try {
    const { accountType, platform } = req.query
    const requestedType = accountType
      ? resourceVisibilityService.normalizeAccountType(accountType)
      : null
    const platformFilter = platform || null

    const accountTypes = requestedType
      ? [requestedType]
      : resourceVisibilityService.getAccountTypes()

    const result = {}
    for (const type of accountTypes) {
      const service = USER_ACCOUNT_SERVICES[type]
      if (!service) {
        continue
      }
      const category = resourceVisibilityService.getAccountCategory(type)
      if (platformFilter && platformFilter !== category && platformFilter !== type) {
        continue
      }

      const allAccounts = normalizeAccountListResult(await service.list())
      const visibleAccounts = await resourceVisibilityService.filterVisibleAccounts(
        req.user.id,
        allAccounts,
        type
      )
      result[type] = await resourceVisibilityService.annotateVisibility(
        req.user.id,
        visibleAccounts,
        type
      )
    }

    res.json({ success: true, data: result })
  } catch (error) {
    logger.error('❌ Get user visible accounts error:', error)
    res.status(500).json({
      error: 'Accounts error',
      message: 'Failed to retrieve visible accounts'
    })
  }
})

// 🏢 创建当前用户自己的账号
router.post('/accounts/:accountType', authenticateUser, async (req, res) => {
  try {
    const accountType = resourceVisibilityService.normalizeAccountType(req.params.accountType)
    const service = USER_ACCOUNT_SERVICES[accountType]
    if (!service) {
      return res.status(400).json({ error: 'Unsupported account type' })
    }

    const account = await service.create({
      ...req.body,
      accountType: req.body.accountType || 'shared'
    })
    await resourceVisibilityService.setAccountOwner(accountType, account.id, req.user)

    res.status(201).json({
      success: true,
      data: {
        ...account,
        ownerUserId: req.user.id,
        ownerUsername: req.user.username,
        ownedByCurrentUser: true
      }
    })
  } catch (error) {
    logger.error('❌ Create user account error:', error)
    res.status(error.statusCode || 500).json({
      error: 'Account creation error',
      message: error.message || 'Failed to create account'
    })
  }
})

// 🔄 更新当前用户拥有的账号
router.put('/accounts/:accountType/:accountId', authenticateUser, async (req, res) => {
  try {
    const accountType = resourceVisibilityService.normalizeAccountType(req.params.accountType)
    const service = USER_ACCOUNT_SERVICES[accountType]
    if (!service) {
      return res.status(400).json({ error: 'Unsupported account type' })
    }

    const canManage = await resourceVisibilityService.canManageAccount(
      req.user.id,
      accountType,
      req.params.accountId
    )
    if (!canManage) {
      return res.status(403).json({ error: 'No permission to update this account' })
    }

    const updated = await service.update(req.params.accountId, req.body)
    res.json({ success: true, data: updated })
  } catch (error) {
    logger.error('❌ Update user account error:', error)
    res.status(error.statusCode || 500).json({
      error: 'Account update error',
      message: error.message || 'Failed to update account'
    })
  }
})

// 🗑️ 删除当前用户拥有的账号
router.delete('/accounts/:accountType/:accountId', authenticateUser, async (req, res) => {
  try {
    const accountType = resourceVisibilityService.normalizeAccountType(req.params.accountType)
    const service = USER_ACCOUNT_SERVICES[accountType]
    if (!service) {
      return res.status(400).json({ error: 'Unsupported account type' })
    }

    const owned = await resourceVisibilityService.isAccountOwnedByUser(
      req.user.id,
      accountType,
      req.params.accountId
    )
    if (!owned) {
      return res.status(403).json({ error: 'Only account owner can delete this account' })
    }

    await service.delete(req.params.accountId)
    res.json({ success: true, message: 'Account deleted successfully' })
  } catch (error) {
    logger.error('❌ Delete user account error:', error)
    res.status(error.statusCode || 500).json({
      error: 'Account delete error',
      message: error.message || 'Failed to delete account'
    })
  }
})

// 📁 用户自己的使用分组（调度分组）
router.get('/account-groups', authenticateUser, async (req, res) => {
  try {
    const { platform } = req.query
    const groups = await accountGroupService.getAllGroups(platform || null, {
      ownerUserId: req.user.id
    })
    res.json({ success: true, data: groups })
  } catch (error) {
    logger.error('❌ Get user account groups error:', error)
    res.status(500).json({ error: 'Failed to get account groups', message: error.message })
  }
})

router.post('/account-groups', authenticateUser, async (req, res) => {
  try {
    const group = await accountGroupService.createGroup({
      name: req.body.name,
      platform: req.body.platform,
      description: req.body.description || '',
      ownerUserId: req.user.id,
      ownerUsername: req.user.username,
      createdByType: 'user'
    })
    res.status(201).json({ success: true, data: group })
  } catch (error) {
    logger.error('❌ Create user account group error:', error)
    res.status(400).json({ error: error.message })
  }
})

router.put('/account-groups/:groupId', authenticateUser, async (req, res) => {
  try {
    const group = await accountGroupService.getGroup(req.params.groupId)
    await resourceVisibilityService.assertCanUseAccountGroup(req.user.id, group)
    const updated = await accountGroupService.updateGroup(req.params.groupId, req.body)
    res.json({ success: true, data: updated })
  } catch (error) {
    logger.error('❌ Update user account group error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.delete('/account-groups/:groupId', authenticateUser, async (req, res) => {
  try {
    const group = await accountGroupService.getGroup(req.params.groupId)
    await resourceVisibilityService.assertCanUseAccountGroup(req.user.id, group)
    await accountGroupService.deleteGroup(req.params.groupId)
    res.json({ success: true, message: 'Account group deleted successfully' })
  } catch (error) {
    logger.error('❌ Delete user account group error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.get('/account-groups/:groupId/members', authenticateUser, async (req, res) => {
  try {
    const group = await accountGroupService.getGroup(req.params.groupId)
    await resourceVisibilityService.assertCanUseAccountGroup(req.user.id, group)
    const members = await accountGroupService.getGroupMembers(req.params.groupId)
    res.json({ success: true, data: members })
  } catch (error) {
    logger.error('❌ Get user account group members error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.post('/account-groups/:groupId/members', authenticateUser, async (req, res) => {
  try {
    const group = await accountGroupService.getGroup(req.params.groupId)
    await resourceVisibilityService.assertCanUseAccountGroup(req.user.id, group)
    const { accountId } = req.body
    const accountPlatform = req.body.accountPlatform || group.platform
    const accountType = req.body.accountType || accountPlatform
    await resourceVisibilityService.assertCanUseAccount(req.user.id, accountType, accountId)
    await accountGroupService.addAccountToGroup(accountId, req.params.groupId, accountPlatform)
    res.json({ success: true, message: 'Account added to group successfully' })
  } catch (error) {
    logger.error('❌ Add user account group member error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.delete('/account-groups/:groupId/members/:accountId', authenticateUser, async (req, res) => {
  try {
    const group = await accountGroupService.getGroup(req.params.groupId)
    await resourceVisibilityService.assertCanUseAccountGroup(req.user.id, group)
    await accountGroupService.removeAccountFromGroup(
      req.params.accountId,
      req.params.groupId,
      req.query.platform || group.platform
    )
    res.json({ success: true, message: 'Account removed from group successfully' })
  } catch (error) {
    logger.error('❌ Remove user account group member error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

// 🔐 权限分组
router.get('/permission-groups', authenticateUser, async (req, res) => {
  try {
    const groups = await permissionGroupService.getUserGroups(req.user.id)
    res.json({ success: true, data: groups })
  } catch (error) {
    logger.error('❌ Get permission groups error:', error)
    res.status(500).json({ error: 'Failed to get permission groups', message: error.message })
  }
})

router.post('/permission-groups', authenticateUser, async (req, res) => {
  try {
    const group = await permissionGroupService.createGroup(req.body, getUserActor(req))
    res.status(201).json({ success: true, data: group })
  } catch (error) {
    logger.error('❌ Create permission group error:', error)
    res.status(400).json({ error: error.message })
  }
})

router.put('/permission-groups/:groupId', authenticateUser, async (req, res) => {
  try {
    const group = await permissionGroupService.updateGroup(
      req.params.groupId,
      req.body,
      getUserActor(req)
    )
    res.json({ success: true, data: group })
  } catch (error) {
    logger.error('❌ Update permission group error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.delete('/permission-groups/:groupId', authenticateUser, async (req, res) => {
  try {
    await permissionGroupService.deleteGroup(req.params.groupId, getUserActor(req))
    res.json({ success: true, message: 'Permission group deleted successfully' })
  } catch (error) {
    logger.error('❌ Delete permission group error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.get('/permission-groups/:groupId/members', authenticateUser, async (req, res) => {
  try {
    await permissionGroupService.assertCanManageGroup(req.params.groupId, getUserActor(req))
    const members = await permissionGroupService.getMembers(req.params.groupId)
    res.json({ success: true, data: members })
  } catch (error) {
    logger.error('❌ Get permission group members error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.post('/permission-groups/:groupId/members', authenticateUser, async (req, res) => {
  try {
    let user = null
    if (req.body.userId) {
      user = await userService.getUserById(req.body.userId, false)
    } else if (req.body.username) {
      user = await userService.getUserByUsername(req.body.username)
    }
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    const members = await permissionGroupService.addMember(
      req.params.groupId,
      user,
      req.body.role || 'member',
      getUserActor(req)
    )
    res.json({ success: true, data: members })
  } catch (error) {
    logger.error('❌ Add permission group member error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.delete('/permission-groups/:groupId/members/:userId', authenticateUser, async (req, res) => {
  try {
    const members = await permissionGroupService.removeMember(
      req.params.groupId,
      req.params.userId,
      getUserActor(req)
    )
    res.json({ success: true, data: members })
  } catch (error) {
    logger.error('❌ Remove permission group member error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.get('/permission-groups/:groupId/accounts', authenticateUser, async (req, res) => {
  try {
    await permissionGroupService.assertCanManageGroup(req.params.groupId, getUserActor(req))
    const accounts = await permissionGroupService.getAccounts(req.params.groupId)
    res.json({ success: true, data: accounts })
  } catch (error) {
    logger.error('❌ Get permission group accounts error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.post('/permission-groups/:groupId/accounts', authenticateUser, async (req, res) => {
  try {
    const accounts = await permissionGroupService.addAccount(
      req.params.groupId,
      req.body.accountType,
      req.body.accountId,
      getUserActor(req)
    )
    res.json({ success: true, data: accounts })
  } catch (error) {
    logger.error('❌ Add permission group account error:', error)
    res.status(error.statusCode || 400).json({ error: error.message })
  }
})

router.delete(
  '/permission-groups/:groupId/accounts/:accountType/:accountId',
  authenticateUser,
  async (req, res) => {
    try {
      const accounts = await permissionGroupService.removeAccount(
        req.params.groupId,
        req.params.accountType,
        req.params.accountId,
        getUserActor(req)
      )
      res.json({ success: true, data: accounts })
    } catch (error) {
      logger.error('❌ Remove permission group account error:', error)
      res.status(error.statusCode || 400).json({ error: error.message })
    }
  }
)

// === 管理员用户管理端点 ===

// 📋 获取用户列表（管理员）
router.get('/', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, role, isActive, search } = req.query

    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      role,
      isActive: isActive === 'true' ? true : isActive === 'false' ? false : undefined
    }

    const result = await userService.getAllUsers(options)

    // 如果有搜索条件，进行过滤
    let filteredUsers = result.users
    if (search) {
      const searchLower = search.toLowerCase()
      filteredUsers = result.users.filter(
        (user) =>
          user.username.toLowerCase().includes(searchLower) ||
          user.displayName.toLowerCase().includes(searchLower) ||
          user.email.toLowerCase().includes(searchLower)
      )
    }

    res.json({
      success: true,
      users: filteredUsers,
      pagination: {
        total: result.total,
        page: result.page,
        limit: result.limit,
        totalPages: result.totalPages
      }
    })
  } catch (error) {
    logger.error('❌ Get users list error:', error)
    res.status(500).json({
      error: 'Users list error',
      message: 'Failed to retrieve users list'
    })
  }
})

// 👤 创建本地密码用户（管理员）
router.post('/', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    if (getUserAuthMode() !== 'local') {
      return res.status(400).json({
        error: 'Unsupported operation',
        message: 'Local user creation is only available in local auth mode'
      })
    }

    const username = inputValidator.validateUsername(req.body.username)
    inputValidator.validatePassword(req.body.password)

    const email = req.body.email ? inputValidator.validateEmail(req.body.email) : ''
    const displayName = req.body.displayName
      ? inputValidator.validateDisplayName(req.body.displayName)
      : username
    const firstName = req.body.firstName ? String(req.body.firstName).trim() : ''
    const lastName = req.body.lastName ? String(req.body.lastName).trim() : ''
    const role = req.body.role || config.userManagement.defaultUserRole
    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({
        error: 'Invalid role',
        message: 'Role must be user or admin'
      })
    }

    const user = await userService.createLocalUser({
      username,
      password: req.body.password,
      email,
      displayName,
      firstName,
      lastName,
      role,
      isActive: req.body.isActive !== false
    })

    res.status(201).json({
      success: true,
      message: 'Local user created successfully',
      user
    })
  } catch (error) {
    logger.error('❌ Create local user error:', error)
    res.status(error.statusCode || 400).json({
      error: 'User creation error',
      message: error.message || 'Failed to create user'
    })
  }
})

// 👤 获取特定用户信息（管理员）
router.get('/:userId', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params

    const user = await userService.getUserById(userId)
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User not found'
      })
    }

    // 获取用户的API Keys（包括已删除的以保留统计数据）
    const apiKeys = await apiKeyService.getUserApiKeys(userId, true)

    res.json({
      success: true,
      user: {
        ...user,
        apiKeys: apiKeys.map((key) => {
          // Flatten usage structure for frontend compatibility
          let flatUsage = {
            requests: 0,
            inputTokens: 0,
            outputTokens: 0,
            totalCost: 0
          }

          if (key.usage && key.usage.total) {
            flatUsage = {
              requests: key.usage.total.requests || 0,
              inputTokens: key.usage.total.inputTokens || 0,
              outputTokens: key.usage.total.outputTokens || 0,
              totalCost: key.totalCost || 0
            }
          }

          return {
            id: key.id,
            name: key.name,
            description: key.description,
            isActive: key.isActive,
            createdAt: key.createdAt,
            lastUsedAt: key.lastUsedAt,
            usage: flatUsage,
            keyPreview: key.key
              ? `${key.key.substring(0, 8)}...${key.key.substring(key.key.length - 4)}`
              : null
          }
        })
      }
    })
  } catch (error) {
    logger.error('❌ Get user details error:', error)
    res.status(500).json({
      error: 'User details error',
      message: 'Failed to retrieve user details'
    })
  }
})

// 🔄 更新用户状态（管理员）
router.patch('/:userId/status', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params
    const { isActive } = req.body

    if (typeof isActive !== 'boolean') {
      return res.status(400).json({
        error: 'Invalid status',
        message: 'isActive must be a boolean value'
      })
    }

    const updatedUser = await userService.updateUserStatus(userId, isActive)

    const adminUser = req.admin?.username || req.user?.username
    logger.info(
      `🔄 Admin ${adminUser} ${isActive ? 'enabled' : 'disabled'} user: ${updatedUser.username}`
    )

    res.json({
      success: true,
      message: `User ${isActive ? 'enabled' : 'disabled'} successfully`,
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        isActive: updatedUser.isActive,
        updatedAt: updatedUser.updatedAt
      }
    })
  } catch (error) {
    logger.error('❌ Update user status error:', error)
    res.status(500).json({
      error: 'Update status error',
      message: error.message || 'Failed to update user status'
    })
  }
})

// 🔄 更新用户角色（管理员）
router.patch('/:userId/role', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params
    const { role } = req.body

    const validRoles = ['user', 'admin']
    if (!role || !validRoles.includes(role)) {
      return res.status(400).json({
        error: 'Invalid role',
        message: `Role must be one of: ${validRoles.join(', ')}`
      })
    }

    const updatedUser = await userService.updateUserRole(userId, role)

    const adminUser = req.admin?.username || req.user?.username
    logger.info(`🔄 Admin ${adminUser} changed user ${updatedUser.username} role to: ${role}`)

    res.json({
      success: true,
      message: `User role updated to ${role} successfully`,
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        role: updatedUser.role,
        updatedAt: updatedUser.updatedAt
      }
    })
  } catch (error) {
    logger.error('❌ Update user role error:', error)
    res.status(500).json({
      error: 'Update role error',
      message: error.message || 'Failed to update user role'
    })
  }
})

// 🔐 重置本地用户密码（管理员）
router.patch('/:userId/password', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    if (getUserAuthMode() !== 'local') {
      return res.status(400).json({
        error: 'Unsupported operation',
        message: 'Password reset is only available in local auth mode'
      })
    }

    const { userId } = req.params
    const { password } = req.body
    inputValidator.validatePassword(password)

    const user = await userService.updateLocalUserPassword(userId, password)

    const adminUser = req.admin?.username || req.user?.username
    logger.info(`🔐 Admin ${adminUser} reset local password for user: ${user.username}`)

    res.json({
      success: true,
      message: 'Password reset successfully',
      user: {
        id: user.id,
        username: user.username,
        passwordUpdatedAt: user.passwordUpdatedAt,
        updatedAt: user.updatedAt
      }
    })
  } catch (error) {
    logger.error('❌ Reset local user password error:', error)
    res.status(error.statusCode || 400).json({
      error: 'Password reset error',
      message: error.message || 'Failed to reset password'
    })
  }
})

// 🔑 禁用用户的所有API Keys（管理员）
router.post('/:userId/disable-keys', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params

    const user = await userService.getUserById(userId)
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User not found'
      })
    }

    const result = await apiKeyService.disableUserApiKeys(userId)

    const adminUser = req.admin?.username || req.user?.username
    logger.info(`🔑 Admin ${adminUser} disabled all API keys for user: ${user.username}`)

    res.json({
      success: true,
      message: `Disabled ${result.count} API keys for user ${user.username}`,
      disabledCount: result.count
    })
  } catch (error) {
    logger.error('❌ Disable user API keys error:', error)
    res.status(500).json({
      error: 'Disable keys error',
      message: 'Failed to disable user API keys'
    })
  }
})

// 📊 获取用户使用统计（管理员）
router.get('/:userId/usage-stats', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params
    const { period = 'week', model } = req.query

    const user = await userService.getUserById(userId)
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User not found'
      })
    }

    // 获取用户的API Keys（包括已删除的以保留统计数据）
    const userApiKeys = await apiKeyService.getUserApiKeys(userId, true)
    const apiKeyIds = userApiKeys.map((key) => key.id)

    if (apiKeyIds.length === 0) {
      return res.json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          displayName: user.displayName
        },
        stats: {
          totalRequests: 0,
          totalInputTokens: 0,
          totalOutputTokens: 0,
          totalCost: 0,
          dailyStats: [],
          modelStats: []
        }
      })
    }

    // 获取使用统计
    const stats = await apiKeyService.getAggregatedUsageStats(apiKeyIds, { period, model })

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName
      },
      stats
    })
  } catch (error) {
    logger.error('❌ Get user usage stats (admin) error:', error)
    res.status(500).json({
      error: 'Usage stats error',
      message: 'Failed to retrieve user usage statistics'
    })
  }
})

// 📊 获取用户管理统计（管理员）
router.get('/stats/overview', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    const stats = await userService.getUserStats()

    res.json({
      success: true,
      stats
    })
  } catch (error) {
    logger.error('❌ Get user stats overview error:', error)
    res.status(500).json({
      error: 'Stats error',
      message: 'Failed to retrieve user statistics'
    })
  }
})

// 🔧 测试LDAP连接（管理员）
router.get('/admin/ldap-test', authenticateUserOrAdmin, requireAdmin, async (req, res) => {
  try {
    const testResult = await ldapService.testConnection()

    res.json({
      success: true,
      ldapTest: testResult,
      config: ldapService.getConfigInfo()
    })
  } catch (error) {
    logger.error('❌ LDAP test error:', error)
    res.status(500).json({
      error: 'LDAP test error',
      message: 'Failed to test LDAP connection'
    })
  }
})

// ═══════════════════════════════════════════════════════════════════════════
// 额度卡核销相关路由
// ═══════════════════════════════════════════════════════════════════════════

const quotaCardService = require('../services/quotaCardService')

// 🎫 核销额度卡
router.post('/redeem-card', authenticateUser, async (req, res) => {
  try {
    const { code, apiKeyId } = req.body

    if (!code) {
      return res.status(400).json({
        error: 'Missing card code',
        message: 'Card code is required'
      })
    }

    if (!apiKeyId) {
      return res.status(400).json({
        error: 'Missing API key ID',
        message: 'API key ID is required'
      })
    }

    // 验证 API Key 属于当前用户
    const keyData = await redis.getApiKey(apiKeyId)
    if (!keyData || Object.keys(keyData).length === 0) {
      return res.status(404).json({
        error: 'API key not found',
        message: 'The specified API key does not exist'
      })
    }

    if (keyData.userId !== req.user.id) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'You can only redeem cards to your own API keys'
      })
    }

    // 执行核销
    const result = await quotaCardService.redeemCard(code, apiKeyId, req.user.id, req.user.username)

    logger.success(`🎫 User ${req.user.username} redeemed card ${code} to key ${apiKeyId}`)

    res.json({
      success: true,
      data: result
    })
  } catch (error) {
    logger.error('❌ Redeem card error:', error)
    res.status(400).json({
      error: 'Redeem failed',
      message: error.message
    })
  }
})

// 📋 获取用户的核销历史
router.get('/redemption-history', authenticateUser, async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query

    const result = await quotaCardService.getRedemptions({
      userId: req.user.id,
      limit: parseInt(limit),
      offset: parseInt(offset)
    })

    res.json({
      success: true,
      data: result
    })
  } catch (error) {
    logger.error('❌ Get redemption history error:', error)
    res.status(500).json({
      error: 'Failed to get redemption history',
      message: error.message
    })
  }
})

// 📊 获取用户的额度信息
router.get('/quota-info', authenticateUser, async (req, res) => {
  try {
    const { apiKeyId } = req.query

    if (!apiKeyId) {
      return res.status(400).json({
        error: 'Missing API key ID',
        message: 'API key ID is required'
      })
    }

    // 验证 API Key 属于当前用户
    const keyData = await redis.getApiKey(apiKeyId)
    if (!keyData || Object.keys(keyData).length === 0) {
      return res.status(404).json({
        error: 'API key not found',
        message: 'The specified API key does not exist'
      })
    }

    if (keyData.userId !== req.user.id) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'You can only view your own API key quota'
      })
    }

    // 检查是否为聚合 Key
    if (keyData.isAggregated !== 'true') {
      return res.json({
        success: true,
        data: {
          isAggregated: false,
          message: 'This is a traditional API key, not using quota system'
        }
      })
    }

    // 解析聚合 Key 数据
    let permissions = []
    let serviceQuotaLimits = {}
    let serviceQuotaUsed = {}

    try {
      permissions = JSON.parse(keyData.permissions || '[]')
    } catch (e) {
      permissions = [keyData.permissions]
    }

    try {
      serviceQuotaLimits = JSON.parse(keyData.serviceQuotaLimits || '{}')
      serviceQuotaUsed = JSON.parse(keyData.serviceQuotaUsed || '{}')
    } catch (e) {
      // 解析失败使用默认值
    }

    res.json({
      success: true,
      data: {
        isAggregated: true,
        quotaLimit: parseFloat(keyData.quotaLimit || 0),
        quotaUsed: parseFloat(keyData.quotaUsed || 0),
        quotaRemaining: parseFloat(keyData.quotaLimit || 0) - parseFloat(keyData.quotaUsed || 0),
        permissions,
        serviceQuotaLimits,
        serviceQuotaUsed,
        expiresAt: keyData.expiresAt
      }
    })
  } catch (error) {
    logger.error('❌ Get quota info error:', error)
    res.status(500).json({
      error: 'Failed to get quota info',
      message: error.message
    })
  }
})

module.exports = router
