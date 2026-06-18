const redis = require('../models/redis')
const logger = require('../utils/logger')

const ACCOUNT_TYPE_ALIASES = {
  'claude-official': 'claude',
  claude_oauth: 'claude',
  claude_console: 'claude-console',
  'claude-console': 'claude-console',
  openai_responses: 'openai-responses',
  'openai-response': 'openai-responses',
  'openai-responses': 'openai-responses',
  azure_openai: 'azure-openai',
  azureopenai: 'azure-openai',
  'azure-openai': 'azure-openai',
  gemini_api: 'gemini-api',
  'gemini-api': 'gemini-api'
}

const ACCOUNT_CONFIG = {
  claude: {
    keyPrefix: 'claude:account:',
    category: 'claude',
    displayName: 'Claude'
  },
  'claude-console': {
    keyPrefix: 'claude_console_account:',
    category: 'claude',
    displayName: 'Claude Console'
  },
  ccr: {
    keyPrefix: 'ccr_account:',
    category: 'claude',
    displayName: 'CCR'
  },
  bedrock: {
    keyPrefix: 'bedrock_account:',
    category: 'claude',
    displayName: 'Bedrock',
    storage: 'json'
  },
  gemini: {
    keyPrefix: 'gemini_account:',
    category: 'gemini',
    displayName: 'Gemini'
  },
  'gemini-api': {
    keyPrefix: 'gemini_api_account:',
    category: 'gemini',
    displayName: 'Gemini API'
  },
  openai: {
    keyPrefix: 'openai:account:',
    category: 'openai',
    displayName: 'OpenAI'
  },
  'openai-responses': {
    keyPrefix: 'openai_responses_account:',
    category: 'openai',
    displayName: 'OpenAI Responses'
  },
  'azure-openai': {
    keyPrefix: 'azure_openai:account:',
    category: 'openai',
    displayName: 'Azure OpenAI'
  },
  droid: {
    keyPrefix: 'droid:account:',
    category: 'droid',
    displayName: 'Droid'
  }
}

function normalizeAccountType(accountType) {
  if (!accountType) {
    return null
  }
  const normalized = String(accountType).trim().toLowerCase()
  return ACCOUNT_TYPE_ALIASES[normalized] || normalized
}

function getAccountConfig(accountType) {
  const type = normalizeAccountType(accountType)
  return type ? ACCOUNT_CONFIG[type] : null
}

function accountRef(accountType, accountId) {
  const type = normalizeAccountType(accountType)
  if (!type || !accountId) {
    return null
  }
  return `${type}:${accountId}`
}

function parseAccountRef(ref) {
  if (!ref || typeof ref !== 'string') {
    return null
  }
  const separatorIndex = ref.indexOf(':')
  if (separatorIndex <= 0) {
    return null
  }
  const accountType = normalizeAccountType(ref.slice(0, separatorIndex))
  const accountId = ref.slice(separatorIndex + 1)
  if (!accountType || !accountId) {
    return null
  }
  return { accountType, accountId }
}

function getAccountKey(accountType, accountId) {
  const config = getAccountConfig(accountType)
  if (!config || !accountId) {
    return null
  }
  return `${config.keyPrefix}${accountId}`
}

function isAdminActor(actor) {
  return Boolean(actor?.admin || actor?.isAdmin || actor?.type === 'admin')
}

function getUserId(actorOrUserId) {
  if (!actorOrUserId) {
    return ''
  }
  if (typeof actorOrUserId === 'string') {
    return actorOrUserId
  }
  return actorOrUserId.id || actorOrUserId.userId || actorOrUserId.user?.id || ''
}

class ResourceVisibilityService {
  normalizeAccountType(accountType) {
    return normalizeAccountType(accountType)
  }

  getAccountTypes() {
    return Object.keys(ACCOUNT_CONFIG)
  }

  getAccountCategory(accountType) {
    return getAccountConfig(accountType)?.category || null
  }

  getAccountRef(accountType, accountId) {
    return accountRef(accountType, accountId)
  }

  parseAccountRef(ref) {
    return parseAccountRef(ref)
  }

  getAccountKey(accountType, accountId) {
    return getAccountKey(accountType, accountId)
  }

  async getRawAccount(accountType, accountId) {
    const key = getAccountKey(accountType, accountId)
    if (!key) {
      return null
    }

    const client = redis.getClientSafe()
    const config = getAccountConfig(accountType)
    if (config?.storage === 'json') {
      const raw = await client.get(key)
      if (!raw) {
        return null
      }
      try {
        const parsed = JSON.parse(raw)
        return { id: accountId, ...parsed }
      } catch (error) {
        logger.warn(
          `Failed to parse account data for ${accountType}:${accountId}: ${error.message}`
        )
        return null
      }
    }

    const data = await client.hgetall(key)
    if (!data || Object.keys(data).length === 0) {
      return null
    }
    return { id: accountId, ...data }
  }

  async setAccountOwner(accountType, accountId, owner = {}) {
    const key = getAccountKey(accountType, accountId)
    if (!key) {
      throw new Error(`Unsupported account type: ${accountType}`)
    }

    const client = redis.getClientSafe()
    const updates = {
      ownerUserId: owner.id || owner.userId || '',
      ownerUsername: owner.username || owner.userUsername || '',
      createdByType: owner.id || owner.userId ? 'user' : owner.createdByType || 'admin',
      updatedAt: new Date().toISOString()
    }

    const config = getAccountConfig(accountType)
    if (config?.storage === 'json') {
      const raw = await client.get(key)
      const parsed = raw ? JSON.parse(raw) : {}
      await client.set(key, JSON.stringify({ ...parsed, ...updates }))
      return updates
    }

    await client.hset(key, updates)
    return updates
  }

  async isAccountOwnedByUser(userId, accountType, accountId) {
    if (!userId || !accountId) {
      return false
    }

    const account = await this.getRawAccount(accountType, accountId)
    return account?.ownerUserId === userId
  }

  async getUserPermissionGroupIds(userId) {
    if (!userId) {
      return []
    }
    const client = redis.getClientSafe()
    return await client.smembers(`user_permission_groups:${userId}`)
  }

  async getAccountPermissionGroupIds(accountType, accountId) {
    const ref = accountRef(accountType, accountId)
    if (!ref) {
      return []
    }
    const client = redis.getClientSafe()
    return await client.smembers(`account_permission_groups:${ref}`)
  }

  async canUseAccount(userId, accountType, accountId) {
    if (!userId) {
      return true
    }

    const account = await this.getRawAccount(accountType, accountId)
    if (!account) {
      return false
    }

    if (account.ownerUserId === userId) {
      return true
    }

    const ref = accountRef(accountType, accountId)
    if (!ref) {
      return false
    }

    const client = redis.getClientSafe()
    const userGroups = await client.smembers(`user_permission_groups:${userId}`)
    if (!userGroups || userGroups.length === 0) {
      return false
    }

    for (const groupId of userGroups) {
      const isAccountShared = await client.sismember(`permission_group_accounts:${groupId}`, ref)
      if (isAccountShared) {
        return true
      }
    }

    return false
  }

  async canManageAccount(userId, accountType, accountId) {
    if (!userId) {
      return true
    }

    const account = await this.getRawAccount(accountType, accountId)
    if (!account) {
      return false
    }

    if (account.ownerUserId === userId) {
      return true
    }

    const ref = accountRef(accountType, accountId)
    if (!ref) {
      return false
    }

    const client = redis.getClientSafe()
    const userGroups = await client.smembers(`user_permission_groups:${userId}`)
    for (const groupId of userGroups || []) {
      const [isAccountShared, member] = await Promise.all([
        client.sismember(`permission_group_accounts:${groupId}`, ref),
        client.hgetall(`permission_group_member:${groupId}:${userId}`)
      ])

      if (isAccountShared && ['owner', 'manager'].includes(member?.role)) {
        return true
      }
    }

    return false
  }

  async assertCanUseAccount(userId, accountType, accountId) {
    const allowed = await this.canUseAccount(userId, accountType, accountId)
    if (!allowed) {
      const error = new Error('Account is not visible to current user')
      error.statusCode = 403
      throw error
    }
  }

  async filterVisibleAccounts(actorOrUserId, accounts, accountType = null) {
    if (!Array.isArray(accounts) || accounts.length === 0) {
      return []
    }

    if (isAdminActor(actorOrUserId)) {
      return accounts
    }

    const userId = getUserId(actorOrUserId)
    if (!userId) {
      return accounts
    }

    const visible = []
    for (const account of accounts) {
      const type = accountType || account.accountType || account.type || account.platform
      const id = account.id || account.accountId
      if (await this.canUseAccount(userId, type, id)) {
        visible.push(account)
      }
    }
    return visible
  }

  async filterVisibleAccountSelections(actorOrUserId, selections) {
    if (!Array.isArray(selections) || selections.length === 0) {
      return []
    }

    if (isAdminActor(actorOrUserId)) {
      return selections
    }

    const userId = getUserId(actorOrUserId)
    if (!userId) {
      return selections
    }

    const visible = []
    for (const selection of selections) {
      const type = selection.accountType || selection.type || selection.platform
      const id = selection.accountId || selection.id
      if (await this.canUseAccount(userId, type, id)) {
        visible.push(selection)
      }
    }
    return visible
  }

  async canUseAccountGroup(userId, group) {
    if (!userId) {
      return true
    }
    return group?.ownerUserId === userId
  }

  async assertCanUseAccountGroup(userId, group) {
    const allowed = await this.canUseAccountGroup(userId, group)
    if (!allowed) {
      const error = new Error('Account group is not visible to current user')
      error.statusCode = 403
      throw error
    }
  }

  async getAccountSummary(accountType, accountId) {
    const normalizedType = normalizeAccountType(accountType)
    const account = await this.getRawAccount(normalizedType, accountId)
    if (!account) {
      return null
    }

    const config = getAccountConfig(normalizedType)
    return {
      id: accountId,
      accountId,
      accountType: normalizedType,
      platform: config?.category || normalizedType,
      typeLabel: config?.displayName || normalizedType,
      name: account.name || accountId,
      ownerUserId: account.ownerUserId || '',
      ownerUsername: account.ownerUsername || '',
      createdByType: account.createdByType || (account.ownerUserId ? 'user' : 'admin')
    }
  }

  async annotateVisibility(userId, accounts, accountType = null) {
    if (!Array.isArray(accounts)) {
      return []
    }

    return await Promise.all(
      accounts.map(async (account) => {
        const type = accountType || account.accountType || account.type || account.platform
        const id = account.id || account.accountId
        const ownedByCurrentUser = userId
          ? await this.isAccountOwnedByUser(userId, type, id)
          : false

        return {
          ...account,
          ownerUserId: account.ownerUserId || '',
          ownerUsername: account.ownerUsername || '',
          ownedByCurrentUser,
          sharedWithCurrentUser: Boolean(userId && !ownedByCurrentUser)
        }
      })
    )
  }

  logDeniedAccess(context) {
    logger.security(
      `🚫 Resource access denied: user=${context.userId || 'unknown'}, account=${context.accountType || 'unknown'}:${context.accountId || 'unknown'}`
    )
  }
}

module.exports = new ResourceVisibilityService()
