const { v4: uuidv4 } = require('uuid')
const redis = require('../models/redis')
const logger = require('../utils/logger')
const resourceVisibilityService = require('./resourceVisibilityService')

const VALID_ROLES = new Set(['owner', 'manager', 'member'])

class PermissionGroupService {
  constructor() {
    this.GROUPS_KEY = 'permission_groups'
    this.GROUP_PREFIX = 'permission_group:'
    this.GROUP_MEMBERS_PREFIX = 'permission_group_members:'
    this.GROUP_MEMBER_PREFIX = 'permission_group_member:'
    this.GROUP_ACCOUNTS_PREFIX = 'permission_group_accounts:'
    this.USER_GROUPS_PREFIX = 'user_permission_groups:'
    this.ACCOUNT_GROUPS_PREFIX = 'account_permission_groups:'
  }

  _client() {
    return redis.getClientSafe()
  }

  _normalizeRole(role) {
    const normalized = role || 'member'
    if (!VALID_ROLES.has(normalized)) {
      throw new Error('Invalid member role')
    }
    return normalized
  }

  async createGroup(groupData, owner) {
    const { name, description = '' } = groupData
    if (!owner?.id) {
      throw new Error('Owner user is required')
    }
    if (!name || !String(name).trim()) {
      throw new Error('权限分组名称不能为空')
    }

    const client = this._client()
    const groupId = uuidv4()
    const now = new Date().toISOString()
    const group = {
      id: groupId,
      name: String(name).trim(),
      description: description || '',
      ownerUserId: owner.id,
      ownerUsername: owner.username || '',
      createdAt: now,
      updatedAt: now
    }

    const pipeline = client.pipeline()
    pipeline.hmset(`${this.GROUP_PREFIX}${groupId}`, group)
    pipeline.sadd(this.GROUPS_KEY, groupId)
    pipeline.sadd(`${this.GROUP_MEMBERS_PREFIX}${groupId}`, owner.id)
    pipeline.sadd(`${this.USER_GROUPS_PREFIX}${owner.id}`, groupId)
    pipeline.hmset(`${this.GROUP_MEMBER_PREFIX}${groupId}:${owner.id}`, {
      userId: owner.id,
      username: owner.username || '',
      role: 'owner',
      joinedAt: now
    })
    await pipeline.exec()

    logger.success(`创建权限分组成功: ${group.name} (${groupId})`)
    return this.getGroup(groupId)
  }

  async getGroup(groupId) {
    const client = this._client()
    const group = await client.hgetall(`${this.GROUP_PREFIX}${groupId}`)
    if (!group || Object.keys(group).length === 0) {
      return null
    }

    const [memberCount, accountCount] = await Promise.all([
      client.scard(`${this.GROUP_MEMBERS_PREFIX}${groupId}`),
      client.scard(`${this.GROUP_ACCOUNTS_PREFIX}${groupId}`)
    ])

    return {
      ...group,
      memberCount: memberCount || 0,
      accountCount: accountCount || 0
    }
  }

  async getAllGroups() {
    const client = this._client()
    const groupIds = await client.smembers(this.GROUPS_KEY)
    const groups = []
    for (const groupId of groupIds) {
      const group = await this.getGroup(groupId)
      if (group) {
        groups.push(group)
      }
    }
    groups.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    return groups
  }

  async getUserGroups(userId) {
    if (!userId) {
      return []
    }
    const client = this._client()
    const groupIds = await client.smembers(`${this.USER_GROUPS_PREFIX}${userId}`)
    const groups = []
    for (const groupId of groupIds) {
      const group = await this.getGroup(groupId)
      if (group) {
        const membership = await this.getMembership(groupId, userId)
        groups.push({ ...group, currentUserRole: membership?.role || 'member' })
      }
    }
    groups.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    return groups
  }

  async updateGroup(groupId, updates, actor) {
    await this.assertCanManageGroup(groupId, actor)
    const client = this._client()

    const updateData = {
      updatedAt: new Date().toISOString()
    }

    if (updates.name !== undefined) {
      if (!String(updates.name).trim()) {
        throw new Error('权限分组名称不能为空')
      }
      updateData.name = String(updates.name).trim()
    }
    if (updates.description !== undefined) {
      updateData.description = updates.description || ''
    }

    await client.hmset(`${this.GROUP_PREFIX}${groupId}`, updateData)
    return this.getGroup(groupId)
  }

  async deleteGroup(groupId, actor) {
    await this.assertCanManageGroup(groupId, actor)
    const client = this._client()
    const group = await this.getGroup(groupId)
    if (!group) {
      throw new Error('权限分组不存在')
    }

    const [memberIds, accountRefs] = await Promise.all([
      client.smembers(`${this.GROUP_MEMBERS_PREFIX}${groupId}`),
      client.smembers(`${this.GROUP_ACCOUNTS_PREFIX}${groupId}`)
    ])

    const pipeline = client.pipeline()
    for (const userId of memberIds) {
      pipeline.srem(`${this.USER_GROUPS_PREFIX}${userId}`, groupId)
      pipeline.del(`${this.GROUP_MEMBER_PREFIX}${groupId}:${userId}`)
    }
    for (const ref of accountRefs) {
      pipeline.srem(`${this.ACCOUNT_GROUPS_PREFIX}${ref}`, groupId)
    }
    pipeline.del(`${this.GROUP_MEMBERS_PREFIX}${groupId}`)
    pipeline.del(`${this.GROUP_ACCOUNTS_PREFIX}${groupId}`)
    pipeline.del(`${this.GROUP_PREFIX}${groupId}`)
    pipeline.srem(this.GROUPS_KEY, groupId)
    await pipeline.exec()

    logger.success(`删除权限分组成功: ${group.name}`)
    return { success: true }
  }

  async getMembership(groupId, userId) {
    const client = this._client()
    const member = await client.hgetall(`${this.GROUP_MEMBER_PREFIX}${groupId}:${userId}`)
    return member && Object.keys(member).length > 0 ? member : null
  }

  async canManageGroup(groupId, actor) {
    if (actor?.admin || actor?.type === 'admin') {
      return true
    }
    const userId = actor?.id || actor?.userId
    if (!userId) {
      return false
    }
    const group = await this.getGroup(groupId)
    if (!group) {
      return false
    }
    if (group.ownerUserId === userId) {
      return true
    }
    const membership = await this.getMembership(groupId, userId)
    return ['owner', 'manager'].includes(membership?.role)
  }

  async assertCanManageGroup(groupId, actor) {
    const allowed = await this.canManageGroup(groupId, actor)
    if (!allowed) {
      const error = new Error('No permission to manage this permission group')
      error.statusCode = 403
      throw error
    }
  }

  async addMember(groupId, user, role, actor) {
    await this.assertCanManageGroup(groupId, actor)
    if (!user?.id) {
      throw new Error('User is required')
    }
    const normalizedRole = this._normalizeRole(role)
    const client = this._client()
    const group = await this.getGroup(groupId)
    if (!group) {
      throw new Error('权限分组不存在')
    }

    const now = new Date().toISOString()
    const pipeline = client.pipeline()
    pipeline.sadd(`${this.GROUP_MEMBERS_PREFIX}${groupId}`, user.id)
    pipeline.sadd(`${this.USER_GROUPS_PREFIX}${user.id}`, groupId)
    pipeline.hmset(`${this.GROUP_MEMBER_PREFIX}${groupId}:${user.id}`, {
      userId: user.id,
      username: user.username || '',
      displayName: user.displayName || '',
      role: normalizedRole,
      joinedAt: now
    })
    await pipeline.exec()

    return this.getMembers(groupId)
  }

  async removeMember(groupId, userId, actor) {
    await this.assertCanManageGroup(groupId, actor)
    const group = await this.getGroup(groupId)
    if (!group) {
      throw new Error('权限分组不存在')
    }
    if (group.ownerUserId === userId) {
      throw new Error('不能移除权限分组所有者')
    }

    const client = this._client()
    const pipeline = client.pipeline()
    pipeline.srem(`${this.GROUP_MEMBERS_PREFIX}${groupId}`, userId)
    pipeline.srem(`${this.USER_GROUPS_PREFIX}${userId}`, groupId)
    pipeline.del(`${this.GROUP_MEMBER_PREFIX}${groupId}:${userId}`)
    await pipeline.exec()

    return this.getMembers(groupId)
  }

  async getMembers(groupId) {
    const client = this._client()
    const userIds = await client.smembers(`${this.GROUP_MEMBERS_PREFIX}${groupId}`)
    const members = []
    for (const userId of userIds) {
      const member = await this.getMembership(groupId, userId)
      if (member) {
        members.push(member)
      }
    }
    members.sort((a, b) => {
      const roleRank = { owner: 0, manager: 1, member: 2 }
      return (roleRank[a.role] ?? 99) - (roleRank[b.role] ?? 99)
    })
    return members
  }

  async addAccount(groupId, accountType, accountId, actor) {
    await this.assertCanManageGroup(groupId, actor)
    const normalizedType = resourceVisibilityService.normalizeAccountType(accountType)
    const ref = resourceVisibilityService.getAccountRef(normalizedType, accountId)
    if (!ref) {
      throw new Error('Invalid account reference')
    }

    const account = await resourceVisibilityService.getRawAccount(normalizedType, accountId)
    if (!account) {
      throw new Error('账号不存在')
    }

    if (!actor?.admin && actor?.id) {
      const canManageAccount = await resourceVisibilityService.canManageAccount(
        actor.id,
        normalizedType,
        accountId
      )
      if (!canManageAccount) {
        const error = new Error('No permission to share this account')
        error.statusCode = 403
        throw error
      }
    }

    const client = this._client()
    const pipeline = client.pipeline()
    pipeline.sadd(`${this.GROUP_ACCOUNTS_PREFIX}${groupId}`, ref)
    pipeline.sadd(`${this.ACCOUNT_GROUPS_PREFIX}${ref}`, groupId)
    await pipeline.exec()

    return this.getAccounts(groupId)
  }

  async removeAccount(groupId, accountType, accountId, actor) {
    await this.assertCanManageGroup(groupId, actor)
    const ref = resourceVisibilityService.getAccountRef(accountType, accountId)
    if (!ref) {
      throw new Error('Invalid account reference')
    }

    const client = this._client()
    const pipeline = client.pipeline()
    pipeline.srem(`${this.GROUP_ACCOUNTS_PREFIX}${groupId}`, ref)
    pipeline.srem(`${this.ACCOUNT_GROUPS_PREFIX}${ref}`, groupId)
    await pipeline.exec()

    return this.getAccounts(groupId)
  }

  async getAccounts(groupId) {
    const client = this._client()
    const refs = await client.smembers(`${this.GROUP_ACCOUNTS_PREFIX}${groupId}`)
    const accounts = []
    for (const ref of refs) {
      const parsed = resourceVisibilityService.parseAccountRef(ref)
      if (!parsed) {
        continue
      }
      const summary = await resourceVisibilityService.getAccountSummary(
        parsed.accountType,
        parsed.accountId
      )
      if (summary) {
        accounts.push(summary)
      }
    }
    accounts.sort((a, b) => a.name.localeCompare(b.name))
    return accounts
  }
}

module.exports = new PermissionGroupService()
