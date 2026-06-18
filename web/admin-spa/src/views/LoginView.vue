<template>
  <div class="flex min-h-screen items-center justify-center p-4 sm:p-6">
    <!-- 主题切换按钮 - 固定在右上角 -->
    <div class="fixed right-4 top-4 z-50">
      <ThemeToggle mode="dropdown" />
    </div>

    <div
      class="glass-strong w-full max-w-md rounded-xl p-6 shadow-2xl sm:rounded-2xl sm:p-8 md:rounded-3xl md:p-10"
    >
      <div class="mb-6 text-center sm:mb-8">
        <!-- 使用自定义布局来保持登录页面的居中大logo样式 -->
        <div
          class="mx-auto mb-4 flex h-16 w-16 items-center justify-center overflow-hidden rounded-xl border border-gray-300/30 bg-gradient-to-br from-blue-500/20 to-purple-500/20 backdrop-blur-sm sm:mb-6 sm:h-20 sm:w-20 sm:rounded-2xl"
        >
          <template v-if="!oemLoading">
            <img
              v-if="authStore.oemSettings.siteIconData || authStore.oemSettings.siteIcon"
              alt="Logo"
              class="h-10 w-10 object-contain sm:h-12 sm:w-12"
              :src="authStore.oemSettings.siteIconData || authStore.oemSettings.siteIcon"
              @error="(e) => (e.target.style.display = 'none')"
            />
            <i v-else class="fas fa-cloud text-2xl text-gray-700 sm:text-3xl" />
          </template>
          <div v-else class="h-10 w-10 animate-pulse rounded bg-gray-300/50 sm:h-12 sm:w-12" />
        </div>
        <template v-if="!oemLoading && authStore.oemSettings.siteName">
          <h1 class="header-title mb-2 text-2xl font-bold text-white sm:text-3xl">
            {{ authStore.oemSettings.siteName }}
          </h1>
        </template>
        <div
          v-else-if="oemLoading"
          class="mx-auto mb-2 h-8 w-48 animate-pulse rounded bg-gray-300/50 sm:h-9 sm:w-64"
        />
        <p class="text-base text-gray-600 dark:text-gray-400 sm:text-lg">
          {{ isUserMode ? '用户控制台' : '管理后台' }}
        </p>
        <div
          class="mt-4 grid grid-cols-2 rounded-xl border border-gray-300/30 bg-white/30 p-1 text-sm dark:bg-gray-800/30"
        >
          <button
            :class="[
              'rounded-lg px-3 py-2 font-medium transition-colors',
              !isUserMode
                ? 'bg-white text-blue-700 shadow dark:bg-gray-700 dark:text-blue-300'
                : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200'
            ]"
            type="button"
            @click="switchLoginMode('admin')"
          >
            管理员
          </button>
          <button
            :class="[
              'rounded-lg px-3 py-2 font-medium transition-colors',
              isUserMode
                ? 'bg-white text-blue-700 shadow dark:bg-gray-700 dark:text-blue-300'
                : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200'
            ]"
            type="button"
            @click="switchLoginMode('user')"
          >
            普通用户
          </button>
        </div>
      </div>

      <form class="space-y-4 sm:space-y-6" @submit.prevent="handleLogin">
        <div>
          <label
            class="mb-2 block text-sm font-semibold text-gray-900 dark:text-gray-100 sm:mb-3"
            for="username"
            >{{ isUserMode ? '普通用户用户名' : '管理员用户名' }}</label
          >
          <input
            id="username"
            v-model="loginForm.username"
            autocomplete="username"
            class="form-input w-full"
            name="username"
            :placeholder="isUserMode ? '请输入普通用户用户名' : '请输入管理员用户名'"
            required
            type="text"
          />
        </div>

        <div>
          <label
            class="mb-2 block text-sm font-semibold text-gray-900 dark:text-gray-100 sm:mb-3"
            for="password"
            >密码</label
          >
          <input
            id="password"
            v-model="loginForm.password"
            autocomplete="current-password"
            class="form-input w-full"
            name="password"
            placeholder="请输入密码"
            required
            type="password"
          />
        </div>

        <button
          class="btn btn-primary w-full px-4 py-3 text-base font-semibold sm:px-6 sm:py-4 sm:text-lg"
          :disabled="loginLoading"
          type="submit"
        >
          <i v-if="!loginLoading" class="fas fa-sign-in-alt mr-2" />
          <div v-if="loginLoading" class="loading-spinner mr-2" />
          {{
            loginLoading ? '登录中...' : isUserMode ? '普通用户登录 / 首次自动注册' : '管理员登录'
          }}
        </button>
      </form>

      <div
        v-if="loginError"
        class="mt-4 rounded-lg border border-red-500/30 bg-red-500/20 p-3 text-center text-xs text-red-800 backdrop-blur-sm dark:text-red-400 sm:mt-6 sm:rounded-xl sm:p-4 sm:text-sm"
      >
        <i class="fas fa-exclamation-triangle mr-2" />{{ loginError }}
      </div>

      <div
        v-if="isUserMode"
        class="mt-4 text-center text-xs text-gray-600 dark:text-gray-400 sm:text-sm"
      >
        首次使用时输入用户名和密码即可自动创建普通用户。
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useUserStore } from '@/stores/user'
import { useThemeStore } from '@/stores/theme'
import ThemeToggle from '@/components/common/ThemeToggle.vue'

const authStore = useAuthStore()
const userStore = useUserStore()
const themeStore = useThemeStore()
const route = useRoute()
const router = useRouter()
const oemLoading = computed(() => authStore.oemLoading)
const userLoginError = ref('')

const loginForm = ref({
  username: '',
  password: ''
})

const isUserMode = computed(() => route.path === '/user-login' || route.query.mode === 'user')
const loginLoading = computed(() => (isUserMode.value ? userStore.loading : authStore.loginLoading))
const loginError = computed(() => (isUserMode.value ? userLoginError.value : authStore.loginError))

onMounted(() => {
  // 初始化主题
  themeStore.initTheme()
  // 加载OEM设置
  authStore.loadOemSettings()
})

watch(
  () => isUserMode.value,
  () => {
    userLoginError.value = ''
    authStore.loginError = ''
  }
)

const switchLoginMode = (mode) => {
  userLoginError.value = ''
  authStore.loginError = ''
  router.replace(mode === 'user' ? '/user-login' : '/login')
}

const handleLogin = async () => {
  userLoginError.value = ''
  authStore.loginError = ''

  if (isUserMode.value) {
    try {
      await userStore.login(loginForm.value)
      await router.push('/dashboard')
    } catch (error) {
      userLoginError.value =
        error.response?.data?.message || error.message || '登录失败，请检查用户名和密码'
    }
    return
  }

  await authStore.login(loginForm.value)
}
</script>
