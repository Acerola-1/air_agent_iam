import { describe, expect, it, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import LoginView from './LoginView.vue'
import { ApiError } from '@/api/http'

const loginMock = vi.fn()
const replaceMock = vi.fn()

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({
    login: loginMock,
    isAuthenticated: false,
    needsTenantSelection: false
  })
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ query: {} }),
  useRouter: () => ({ replace: replaceMock })
}))

// Element Plus 组件在 jsdom 下的轻量替身，聚焦状态/错误/提交流。
const ElForm = defineComponent({
  props: ['modelValue'],
  emits: ['submit'],
  setup(_, { slots, emit, expose }) {
    expose({ validate: async () => true })
    return () => h('form', { onSubmit: (e: Event) => { e.preventDefault(); emit('submit') } }, slots.default?.())
  }
})
const ElFormItem = defineComponent({
  setup(_, { slots }) {
    return () => h('label', slots.default?.())
  }
})
const ElInput = defineComponent({
  props: ['modelValue', 'type'],
  emits: ['update:modelValue'],
  setup(props, { emit }) {
    return () =>
      h('input', {
        value: props.modelValue,
        type: props.type === 'password' ? 'password' : 'text',
        onInput: (e: Event) => emit('update:modelValue', (e.target as HTMLInputElement).value)
      })
  }
})
const ElAlert = defineComponent({
  props: ['title'],
  setup(props) {
    return () => h('div', { 'data-testid': 'error' }, props.title)
  }
})

const global = {
  components: {
    'el-form': ElForm,
    'el-form-item': ElFormItem,
    'el-input': ElInput,
    'el-alert': ElAlert,
    'el-icon': defineComponent({ setup: (_, { slots }) => () => h('i', slots.default?.()) }),
    Loading: defineComponent({ setup: () => () => h('i') })
  }
}

async function fillAndSubmit(wrapper: ReturnType<typeof mount>): Promise<void> {
  const inputs = wrapper.findAll('input')
  ;(inputs[0].element as HTMLInputElement).value = 'alice'
  await inputs[0].trigger('input')
  ;(inputs[1].element as HTMLInputElement).value = 'correct-pass'
  await inputs[1].trigger('input')
  await wrapper.find('[data-testid="login-submit"]').trigger('click')
  wrapper.findComponent({ ref: 'formRef' }).vm.$emit('submit', { preventDefault() {} })
}

describe('LoginView', () => {
  beforeEach(() => {
    loginMock.mockReset()
    replaceMock.mockReset()
  })

  it('登录失败显示后端错误，不跳转、不显示成功', async () => {
    loginMock.mockRejectedValueOnce(new ApiError(401, 'invalid_credentials', '账号或密码错误', null))
    const wrapper = mount(LoginView, { global })
    await fillAndSubmit(wrapper)
    await flushPromises()
    expect(loginMock).toHaveBeenCalledWith('alice', 'correct-pass')
    expect(wrapper.find('[data-testid="login-error"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('账号或密码不正确')
    expect(replaceMock).not.toHaveBeenCalled()
  })

  it('登录成功跳转个人设置页', async () => {
    loginMock.mockResolvedValueOnce(undefined)
    const wrapper = mount(LoginView, { global })
    await fillAndSubmit(wrapper)
    await flushPromises()
    expect(replaceMock).toHaveBeenCalledWith('/profile')
    expect(wrapper.find('[data-testid="login-error"]').exists()).toBe(false)
  })

  it('503 依赖失败给出失败关闭提示', async () => {
    loginMock.mockRejectedValueOnce(new ApiError(503, 'dependency_unavailable', '依赖故障', null))
    const wrapper = mount(LoginView, { global })
    await fillAndSubmit(wrapper)
    await flushPromises()
    expect(wrapper.text()).toContain('身份依赖暂不可用')
  })
})
