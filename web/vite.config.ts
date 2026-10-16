import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

// 仅回环开发服务器；生产由 Spring Boot 同源托管 web/dist，不存在 Node 生产 BFF。
// 代理白名单只含浏览器契约 /web-api；/v1/internal 等内部端点不向开发前端开放。
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  server: {
    host: '127.0.0.1',
    port: 19101,
    strictPort: true,
    proxy: {
      '/web-api': {
        target: 'http://127.0.0.1:19100',
        changeOrigin: false
      }
    }
  },
  preview: {
    host: '127.0.0.1',
    port: 19101,
    strictPort: true
  },
  build: {
    outDir: 'dist',
    sourcemap: false
  },
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.spec.ts']
  }
})
