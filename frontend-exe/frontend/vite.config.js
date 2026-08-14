import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    host: '0.0.0.0',
    allowedHosts: [
      'redeye.desaivraj.site',
    ],
    port: 5173,
    strictPort: true
  }
})
