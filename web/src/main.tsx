import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'

import { App } from './app/app'
import { AppProviders } from './app/providers'
import './index.css'

const root = document.getElementById('root')
if (!root) throw new Error('未找到 #root 挂载节点')

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <AppProviders>
        <App />
      </AppProviders>
    </BrowserRouter>
  </StrictMode>,
)
