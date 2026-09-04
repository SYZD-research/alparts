import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { DesktopBoundary } from './components/desktop/DesktopBoundary';
import './styles/globals.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <DesktopBoundary>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </DesktopBoundary>
  </React.StrictMode>,
);
