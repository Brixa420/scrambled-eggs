import { createGlobalStyle } from 'styled-components';

export const GlobalStyles = createGlobalStyle`
  :root {
    /* Light theme */
    --color-primary: #4a36d6;
    --color-primary-dark: #3a2bb5;
    --color-primary-light: #6d5dfc;
    --color-secondary: #6c757d;
    --color-success: #28a745;
    --color-danger: #dc3545;
    --color-warning: #ffc107;
    --color-info: #17a2b8;
    --color-light: #f8f9fa;
    --color-dark: #343a40;
    
    --color-bg: #ffffff;
    --color-bg-secondary: #f8f9fa;
    --color-text: #212529;
    --color-text-secondary: #6c757d;
    --color-border: #dee2e6;
    
    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
    --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    
    --radius-sm: 0.25rem;
    --radius: 0.375rem;
    --radius-md: 0.5rem;
    --radius-lg: 0.75rem;
    --radius-full: 9999px;
    
    --transition: all 0.2s ease-in-out;
  }
  
  [data-theme='dark'] {
    --color-bg: #1a1a2e;
    --color-bg-secondary: #2d2d42;
    --color-text: #e6e6e6;
    --color-text-secondary: #a0a0c0;
    --color-border: #3a3a4a;
  }
  
  *,
  *::before,
  *::after {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }
  
  html {
    font-size: 16px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    scroll-behavior: smooth;
  }
  
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', sans-serif;
    background-color: var(--color-bg);
    color: var(--color-text);
    transition: background-color 0.2s, color 0.2s;
  }
  
  h1, h2, h3, h4, h5, h6 {
    font-weight: 600;
    line-height: 1.2;
    margin-bottom: 0.5em;
    color: var(--color-text);
  }
  
  h1 { font-size: 2.5rem; }
  h2 { font-size: 2rem; }
  h3 { font-size: 1.75rem; }
  h4 { font-size: 1.5rem; }
  h5 { font-size: 1.25rem; }
  h6 { font-size: 1rem; }
  
  p {
    margin-bottom: 1rem;
  }
  
  a {
    color: var(--color-primary);
    text-decoration: none;
    transition: var(--transition);
    
    &:hover {
      color: var(--color-primary-dark);
      text-decoration: underline;
    }
  }
  
  button, 
  input, 
  select, 
  textarea {
    font-family: inherit;
    font-size: 1rem;
  }
  
  button {
    cursor: pointer;
    background: none;
    border: none;
    outline: none;
  }
  
  img {
    max-width: 100%;
    height: auto;
  }
  
  /* Custom scrollbar */
  ::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }
  
  ::-webkit-scrollbar-track {
    background: var(--color-bg-secondary);
  }
  
  ::-webkit-scrollbar-thumb {
    background: var(--color-primary);
    border-radius: var(--radius-full);
    
    &:hover {
      background: var(--color-primary-dark);
    }
  }
  
  /* Animations */
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  
  @keyframes slideUp {
    from { 
      opacity: 0;
      transform: translateY(20px);
    }
    to { 
      opacity: 1;
      transform: translateY(0);
    }
  }
  
  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
  
  /* Utility classes */
  .container {
    width: 100%;
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 1rem;
  }
  
  .flex {
    display: flex;
  }
  
  .items-center {
    align-items: center;
  }
  
  .justify-between {
    justify-content: space-between;
  }
  
  .gap-2 {
    gap: 0.5rem;
  }
  
  .gap-4 {
    gap: 1rem;
  }
  
  .mt-4 {
    margin-top: 1rem;
  }
  
  .mb-4 {
    margin-bottom: 1rem;
  }
  
  .p-4 {
    padding: 1rem;
  }
  
  .text-center {
    text-align: center;
  }
  
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
  }
`;
