/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#070a13',
          900: '#0b0f19',
          850: '#0f172a',
          800: '#131e36',
          700: '#1e293b',
          600: '#334155',
        },
        soc: {
          benign: '#10b981',    // Emerald Green
          warning: '#f59e0b',   // Amber
          malicious: '#ef4444', // Red
          critical: '#dc2626',  // Deep Crimson
          neutral: '#3b82f6',   // Blue
          purple: '#8b5cf6',    // Indigo/Purple
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace']
      }
    },
  },
  plugins: [],
}
