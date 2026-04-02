/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: '#0f172a',
        darker: '#020617',
        primary: {
          DEFAULT: '#3b82f6',
          glow: 'rgba(59, 130, 246, 0.5)',
        },
        danger: {
          DEFAULT: '#ef4444',
          glow: 'rgba(239, 68, 68, 0.5)',
        },
        success: {
          DEFAULT: '#10b981',
          glow: 'rgba(16, 185, 129, 0.5)',
        },
        warning: {
          DEFAULT: '#f59e0b',
          glow: 'rgba(245, 158, 11, 0.5)',
        },
      },
      backgroundImage: {
        'glass-gradient': 'linear-gradient(135deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0.05))',
      },
    },
  },
  plugins: [],
}
