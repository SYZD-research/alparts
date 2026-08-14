import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        discord: {
          bg: '#313338',
          sidebar: '#2b2d31',
          input: '#383a40',
          hover: '#404249',
          active: '#4e505899',
          text: '#dbdee1',
          muted: '#949ba4',
          accent: '#5865f2',
          'accent-hover': '#4752c4',
          green: '#23a559',
          red: '#ed4245',
          yellow: '#f0b232',
          channel: '#80848e',
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
