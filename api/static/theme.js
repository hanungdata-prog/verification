// Theme Management - Vercel Style
class ThemeManager {
    constructor() {
        this.storageKey = 'authgateway-theme';
        this.init();
    }

    init() {
        this.loadTheme();
        this.createToggle();
        this.addSystemListener();
    }

    loadTheme() {
        const saved = localStorage.getItem(this.storageKey);
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        this.setTheme(saved || (prefersDark ? 'dark' : 'light'));
    }

    setTheme(theme) {
        document.documentElement.classList.toggle('dark-theme', theme === 'dark');
        document.documentElement.classList.toggle('light-theme', theme === 'light');
        localStorage.setItem(this.storageKey, theme);
    }

    toggleTheme() {
        const isDark = document.documentElement.classList.contains('dark-theme');
        this.setTheme(isDark ? 'light' : 'dark');
    }

    createToggle() {
        if (document.querySelector('.theme-toggle')) return;
        const btn = document.createElement('button');
        btn.className = 'theme-toggle';
        btn.innerHTML = '<i class="fas fa-moon"></i>';
        btn.addEventListener('click', () => this.toggleTheme());
        document.body.appendChild(btn);
    }

    addSystemListener() {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
            if (!localStorage.getItem(this.storageKey)) {
                this.setTheme(e.matches ? 'dark' : 'light');
            }
        });
    }
}

document.addEventListener('DOMContentLoaded', () => new ThemeManager());