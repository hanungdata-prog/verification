// Theme Management System for AuthGateway
class ThemeManager {
    constructor() {
        this.currentTheme = 'dark';
        this.storageKey = 'authgateway-theme';
        this.init();
    }

    init() {
        // Load saved theme or detect system preference
        this.loadTheme();

        // Create and add theme toggle button
        this.createThemeToggle();

        // Add keyboard shortcut for theme toggle (Ctrl/Cmd + Shift + D)
        this.addKeyboardShortcut();

        // Listen for system theme changes
        this.addSystemThemeListener();

        // Add smooth transitions for theme changes
        this.addThemeTransitions();
    }

    loadTheme() {
        // Try to load saved theme from localStorage
        const savedTheme = localStorage.getItem(this.storageKey);

        if (savedTheme) {
            this.setTheme(savedTheme, false); // Don't save again to avoid infinite loop
        } else {
            // Detect system preference
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            this.setTheme(prefersDark ? 'dark' : 'light', false);
        }
    }

    setTheme(theme, save = true) {
        if (theme === this.currentTheme) return;

        const html = document.documentElement;
        const body = document.body;

        // Add transition class
        body.classList.add('theme-transition');

        // Update theme
        if (theme === 'dark') {
            html.classList.remove('light-theme');
            html.classList.add('dark-theme');
            this.updateThemeToggleIcon('moon');
        } else {
            html.classList.remove('dark-theme');
            html.classList.add('light-theme');
            this.updateThemeToggleIcon('sun');
        }

        this.currentTheme = theme;

        // Save preference
        if (save) {
            localStorage.setItem(this.storageKey, theme);
        }

        // Remove transition class after animation completes
        setTimeout(() => {
            body.classList.remove('theme-transition');
        }, 300);

        // Dispatch custom event for theme change
        this.dispatchThemeChangeEvent(theme);
    }

    toggleTheme() {
        const newTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);

        // Add haptic feedback for mobile (if supported)
        if ('vibrate' in navigator) {
            navigator.vibrate(50);
        }
    }

    createThemeToggle() {
        // Check if toggle already exists
        if (document.querySelector('.theme-toggle')) return;

        const toggle = document.createElement('button');
        toggle.className = 'theme-toggle';
        toggle.setAttribute('aria-label', 'Toggle dark mode');
        toggle.setAttribute('title', 'Toggle theme (Ctrl+Shift+D)');
        toggle.innerHTML = `<i class="fas fa-moon"></i>`;

        // Add click handler
        toggle.addEventListener('click', () => this.toggleTheme());

        // Add keyboard accessibility
        toggle.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.toggleTheme();
            }
        });

        // Add to page
        document.body.appendChild(toggle);

        // Set initial icon
        this.updateThemeToggleIcon(this.currentTheme === 'dark' ? 'moon' : 'sun');
    }

    updateThemeToggleIcon(icon) {
        const toggle = document.querySelector('.theme-toggle i');
        if (toggle) {
            toggle.className = icon === 'moon' ? 'fas fa-moon' : 'fas fa-sun';
        }
    }

    addKeyboardShortcut() {
        document.addEventListener('keydown', (e) => {
            // Ctrl+Shift+D or Cmd+Shift+D to toggle theme
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'D') {
                e.preventDefault();
                this.toggleTheme();
            }
        });
    }

    addSystemThemeListener() {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

        // Listen for system theme changes
        mediaQuery.addEventListener('change', (e) => {
            // Only change theme if user hasn't manually set one
            if (!localStorage.getItem(this.storageKey)) {
                this.setTheme(e.matches ? 'dark' : 'light', false);
            }
        });
    }

    addThemeTransitions() {
        // Add meta tag for theme color
        const metaThemeColor = document.createElement('meta');
        metaThemeColor.name = 'theme-color';
        metaThemeColor.content = this.getThemeColor();
        document.head.appendChild(metaThemeColor);

        // Update theme color when theme changes
        document.addEventListener('themechange', () => {
            metaThemeColor.content = this.getThemeColor();
        });
    }

    getThemeColor() {
        return this.currentTheme === 'dark' ? '#0d1117' : '#3b82f6';
    }

    dispatchThemeChangeEvent(theme) {
        const event = new CustomEvent('themechange', {
            detail: { theme }
        });
        document.dispatchEvent(event);
    }

    // Public method to get current theme
    getCurrentTheme() {
        return this.currentTheme;
    }

    // Public method to check if dark mode is active
    isDarkMode() {
        return this.currentTheme === 'dark';
    }

    // Public method to reset theme to system preference
    resetToSystemTheme() {
        localStorage.removeItem(this.storageKey);
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        this.setTheme(prefersDark ? 'dark' : 'light', false);
    }
}

// Initialize theme manager when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.themeManager = new ThemeManager();
});

// Also initialize immediately if DOM is already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.themeManager = new ThemeManager();
    });
} else {
    window.themeManager = new ThemeManager();
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThemeManager;
}