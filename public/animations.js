// Enhanced animations script
document.addEventListener('DOMContentLoaded', function() {
    // Trigger staggered animations
    animateStaggeredElements();
    
    // Handle smooth page transitions
    handlePageTransitions();
});

function animateStaggeredElements() {
    // Get all elements with stagger classes
    const staggerElements = document.querySelectorAll('[class*="stagger-"]');
    
    staggerElements.forEach((element, index) => {
        // Get the stagger delay from the class name (stagger-1, stagger-2, etc.)
        const classList = Array.from(element.classList);
        const staggerClass = classList.find(cls => cls.startsWith('stagger-'));
        
        if (staggerClass) {
            const delayValue = staggerClass.replace('stagger-', '');
            const delay = parseInt(delayValue) * 100; // Convert to milliseconds
            
            // Apply a slight delay for each element
            setTimeout(() => {
                element.style.opacity = '0';
                element.style.transform = 'translateY(20px)';
                element.style.transition = 'opacity 0.4s ease-out, transform 0.4s ease-out';
                
                // Trigger animation after a short delay
                setTimeout(() => {
                    element.style.opacity = '1';
                    element.style.transform = 'translateY(0)';
                }, 50);
            }, delay);
        }
    });
}

function handlePageTransitions() {
    // Add fade-in effect to the entire page on load
    const body = document.body;
    body.style.opacity = '0';
    body.style.transition = 'opacity 0.5s ease-out';
    
    // Fade in after DOM is loaded
    setTimeout(() => {
        body.style.opacity = '1';
    }, 100);
    
    // Add smooth transitions to interactive elements
    const interactiveElements = document.querySelectorAll('button, a, input, select, textarea');
    interactiveElements.forEach(element => {
        element.style.transition = 'all 0.2s ease';
    });
}

// Add ripple effect to buttons
function addRippleEffect() {
    const buttons = document.querySelectorAll('.btn, button, [role="button"]');
    
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            // Create ripple element
            const ripple = document.createElement('span');
            ripple.classList.add('ripple-effect');
            
            // Position ripple at click location
            const rect = button.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            // Style ripple
            ripple.style.width = ripple.style.height = size + 'px';
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';
            
            // Add to button
            if (button.style.position !== 'relative') {
                button.style.position = 'relative';
            }
            
            button.appendChild(ripple);
            
            // Remove ripple after animation
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
}

// Call ripple effect function when DOM is loaded
document.addEventListener('DOMContentLoaded', addRippleEffect);

// Enhanced scroll animations for long pages
function handleScrollAnimations() {
    const animatedElements = document.querySelectorAll('.animate-fade-in, .animate-slide-in-up, [class*="stagger-"]');
    
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    animatedElements.forEach(el => {
        // Initially hide elements
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.5s ease-out, transform 0.5s ease-out';
        
        // Observe for scroll
        observer.observe(el);
    });
}

// Initialize scroll animations if there are elements to animate
if (document.querySelectorAll('.animate-fade-in, .animate-slide-in-up, [class*="stagger-"]').length > 0) {
    document.addEventListener('DOMContentLoaded', handleScrollAnimations);
}

// Smooth scrolling for anchor links
document.addEventListener('click', function(e) {
    if (e.target.matches('a[href^="#"]')) {
        e.preventDefault();
        const targetId = e.target.getAttribute('href');
        const targetElement = document.querySelector(targetId);
        
        if (targetElement) {
            targetElement.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    }
});

// Enhanced focus management for accessibility
function enhanceFocus() {
    // Add focus indicators for keyboard navigation
    let isUsingKeyboard = false;
    
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Tab') {
            isUsingKeyboard = true;
        }
    });
    
    document.addEventListener('mousedown', () => {
        isUsingKeyboard = false;
    });
    
    const focusableElements = document.querySelectorAll('a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])');
    
    focusableElements.forEach(element => {
        element.addEventListener('focus', () => {
            if (isUsingKeyboard) {
                element.classList.add('keyboard-focused');
            }
        });
        
        element.addEventListener('blur', () => {
            element.classList.remove('keyboard-focused');
        });
    });
}

// Initialize focus enhancement
document.addEventListener('DOMContentLoaded', enhanceFocus);