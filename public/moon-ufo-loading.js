// Moon and UFO Loading Screen Controller - Enhanced Version
class MoonUFOLoading {
  constructor() {
    this.overlay = null;
    this.progressText = null;
    this.steps = [];
    this.currentStep = 0;
    this.init();
  }

  init() {
    this.createOverlay();
  }

  createOverlay() {
    // Create loading overlay
    this.overlay = document.createElement('div');
    this.overlay.className = 'loading-overlay';
    
    this.overlay.innerHTML = `
      <div class="moon-container">
        <div class="moon">
          <div class="crater crater-1"></div>
          <div class="crater crater-2"></div>
          <div class="crater crater-3"></div>
          <div class="crater crater-4"></div>
          <div class="crater crater-5"></div>
        </div>
        <div class="ufo">
          <div class="ufo-body"></div>
          <div class="ufo-light"></div>
        </div>
      </div>
      <div class="progress-text">Initializing...</div>
      <div class="progress-subtext">Please wait while we prepare your session</div>
      <div class="loading-steps">
        <div class="loading-step" data-step="1">
          <div class="step-icon">
            <i class="fas fa-circle-notch fa-spin"></i>
          </div>
          <span>Connecting to servers</span>
        </div>
        <div class="loading-step" data-step="2">
          <div class="step-icon">
            <i class="fas fa-circle-notch fa-spin"></i>
          </div>
          <span>Verifying credentials</span>
        </div>
        <div class="loading-step" data-step="3">
          <div class="step-icon">
            <i class="fas fa-circle-notch fa-spin"></i>
          </div>
          <span>Loading user data</span>
        </div>
        <div class="loading-step" data-step="4">
          <div class="step-icon">
            <i class="fas fa-circle-notch fa-spin"></i>
          </div>
          <span>Finalizing setup</span>
        </div>
      </div>
    `;
    
    document.body.appendChild(this.overlay);
    this.progressText = this.overlay.querySelector('.progress-text');
    this.progressSubtext = this.overlay.querySelector('.progress-subtext');
    this.steps = this.overlay.querySelectorAll('.loading-step');
  }

  show() {
    if (this.overlay) {
      this.overlay.classList.add('active');
      this.currentStep = 0;
      this.resetSteps();
    }
  }

  hide() {
    if (this.overlay) {
      this.overlay.classList.remove('active');
    }
  }

  resetSteps() {
    this.steps.forEach(step => {
      step.classList.remove('active', 'completed');
      const icon = step.querySelector('.step-icon');
      icon.classList.remove('active', 'completed');
      icon.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
    });
  }

  updateProgress(percent, message = '') {
    if (this.progressText) {
      this.progressText.textContent = `${Math.round(percent)}% ${message}`;
    }
    
    // Enhanced UFO movement - circular orbit around moon
    const ufo = this.overlay.querySelector('.ufo');
    const moonContainer = this.overlay.querySelector('.moon-container');
    
    if (ufo && moonContainer) {
      // Calculate angle based on progress (0-100% -> 0-360deg)
      const angle = (percent / 100) * 360 * (Math.PI / 180);
      const radius = 110; // Distance from moon center
      
      // Calculate position
      const x = Math.cos(angle - Math.PI / 2) * radius;
      const y = Math.sin(angle - Math.PI / 2) * radius;
      
      // Apply transform with smooth transition
      ufo.style.transition = 'transform 0.3s ease-out';
      ufo.style.transform = `translate(calc(-50% + ${x}px), ${y}px)`;
      
      // Tilt UFO based on movement direction
      const tilt = Math.cos(angle) * 5;
      const ufoBody = ufo.querySelector('.ufo-body');
      if (ufoBody) {
        ufoBody.style.transform = `translateX(-50%) rotate(${tilt}deg)`;
      }
    }
  }

  updateSubtext(text) {
    if (this.progressSubtext) {
      this.progressSubtext.textContent = text;
    }
  }

  updateStep(step, status = 'active') {
    if (step > this.currentStep) {
      this.currentStep = step;
    }

    const stepElement = this.overlay.querySelector(`[data-step="${step}"]`);
    if (stepElement) {
      const icon = stepElement.querySelector('.step-icon');
      
      // Remove all status classes
      stepElement.classList.remove('active', 'completed');
      icon.classList.remove('active', 'completed');
      
      if (status === 'completed') {
        stepElement.classList.add('completed');
        icon.classList.add('completed');
        icon.innerHTML = '<i class="fas fa-check"></i>';
      } else if (status === 'active') {
        stepElement.classList.add('active');
        icon.classList.add('active');
        icon.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
      } else if (status === 'error') {
        icon.innerHTML = '<i class="fas fa-exclamation"></i>';
      }
    }
  }

  simulateProgress() {
    let percent = 0;
    const interval = setInterval(() => {
      percent += Math.random() * 5;
      if (percent >= 100) {
        percent = 100;
        clearInterval(interval);
        this.updateProgress(percent, 'Complete!');
        this.updateSubtext('Setup finished. Redirecting...');
      } else {
        this.updateProgress(percent, 'Loading...');
        this.updateSubtext('Please wait while we prepare your session');
      }
      
      // Update steps based on progress
      if (percent >= 25) this.updateStep(1, 'completed');
      if (percent >= 30) this.updateStep(2, 'active');
      if (percent >= 50) this.updateStep(2, 'completed');
      if (percent >= 55) this.updateStep(3, 'active');
      if (percent >= 75) this.updateStep(3, 'completed');
      if (percent >= 80) this.updateStep(4, 'active');
      if (percent >= 100) this.updateStep(4, 'completed');
    }, 200);
  }
  
  // Method to show loading when verify button is clicked
  showOnVerifyClick(callback) {
    // Show loading screen immediately
    this.show();

    // Start progress simulation with smoother animation
    let percent = 0;
    const interval = setInterval(() => {
      // Smoother increment with easing
      const increment = percent < 50 ? 3 : percent < 80 ? 2 : 1.5;
      percent += increment;

      if (percent >= 100) {
        percent = 100;
        clearInterval(interval);
        this.updateProgress(percent, 'Complete!');
        this.updateSubtext('Verification complete. Redirecting...');

        // Call the callback immediately after animation completes
        setTimeout(() => {
          if (callback && typeof callback === 'function') {
            try {
              callback();
            } catch (error) {
              console.error('Error executing callback:', error);
              // Hide loading on error
              this.hide();
            }
          }
        }, 500); // Reduced delay for faster response
      } else {
        this.updateProgress(percent, 'Verifying...');

        // Dynamic subtext based on progress
        if (percent < 30) {
          this.updateSubtext('Establishing secure connection...');
        } else if (percent < 60) {
          this.updateSubtext('Authenticating credentials...');
        } else if (percent < 90) {
          this.updateSubtext('Loading your dashboard...');
        } else {
          this.updateSubtext('Almost ready...');
        }
      }

      // Update steps based on progress with smoother transitions
      if (percent >= 20) this.updateStep(1, 'active');
      if (percent >= 30) this.updateStep(1, 'completed');
      if (percent >= 35) this.updateStep(2, 'active');
      if (percent >= 55) this.updateStep(2, 'completed');
      if (percent >= 60) this.updateStep(3, 'active');
      if (percent >= 80) this.updateStep(3, 'completed');
      if (percent >= 85) this.updateStep(4, 'active');
      if (percent >= 100) this.updateStep(4, 'completed');
    }, 80);
  }

  // Add method to hide loading and reset
  hideLoading() {
    this.hide();
    this.resetSteps();
  }

  // Add method to show error state
  showError(message = 'Verification failed') {
    if (this.progressText) {
      this.progressText.textContent = 'Error!';
    }
    if (this.progressSubtext) {
      this.progressSubtext.textContent = message;
    }

    // Mark current step as error
    if (this.currentStep > 0) {
      this.updateStep(this.currentStep, 'error');
    }

    // Hide after delay
    setTimeout(() => {
      this.hideLoading();
    }, 3000);
  }
  
  // Demo method to show all features
  demo() {
    this.show();
    this.simulateProgress();
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.moonUFOLoading = new MoonUFOLoading();
  
  // Optional: Add demo button for testing
  if (window.location.search.includes('demo=true')) {
    setTimeout(() => {
      window.moonUFOLoading.demo();
    }, 1000);
  }
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MoonUFOLoading;
}