class PQCChatContentScript {
  constructor() {
    this.isInjected = false;
    this.init();
  }

  init() {
    // Wait for page to load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.setup());
    } else {
      this.setup();
    }
  }

  setup() {
    this.setupMessageListener();
    this.injectExtensionIndicator();
    this.notifyExtensionPresence();
  }

  setupMessageListener() {
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true;
    });
  }

  handleMessage(message, sender, sendResponse) {
    switch (message.action) {
      case 'injectSearchResults':
        this.injectSearchResults(message.data);
        sendResponse({ success: true });
        break;

      case 'getPageInfo':
        sendResponse({
          success: true,
          info: this.getPageInfo()
        });
        break;

      case 'highlightText':
        this.highlightText(message.text);
        sendResponse({ success: true });
        break;

      default:
        sendResponse({ success: false, error: 'Unknown action' });
    }
  }

  injectSearchResults(data) {
    try {
      // Find the message input area
      const messageInput = this.findMessageInput();
      
      if (messageInput) {
        // Insert the search results into the chat
        this.insertMessageIntoChat(data.message);
        this.showNotification('Search results added to chat!');
      } else {
        console.error('Could not find message input');
        this.showNotification('Could not find chat input', 'error');
      }
    } catch (error) {
      console.error('Failed to inject search results:', error);
      this.showNotification('Failed to add search results', 'error');
    }
  }

  findMessageInput() {
    // Try multiple selectors to find the message input
    const selectors = [
      'textarea[placeholder*="message"]',
      'input[placeholder*="message"]',
      'textarea[data-testid*="message"]',
      'input[data-testid*="message"]',
      '.message-input textarea',
      '.message-input input',
      '#messageInput',
      '[data-testid="message-input"]'
    ];

    for (const selector of selectors) {
      const element = document.querySelector(selector);
      if (element) {
        return element;
      }
    }

    return null;
  }

  insertMessageIntoChat(message) {
    const messageInput = this.findMessageInput();
    
    if (messageInput) {
      // Set the value
      messageInput.value = message;
      
      // Trigger input events to notify React
      const inputEvent = new Event('input', { bubbles: true });
      const changeEvent = new Event('change', { bubbles: true });
      
      messageInput.dispatchEvent(inputEvent);
      messageInput.dispatchEvent(changeEvent);
      
      // Focus the input
      messageInput.focus();
      
      // Try to find and click send button
      setTimeout(() => {
        this.clickSendButton();
      }, 100);
    }
  }

  clickSendButton() {
    const sendSelectors = [
      'button[type="submit"]',
      'button[data-testid*="send"]',
      '.send-button',
      'button:has(svg[data-testid*="send"])',
      'button:has(svg[viewBox*="24"])', // Common send icon viewBox
      'form button[type="button"]:last-child'
    ];

    for (const selector of sendSelectors) {
      const button = document.querySelector(selector);
      if (button && !button.disabled) {
        button.click();
        return true;
      }
    }

    return false;
  }

  injectExtensionIndicator() {
    if (this.isInjected) return;

    // Create extension indicator
    const indicator = document.createElement('div');
    indicator.id = 'pqc-extension-indicator';
    indicator.innerHTML = `
      <div style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: rgba(16, 185, 129, 0.9);
        color: white;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-family: system-ui, sans-serif;
        z-index: 10000;
        display: flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(10px);
        transition: opacity 0.3s ease;
      ">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
          <path d="M2 17L12 22L22 17" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
          <path d="M2 12L12 17L22 12" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
        </svg>
        PQC Search Extension Active
      </div>
    `;

    document.body.appendChild(indicator);
    this.isInjected = true;

    // Auto-hide after 3 seconds
    setTimeout(() => {
      const element = document.getElementById('pqc-extension-indicator');
      if (element) {
        element.style.opacity = '0';
        setTimeout(() => element.remove(), 300);
      }
    }, 3000);
  }

  notifyExtensionPresence() {
    // Notify background script that extension is active on this page
    chrome.runtime.sendMessage({
      action: 'extensionActive',
      url: window.location.href
    }).catch(() => {
      // Background script might not be ready
    });
  }

  getPageInfo() {
    return {
      url: window.location.href,
      title: document.title,
      hasMessageInput: !!this.findMessageInput(),
      isChat: window.location.href.includes('localhost:5000')
    };
  }

  highlightText(text) {
    // Simple text highlighting
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    const textNodes = [];
    let node;

    while (node = walker.nextNode()) {
      if (node.textContent.toLowerCase().includes(text.toLowerCase())) {
        textNodes.push(node);
      }
    }

    textNodes.forEach(textNode => {
      const parent = textNode.parentNode;
      const content = textNode.textContent;
      const regex = new RegExp(`(${text})`, 'gi');
      const highlightedContent = content.replace(regex, '<mark style="background: #fbbf24; color: #000;">$1</mark>');
      
      if (highlightedContent !== content) {
        const wrapper = document.createElement('span');
        wrapper.innerHTML = highlightedContent;
        parent.replaceChild(wrapper, textNode);
      }
    });
  }

  showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 80px;
      right: 20px;
      background: ${type === 'error' ? '#ef4444' : '#10b981'};
      color: white;
      padding: 12px 16px;
      border-radius: 6px;
      font-size: 14px;
      font-family: system-ui, sans-serif;
      z-index: 10001;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      backdrop-filter: blur(10px);
      max-width: 300px;
      word-wrap: break-word;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.opacity = '0';
      notification.style.transform = 'translateX(100%)';
      notification.style.transition = 'all 0.3s ease';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }
}

// Initialize content script with error handling
let pqcContentScript;
try {
  pqcContentScript = new PQCChatContentScript();
  console.log('PQC Extension: Content script initialized');
} catch (error) {
  console.error('PQC Extension: Content script initialization failed:', error);
}

// Handle dynamic content changes
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    if (mutation.type === 'childList') {
      // Re-check for message input if DOM changes significantly
      const messageInput = pqcContentScript.findMessageInput();
      if (messageInput && !messageInput.dataset.pqcExtensionReady) {
        messageInput.dataset.pqcExtensionReady = 'true';
        console.log('PQC Extension: Message input detected');
      }
    }
  });
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  observer.disconnect();
});