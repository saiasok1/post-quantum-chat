class PQCChatExtensionBackground {
  constructor() {
    this.chatTabs = new Set();
    this.init();
  }

  init() {
    this.setupMessageListeners();
    this.setupTabListeners();
    this.setupContextMenus();
  }

  setupMessageListeners() {
    // Listen for messages from popup and content scripts
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async responses
    });
  }

  setupTabListeners() {
    // Track chat tabs
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (tab.url && tab.url.includes('localhost:5000')) {
        this.chatTabs.add(tabId);
        this.notifyConnectionStatus(true);
      }
    });

    chrome.tabs.onRemoved.addListener((tabId) => {
      if (this.chatTabs.has(tabId)) {
        this.chatTabs.delete(tabId);
        if (this.chatTabs.size === 0) {
          this.notifyConnectionStatus(false);
        }
      }
    });

    // Check existing tabs on startup
    this.checkExistingTabs();
  }

  async checkExistingTabs() {
    try {
      const tabs = await chrome.tabs.query({ url: 'http://localhost:5000/*' });
      tabs.forEach(tab => {
        if (tab.id) {
          this.chatTabs.add(tab.id);
        }
      });
      this.notifyConnectionStatus(this.chatTabs.size > 0);
    } catch (error) {
      console.error('Failed to check existing tabs:', error);
    }
  }

  setupContextMenus() {
    try {
      // Remove existing context menus first
      chrome.contextMenus.removeAll(() => {
        // Create context menu for selected text
        chrome.contextMenus.create({
          id: 'searchSelectedText',
          title: 'Search with PQC Chat Extension',
          contexts: ['selection']
        }, () => {
          if (chrome.runtime.lastError) {
            console.error('Context menu creation error:', chrome.runtime.lastError);
          }
        });
      });

      chrome.contextMenus.onClicked.addListener((info, tab) => {
        if (info.menuItemId === 'searchSelectedText' && info.selectionText) {
          this.performContextSearch(info.selectionText);
        }
      });
    } catch (error) {
      console.error('Context menu setup error:', error);
    }
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.action) {
        case 'sendToChat':
          await this.sendMessageToChat(message.data);
          sendResponse({ success: true });
          break;

        case 'performSearch':
          const results = await this.performSearch(message.query, message.engine);
          sendResponse({ success: true, results });
          break;

        case 'getConnectionStatus':
          sendResponse({ connected: this.chatTabs.size > 0 });
          break;

        case 'openChat':
          await this.openChatTab();
          sendResponse({ success: true });
          break;

        default:
          sendResponse({ success: false, error: 'Unknown action' });
      }
    } catch (error) {
      console.error('Background script error:', error);
      sendResponse({ success: false, error: error.message });
    }
  }

  async sendMessageToChat(data) {
    if (this.chatTabs.size === 0) {
      throw new Error('No chat tabs open');
    }

    // Send message to all open chat tabs
    for (const tabId of this.chatTabs) {
      try {
        await chrome.tabs.sendMessage(tabId, {
          action: 'injectSearchResults',
          data: data
        });
      } catch (error) {
        console.error(`Failed to send message to tab ${tabId}:`, error);
        // Remove invalid tab
        this.chatTabs.delete(tabId);
      }
    }

    // Update connection status if no valid tabs remain
    if (this.chatTabs.size === 0) {
      this.notifyConnectionStatus(false);
    }
  }

  async performSearch(query, engine = 'duckduckgo') {
    try {
      if (engine === 'google') {
        return await this.searchGoogle(query);
      } else {
        return await this.searchDuckDuckGo(query);
      }
    } catch (error) {
      console.error('Search failed:', error);
      throw error;
    }
  }

  async searchDuckDuckGo(query) {
    try {
      const response = await fetch(`https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&skip_disambig=1`);
      const data = await response.json();
      
      const results = [];
      
      // Add instant answer
      if (data.Abstract) {
        results.push({
          title: data.Heading || 'Instant Answer',
          url: data.AbstractURL || '#',
          snippet: data.Abstract
        });
      }
      
      // Add related topics
      if (data.RelatedTopics && data.RelatedTopics.length > 0) {
        data.RelatedTopics.slice(0, 9).forEach(topic => {
          if (topic.Text && topic.FirstURL) {
            results.push({
              title: topic.Text.split(' - ')[0] || 'Related Topic',
              url: topic.FirstURL,
              snippet: topic.Text
            });
          }
        });
      }
      
      return results;
    } catch (error) {
      console.error('DuckDuckGo search failed:', error);
      return [];
    }
  }

  async searchGoogle(query) {
    // This would require API keys stored in extension storage
    const { pqcChatSettings } = await chrome.storage.sync.get(['pqcChatSettings']);
    
    if (!pqcChatSettings?.googleApiKey || !pqcChatSettings?.searchEngineId) {
      throw new Error('Google API credentials not configured');
    }

    const url = `https://www.googleapis.com/customsearch/v1?key=${pqcChatSettings.googleApiKey}&cx=${pqcChatSettings.searchEngineId}&q=${encodeURIComponent(query)}&num=10`;
    
    const response = await fetch(url);
    const data = await response.json();
    
    if (data.error) {
      throw new Error(data.error.message);
    }
    
    return (data.items || []).map(item => ({
      title: item.title,
      url: item.link,
      snippet: item.snippet
    }));
  }

  async performContextSearch(selectedText) {
    try {
      // Store the selected text for when popup opens
      await chrome.storage.local.set({ 
        pendingSearch: selectedText,
        pendingSearchTimestamp: Date.now()
      });
      
      // Perform search directly and send to chat if available
      const results = await this.performSearch(selectedText, 'duckduckgo');
      
      if (results.length > 0 && this.chatTabs.size > 0) {
        // Format results for chat
        const formattedResults = this.formatResultsForChat(selectedText, results);
        
        // Send directly to chat
        await this.sendMessageToChat({
          message: formattedResults,
          type: 'search-results'
        });
        
        // Show notification
        this.showNotification(`Search results for "${selectedText}" sent to chat!`);
      } else {
        // Show notification to open extension manually
        this.showNotification(`Right-click extension icon to search for "${selectedText}"`);
      }
    } catch (error) {
      console.error('Context search failed:', error);
      this.showNotification('Context search failed. Please use extension popup.');
    }
  }

  formatResultsForChat(query, results) {
    let message = `🔍 **Search Results for: "${query}"**\n\n`;
    
    results.slice(0, 5).forEach((result, index) => {
      message += `**${index + 1}. ${result.title}**\n`;
      message += `🔗 ${result.url}\n`;
      message += `📝 ${result.snippet}\n\n`;
    });
    
    message += `_Search performed via PQC Chat Extension (Context Menu)_`;
    return message;
  }

  async showNotification(message) {
    try {
      await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'PQC Chat Extension',
        message: message
      });
    } catch (error) {
      // Notifications might not be available, ignore
      console.log('Notification not shown:', error.message);
    }
  }

  async openChatTab() {
    try {
      // Check if chat tab already exists
      const tabs = await chrome.tabs.query({ url: 'http://localhost:5000/*' });
      
      if (tabs.length > 0) {
        // Focus existing tab
        await chrome.tabs.update(tabs[0].id, { active: true });
        await chrome.windows.update(tabs[0].windowId, { focused: true });
      } else {
        // Create new tab
        const tab = await chrome.tabs.create({ url: 'http://localhost:5000' });
        this.chatTabs.add(tab.id);
        this.notifyConnectionStatus(true);
      }
    } catch (error) {
      console.error('Failed to open chat tab:', error);
      throw error;
    }
  }

  notifyConnectionStatus(connected) {
    // Notify popup about connection status change
    chrome.runtime.sendMessage({
      action: 'connectionStatusUpdate',
      connected: connected
    }).catch(() => {
      // Popup might not be open, ignore error
    });
  }

  // Periodic cleanup of invalid tabs
  async cleanupTabs() {
    const validTabs = new Set();
    
    for (const tabId of this.chatTabs) {
      try {
        const tab = await chrome.tabs.get(tabId);
        if (tab && tab.url && tab.url.includes('localhost:5000')) {
          validTabs.add(tabId);
        }
      } catch (error) {
        // Tab no longer exists
      }
    }
    
    this.chatTabs = validTabs;
    this.notifyConnectionStatus(this.chatTabs.size > 0);
  }
}

// Global instance
let pqcExtensionBackground;

// Initialize background script when service worker starts
chrome.runtime.onStartup.addListener(() => {
  console.log('PQC Extension: Service worker starting up');
  initializeExtension();
});

chrome.runtime.onInstalled.addListener((details) => {
  console.log('PQC Extension: Extension installed/updated');
  initializeExtension();
  
  if (details.reason === 'install') {
    console.log('PQC Chat Search Extension installed');
    // Open welcome page or chat
    chrome.tabs.create({ url: 'http://localhost:5000' }).catch(console.error);
  }
});

function initializeExtension() {
  try {
    pqcExtensionBackground = new PQCChatExtensionBackground();
    console.log('PQC Extension: Background script initialized');
  } catch (error) {
    console.error('PQC Extension: Failed to initialize background script:', error);
  }
}

// Periodic cleanup with error handling
function setupPeriodicCleanup() {
  setInterval(() => {
    if (pqcExtensionBackground) {
      try {
        pqcExtensionBackground.cleanupTabs();
      } catch (error) {
        console.error('PQC Extension: Cleanup error:', error);
      }
    }
  }, 30000); // Every 30 seconds
}

// Initialize immediately if service worker is already running
if (!pqcExtensionBackground) {
  initializeExtension();
}

setupPeriodicCleanup();