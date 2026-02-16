class PQCChatSearchExtension {
  constructor() {
    this.searchResults = [];
    this.isConnected = false;
    this.settings = {
      googleApiKey: '',
      searchEngineId: '',
      maxResults: 10,
      autoSendToChat: false
    };
    
    this.init();
  }

  async init() {
    await this.loadSettings();
    await this.checkPendingSearch();
    this.setupEventListeners();
    this.checkChatConnection();
    this.updateUI();
  }

  async checkPendingSearch() {
    try {
      const result = await chrome.storage.local.get(['pendingSearch', 'pendingSearchTimestamp']);
      
      if (result.pendingSearch && result.pendingSearchTimestamp) {
        // Check if the pending search is recent (within 30 seconds)
        const now = Date.now();
        const timeDiff = now - result.pendingSearchTimestamp;
        
        if (timeDiff < 30000) { // 30 seconds
          // Fill the search input with pending search
          setTimeout(() => {
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {
              searchInput.value = result.pendingSearch;
              searchInput.focus();
              searchInput.select();
            }
          }, 100);
          
          // Clear the pending search
          await chrome.storage.local.remove(['pendingSearch', 'pendingSearchTimestamp']);
        }
      }
    } catch (error) {
      console.error('Failed to check pending search:', error);
    }
  }

  setupEventListeners() {
    // Search functionality
    document.getElementById('searchBtn').addEventListener('click', () => this.performSearch());
    document.getElementById('searchInput').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.performSearch();
    });

    // Settings
    document.getElementById('settingsBtn').addEventListener('click', () => this.showSettings());
    document.getElementById('closeSettings').addEventListener('click', () => this.hideSettings());
    document.getElementById('saveSettings').addEventListener('click', () => this.saveSettings());

    // Chat integration
    document.getElementById('sendToChat').addEventListener('click', () => this.sendResultsToChat());
    document.getElementById('openChatBtn').addEventListener('click', () => this.openChat());
    document.getElementById('clearResults').addEventListener('click', () => this.clearResults());

    // Auto-focus search input
    document.getElementById('searchInput').focus();
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.sync.get(['pqcChatSettings']);
      if (result.pqcChatSettings) {
        this.settings = { ...this.settings, ...result.pqcChatSettings };
        this.populateSettingsForm();
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }

  async saveSettings() {
    try {
      // Get values from form
      this.settings.googleApiKey = document.getElementById('googleApiKey').value;
      this.settings.searchEngineId = document.getElementById('searchEngineId').value;
      this.settings.maxResults = parseInt(document.getElementById('maxResults').value);
      this.settings.autoSendToChat = document.getElementById('autoSendToChat').checked;

      // Save to storage
      await chrome.storage.sync.set({ pqcChatSettings: this.settings });
      
      this.hideSettings();
      this.showNotification('Settings saved successfully!');
    } catch (error) {
      console.error('Failed to save settings:', error);
      this.showNotification('Failed to save settings', 'error');
    }
  }

  populateSettingsForm() {
    document.getElementById('googleApiKey').value = this.settings.googleApiKey || '';
    document.getElementById('searchEngineId').value = this.settings.searchEngineId || '';
    document.getElementById('maxResults').value = this.settings.maxResults || 10;
    document.getElementById('autoSendToChat').checked = this.settings.autoSendToChat || false;
  }

  async performSearch() {
    const query = document.getElementById('searchInput').value.trim();
    if (!query) return;

    const searchEngine = document.getElementById('searchEngine').value;
    
    this.showLoading();
    
    try {
      let results;
      if (searchEngine === 'google') {
        results = await this.searchGoogle(query);
      } else {
        results = await this.searchDuckDuckGo(query);
      }
      
      this.searchResults = results;
      this.displayResults(results);
      
      if (this.settings.autoSendToChat && results.length > 0) {
        await this.sendResultsToChat();
      }
    } catch (error) {
      console.error('Search failed:', error);
      this.showError('Search failed. Please try again.');
    }
  }

  async searchDuckDuckGo(query) {
    try {
      // Use DuckDuckGo Instant Answer API
      const response = await fetch(`https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&skip_disambig=1`);
      const data = await response.json();
      
      const results = [];
      
      // Add instant answer if available
      if (data.Abstract) {
        results.push({
          title: data.Heading || 'Instant Answer',
          url: data.AbstractURL || '#',
          snippet: data.Abstract
        });
      }
      
      // Add related topics
      if (data.RelatedTopics && data.RelatedTopics.length > 0) {
        data.RelatedTopics.slice(0, this.settings.maxResults - 1).forEach(topic => {
          if (topic.Text && topic.FirstURL) {
            results.push({
              title: topic.Text.split(' - ')[0] || 'Related Topic',
              url: topic.FirstURL,
              snippet: topic.Text
            });
          }
        });
      }
      
      // If no results from DuckDuckGo API, create a fallback search result
      if (results.length === 0) {
        results.push({
          title: `Search results for: ${query}`,
          url: `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
          snippet: `Click to view search results for "${query}" on DuckDuckGo`
        });
      }
      
      return results;
    } catch (error) {
      console.error('DuckDuckGo search failed:', error);
      // Fallback result
      return [{
        title: `Search: ${query}`,
        url: `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
        snippet: `Search for "${query}" on DuckDuckGo`
      }];
    }
  }

  async searchGoogle(query) {
    if (!this.settings.googleApiKey || !this.settings.searchEngineId) {
      throw new Error('Google API key and Search Engine ID are required');
    }

    const url = `https://www.googleapis.com/customsearch/v1?key=${this.settings.googleApiKey}&cx=${this.settings.searchEngineId}&q=${encodeURIComponent(query)}&num=${this.settings.maxResults}`;
    
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

  displayResults(results) {
    const container = document.getElementById('resultsContainer');
    const searchResults = document.getElementById('searchResults');
    const loadingState = document.getElementById('loadingState');
    
    loadingState.classList.add('hidden');
    
    if (results.length === 0) {
      container.innerHTML = '<div class="no-results">No results found</div>';
      searchResults.classList.remove('hidden');
      return;
    }
    
    container.innerHTML = results.map(result => `
      <div class="search-result">
        <div class="result-title">${this.escapeHtml(result.title)}</div>
        <div class="result-url">${this.escapeHtml(result.url)}</div>
        <div class="result-snippet">${this.escapeHtml(result.snippet)}</div>
      </div>
    `).join('');
    
    searchResults.classList.remove('hidden');
  }

  showLoading() {
    document.getElementById('loadingState').classList.remove('hidden');
    document.getElementById('searchResults').classList.add('hidden');
  }

  showError(message) {
    document.getElementById('loadingState').classList.add('hidden');
    document.getElementById('searchResults').classList.add('hidden');
    this.showNotification(message, 'error');
  }

  async sendResultsToChat() {
    if (this.searchResults.length === 0) {
      this.showNotification('No results to send', 'error');
      return;
    }

    try {
      // Format results for chat
      const query = document.getElementById('searchInput').value.trim();
      const formattedResults = this.formatResultsForChat(query, this.searchResults);
      
      // Send to background script to communicate with chat
      await chrome.runtime.sendMessage({
        action: 'sendToChat',
        data: {
          message: formattedResults,
          type: 'search-results'
        }
      });
      
      this.showNotification('Results sent to chat!');
    } catch (error) {
      console.error('Failed to send to chat:', error);
      this.showNotification('Failed to send to chat', 'error');
    }
  }

  formatResultsForChat(query, results) {
    let message = `🔍 **Search Results for: "${query}"**\n\n`;
    
    results.slice(0, 5).forEach((result, index) => {
      message += `**${index + 1}. ${result.title}**\n`;
      message += `🔗 ${result.url}\n`;
      message += `📝 ${result.snippet}\n\n`;
    });
    
    message += `_Search performed via PQC Chat Extension_`;
    return message;
  }

  async checkChatConnection() {
    try {
      // Check if chat tab is open
      const tabs = await chrome.tabs.query({ url: 'http://localhost:5000/*' });
      this.isConnected = tabs.length > 0;
      this.updateConnectionStatus();
    } catch (error) {
      console.error('Failed to check chat connection:', error);
      this.isConnected = false;
      this.updateConnectionStatus();
    }
  }

  updateConnectionStatus() {
    const statusElement = document.getElementById('connectionStatus');
    const statusDot = statusElement.querySelector('.status-dot');
    const statusText = statusElement.querySelector('span');
    
    if (this.isConnected) {
      statusDot.classList.remove('offline');
      statusDot.classList.add('online');
      statusText.textContent = 'Connected';
    } else {
      statusDot.classList.remove('online');
      statusDot.classList.add('offline');
      statusText.textContent = 'Disconnected';
    }
  }

  async openChat() {
    try {
      // Check if chat is already open
      const tabs = await chrome.tabs.query({ url: 'http://localhost:5000/*' });
      
      if (tabs.length > 0) {
        // Focus existing tab
        await chrome.tabs.update(tabs[0].id, { active: true });
        await chrome.windows.update(tabs[0].windowId, { focused: true });
      } else {
        // Open new tab
        await chrome.tabs.create({ url: 'http://localhost:5000' });
      }
      
      // Close extension popup
      window.close();
    } catch (error) {
      console.error('Failed to open chat:', error);
      this.showNotification('Failed to open chat', 'error');
    }
  }

  clearResults() {
    this.searchResults = [];
    document.getElementById('searchResults').classList.add('hidden');
    document.getElementById('searchInput').value = '';
    document.getElementById('searchInput').focus();
  }

  showSettings() {
    document.getElementById('settingsPanel').classList.remove('hidden');
  }

  hideSettings() {
    document.getElementById('settingsPanel').classList.add('hidden');
  }

  updateUI() {
    // Update encryption badge based on connection
    const encryptionBadge = document.getElementById('encryptionBadge');
    if (this.isConnected) {
      encryptionBadge.style.opacity = '1';
    } else {
      encryptionBadge.style.opacity = '0.5';
    }
  }

  showNotification(message, type = 'success') {
    // Create a simple notification system
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      right: 10px;
      padding: 10px 15px;
      border-radius: 4px;
      color: white;
      font-size: 12px;
      z-index: 10000;
      background: ${type === 'error' ? '#ef4444' : '#10b981'};
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.remove();
    }, 3000);
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize the extension when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  try {
    window.pqcExtension = new PQCChatSearchExtension();
  } catch (error) {
    console.error('Failed to initialize PQC extension:', error);
  }
});

// Listen for connection status updates
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  try {
    if (message.action === 'connectionStatusUpdate') {
      // Update connection status in popup
      const extension = window.pqcExtension;
      if (extension) {
        extension.isConnected = message.connected;
        extension.updateConnectionStatus();
        extension.updateUI();
      }
    } else if (message.action === 'fillSearchInput') {
      // Fill search input with selected text
      const searchInput = document.getElementById('searchInput');
      if (searchInput && message.text) {
        searchInput.value = message.text;
        searchInput.focus();
      }
    }
    sendResponse({ success: true });
  } catch (error) {
    console.error('Popup message handler error:', error);
    sendResponse({ success: false, error: error.message });
  }
  return true;
});