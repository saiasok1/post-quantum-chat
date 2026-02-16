// Simplified background script for debugging
console.log('PQC Extension: Background script loading...');

// Simple message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Background received message:', message);
  
  try {
    switch (message.action) {
      case 'sendToChat':
        handleSendToChat(message.data).then(result => {
          sendResponse({ success: true, result });
        }).catch(error => {
          sendResponse({ success: false, error: error.message });
        });
        break;
        
      case 'getConnectionStatus':
        checkChatConnection().then(connected => {
          sendResponse({ connected });
        });
        break;
        
      case 'openChat':
        openChatTab().then(() => {
          sendResponse({ success: true });
        }).catch(error => {
          sendResponse({ success: false, error: error.message });
        });
        break;
        
      default:
        sendResponse({ success: false, error: 'Unknown action' });
    }
  } catch (error) {
    console.error('Background message handler error:', error);
    sendResponse({ success: false, error: error.message });
  }
  
  return true; // Keep message channel open
});

// Simple chat connection check
async function checkChatConnection() {
  try {
    const tabs = await chrome.tabs.query({ url: 'http://localhost:5000/*' });
    return tabs.length > 0;
  } catch (error) {
    console.error('Failed to check chat connection:', error);
    return false;
  }
}

// Simple send to chat function
async function handleSendToChat(data) {
  try {
    const tabs = await chrome.tabs.query({ url: 'http://localhost:5000/*' });
    
    if (tabs.length === 0) {
      throw new Error('No chat tabs open');
    }
    
    // Send to first chat tab
    await chrome.tabs.sendMessage(tabs[0].id, {
      action: 'injectSearchResults',
      data: data
    });
    
    return 'Message sent successfully';
  } catch (error) {
    console.error('Failed to send to chat:', error);
    throw error;
  }
}

// Simple open chat function
async function openChatTab() {
  try {
    const tabs = await chrome.tabs.query({ url: 'http://localhost:5000/*' });
    
    if (tabs.length > 0) {
      // Focus existing tab
      await chrome.tabs.update(tabs[0].id, { active: true });
      await chrome.windows.update(tabs[0].windowId, { focused: true });
    } else {
      // Create new tab
      await chrome.tabs.create({ url: 'http://localhost:5000' });
    }
  } catch (error) {
    console.error('Failed to open chat:', error);
    throw error;
  }
}

// Simple context menu setup (optional)
chrome.runtime.onInstalled.addListener(() => {
  console.log('PQC Extension: Extension installed');
  
  try {
    chrome.contextMenus.create({
      id: 'searchSelectedText',
      title: 'Search with PQC Chat Extension',
      contexts: ['selection']
    }, () => {
      if (chrome.runtime.lastError) {
        console.log('Context menu creation skipped:', chrome.runtime.lastError.message);
      } else {
        console.log('Context menu created successfully');
      }
    });
  } catch (error) {
    console.log('Context menu setup skipped due to error:', error);
  }
});

// Context menu click handler
chrome.contextMenus?.onClicked?.addListener((info, tab) => {
  if (info.menuItemId === 'searchSelectedText' && info.selectionText) {
    console.log('Context menu clicked with text:', info.selectionText);
    // Could open popup with pre-filled search here
  }
});

console.log('PQC Extension: Background script loaded successfully');