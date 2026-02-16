# PQC Chat Search Extension

A Chrome extension that integrates with the PQC Secure Chat application, providing internet search capabilities directly within the chat interface.

## Features

### 🔍 **Internet Search Integration**
- **DuckDuckGo Search** - Privacy-focused search without API keys
- **Google Custom Search** - Advanced search with API integration
- **Context Menu Search** - Right-click selected text to search
- **Auto-send Results** - Automatically send search results to chat

### 🔐 **PQC Chat Integration**
- **Real-time Connection** - Detects when chat is open
- **Secure Message Injection** - Sends search results to encrypted chat
- **Extension Indicator** - Shows when extension is active
- **Quick Chat Access** - One-click to open/focus chat tab

### ⚙️ **Customizable Settings**
- **Search Engine Selection** - Choose between DuckDuckGo and Google
- **API Configuration** - Set up Google Search API credentials
- **Result Limits** - Configure number of search results
- **Auto-send Toggle** - Enable/disable automatic result sending

## Installation

### 1. **Prepare the Extension**
```bash
# Navigate to the chrome-extension directory
cd chrome-extension

# Create icon files (see icons/create-icons.md for instructions)
# You need: icon16.png, icon32.png, icon48.png, icon128.png
```

### 2. **Load in Chrome**
1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" (top-right toggle)
3. Click "Load unpacked"
4. Select the `chrome-extension` folder
5. The extension should appear in your extensions list

### 3. **Pin the Extension**
1. Click the extensions icon (puzzle piece) in Chrome toolbar
2. Find "PQC Chat Search Extension"
3. Click the pin icon to keep it visible

## Setup

### 1. **Start PQC Chat Server**
```bash
# In your main project directory
npm run dev
```
The chat should be running at `http://localhost:5000`

### 2. **Configure Search APIs (Optional)**

#### **DuckDuckGo (Default)**
- No setup required
- Privacy-focused
- Limited results but no API keys needed

#### **Google Custom Search**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable "Custom Search API"
4. Create credentials (API Key)
5. Set up [Custom Search Engine](https://cse.google.com/)
6. Get your Search Engine ID
7. Enter both in extension settings

## Usage

### 1. **Basic Search**
1. Click the extension icon in Chrome toolbar
2. Enter your search query
3. Click search or press Enter
4. View results in the extension popup

### 2. **Send to Chat**
1. Perform a search
2. Click "Send to Chat" button
3. Results will be formatted and sent to your PQC chat
4. Switch to chat tab to see the results

### 3. **Context Menu Search**
1. Select any text on a webpage
2. Right-click and choose "Search with PQC Chat Extension"
3. Extension popup opens with pre-filled search
4. Results can be sent directly to chat

### 4. **Auto-send Mode**
1. Open extension settings (gear icon)
2. Enable "Auto-send results to chat"
3. All future searches will automatically send results to chat

## Extension Structure

```
chrome-extension/
├── manifest.json          # Extension configuration
├── popup.html             # Main extension interface
├── popup.css              # Extension styling
├── popup.js               # Extension logic
├── background.js          # Background service worker
├── content.js             # Chat page integration
├── content.css            # Content script styles
├── icons/                 # Extension icons
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
└── README.md              # This file
```

## API Integration

### **DuckDuckGo Instant Answer API**
- **Endpoint**: `https://api.duckduckgo.com/`
- **No Authentication Required**
- **Rate Limits**: Reasonable use policy
- **Results**: Instant answers and related topics

### **Google Custom Search API**
- **Endpoint**: `https://www.googleapis.com/customsearch/v1`
- **Authentication**: API Key required
- **Rate Limits**: 100 queries/day (free tier)
- **Results**: Comprehensive web search results

## Security Features

### **Post-Quantum Cryptography Integration**
- Extension respects PQC chat encryption
- Search results sent through encrypted channels
- No sensitive data stored in extension
- Privacy-focused search options available

### **Permissions**
- `activeTab` - Access current tab for context menu
- `storage` - Save extension settings
- `background` - Run background service worker
- `webRequest` - Monitor chat connection status

### **Data Privacy**
- Settings stored locally in Chrome
- No data sent to external servers (except search APIs)
- DuckDuckGo search provides privacy protection
- Google search only if explicitly configured

## Troubleshooting

### **Extension Not Loading**
1. Check Chrome version (requires Manifest V3 support)
2. Ensure all files are present in extension directory
3. Check for JavaScript errors in `chrome://extensions/`
4. Reload extension after making changes

### **Chat Connection Issues**
1. Ensure PQC chat is running at `http://localhost:5000`
2. Check that chat tab is open and active
3. Refresh chat page if connection indicator shows offline
4. Check browser console for WebSocket errors

### **Search Not Working**
1. Verify internet connection
2. For Google search, check API key and Search Engine ID
3. Check API quotas and rate limits
4. Try switching to DuckDuckGo search

### **Results Not Sending to Chat**
1. Ensure chat tab is open and focused
2. Check that message input field is available
3. Verify extension has permission to access localhost
4. Check content script injection in developer tools

## Development

### **Testing**
1. Load extension in developer mode
2. Open developer tools for extension popup
3. Check background script logs in `chrome://extensions/`
4. Use content script debugging in chat page

### **Customization**
- Modify `popup.css` for styling changes
- Update `popup.js` for functionality changes
- Extend `background.js` for new features
- Enhance `content.js` for better chat integration

## Contributing

1. Fork the repository
2. Create feature branch
3. Test thoroughly with PQC chat
4. Submit pull request with detailed description

## License

This extension is part of the PQC Secure Chat project and follows the same licensing terms.