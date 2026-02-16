# Quick Installation Guide

## 1. Create Extension Icons

First, create the required icon files. You can use simple placeholder icons for testing:

### Option A: Create Simple Icons (Quick)
Create 4 PNG files with solid colors:
- `icons/icon16.png` - 16x16 blue square
- `icons/icon32.png` - 32x32 blue square  
- `icons/icon48.png` - 48x48 blue square
- `icons/icon128.png` - 128x128 blue square

### Option B: Download Icons (Recommended)
1. Go to https://heroicons.com/
2. Search for "shield" or "lock"
3. Download as PNG in required sizes
4. Save in the `icons/` folder

## 2. Install Extension

1. **Open Chrome Extensions**
   - Go to `chrome://extensions/`
   - Enable "Developer mode" (top-right toggle)

2. **Load Extension**
   - Click "Load unpacked"
   - Select the `chrome-extension` folder
   - Extension should appear in your list

3. **Pin Extension**
   - Click extensions icon (puzzle piece) in toolbar
   - Find "PQC Chat Search Extension"
   - Click pin icon to keep visible

## 3. Test Extension

1. **Start PQC Chat**
   ```bash
   npm run dev
   ```

2. **Open Chat**
   - Go to `http://localhost:5000`
   - Generate keys and test messaging

3. **Test Extension**
   - Click extension icon in Chrome toolbar
   - Try searching for something
   - Click "Send to Chat" to test integration

## 4. Configure (Optional)

1. **Open Extension Settings**
   - Click gear icon in extension popup
   
2. **For Google Search (Optional)**
   - Get API key from Google Cloud Console
   - Set up Custom Search Engine
   - Enter credentials in settings

3. **Adjust Preferences**
   - Set max results
   - Enable auto-send if desired
   - Save settings

## Troubleshooting

- **Extension won't load**: Check that all files exist, especially icons
- **Can't connect to chat**: Make sure chat is running on localhost:5000
- **Search not working**: Try DuckDuckGo first (no setup required)
- **Results not sending**: Ensure chat tab is open and active

## Quick Test Commands

```bash
# Start the chat server
npm run dev

# In another terminal, check if server is running
curl http://localhost:5000

# Open Chrome and test extension
# 1. Load extension
# 2. Open localhost:5000
# 3. Click extension icon
# 4. Search for "test"
# 5. Click "Send to Chat"
```