# Quick Setup - No Icons Required

The extension has been updated to work without icons. Follow these steps:

## Method 1: Load Extension Without Icons (Fastest)

1. **Open Chrome Extensions**
   - Go to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top-right)

2. **Load Extension**
   - Click "Load unpacked"
   - Navigate to and select the `chrome-extension` folder
   - Extension should load successfully (may show default Chrome icon)

3. **Test Extension**
   - Look for "PQC Chat Search Extension" in your extensions list
   - Click the extension icon in toolbar (or extensions menu)
   - Extension popup should open

## Method 2: Create Icons (Optional, for better appearance)

1. **Open Icon Generator**
   - Open `chrome-extension/create-icons.html` in your browser
   - Click "Generate All Icons"
   - Click "Download All Icons"

2. **Install Icons**
   - Create folder: `chrome-extension/icons/`
   - Move downloaded PNG files to the icons folder
   - Reload extension in Chrome

3. **Update Manifest (if you added icons)**
   - Uncomment the icon sections in `manifest.json`
   - Reload extension

## Troubleshooting

### Extension Won't Load
- Check that `manifest.json` exists in the folder
- Ensure Chrome Developer mode is enabled
- Try reloading the extension page

### Missing Files Error
- Make sure all these files exist:
  - `manifest.json`
  - `popup.html`
  - `popup.css`
  - `popup.js`
  - `background.js`
  - `content.js`
  - `content.css`

### Permission Errors
- The extension needs access to `localhost:5000`
- Make sure your PQC chat is running on that port

## Test the Extension

1. **Start PQC Chat**
   ```bash
   npm run dev
   ```

2. **Open Chat in Browser**
   - Go to `http://localhost:5000`

3. **Test Extension**
   - Click extension icon in Chrome toolbar
   - Try searching for "test"
   - Check if "Connected" status shows in extension
   - Try "Send to Chat" button

## Next Steps

Once the extension loads successfully:
1. Test basic search functionality
2. Test chat integration
3. Configure settings if needed
4. Add icons later for better appearance

The extension should work perfectly without icons - they're just for visual appeal!