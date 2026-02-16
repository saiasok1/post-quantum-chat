# 🔧 Extension Troubleshooting Guide

## 🚨 Common Errors & Fixes

### 1. **Service Worker Registration Failed**

**Error**: "Service worker registration failed"

**Causes & Solutions**:

#### **A. Background Script Syntax Error**
```bash
# Check Chrome Developer Tools
1. Go to chrome://extensions/
2. Find "PQC Chat Search Extension"
3. Click "Errors" button
4. Look for JavaScript syntax errors
```

**Fix**: Use the simplified background script:
1. Rename `background.js` to `background-original.js`
2. Rename `background-simple.js` to `background.js`
3. Reload extension

#### **B. Manifest V3 Compatibility**
**Fix**: Ensure manifest.json has correct format:
```json
{
  "manifest_version": 3,
  "background": {
    "service_worker": "background.js"
  }
}
```

### 2. **Context Menu Creation Error**

**Error**: "Uncaught TypeError in creating context menu"

**Causes & Solutions**:

#### **A. Missing Permissions**
**Fix**: Add to manifest.json:
```json
{
  "permissions": [
    "contextMenus"
  ]
}
```

#### **B. Context Menu API Not Available**
**Fix**: The simplified background script handles this gracefully.

### 3. **Extension Won't Load**

**Symptoms**: Extension appears grayed out or shows errors

**Solutions**:

#### **A. Check File Structure**
Ensure you have all required files:
```
chrome-extension/
├── manifest.json
├── background.js (or background-simple.js renamed)
├── popup.html
├── popup.css
├── popup.js
├── content.js
├── content.css
└── icons/ (optional)
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

#### **B. Check Manifest Syntax**
- Use JSON validator to check manifest.json
- Ensure no trailing commas
- Ensure proper quotes and brackets

#### **C. Check Chrome Version**
- Requires Chrome 88+ for Manifest V3
- Update Chrome if needed

## 🛠️ Quick Fixes

### **Fix 1: Use Simplified Background Script**
```bash
# In chrome-extension folder
mv background.js background-original.js
mv background-simple.js background.js
# Reload extension in Chrome
```

### **Fix 2: Minimal Manifest (No Icons)**
Update manifest.json to remove icon references:
```json
{
  "manifest_version": 3,
  "name": "PQC Chat Search Extension",
  "version": "1.0.0",
  "description": "Secure post-quantum chat with integrated internet search capabilities",
  "permissions": [
    "activeTab",
    "storage",
    "tabs"
  ],
  "host_permissions": [
    "http://localhost:5000/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "action": {
    "default_popup": "popup.html",
    "default_title": "PQC Chat Search"
  },
  "content_scripts": [
    {
      "matches": ["http://localhost:5000/*"],
      "js": ["content.js"],
      "css": ["content.css"]
    }
  ]
}
```

### **Fix 3: Debug Mode**
1. Open Chrome DevTools for extension:
   - Go to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "background page" or "service worker" link
   - Check console for errors

2. Debug popup:
   - Right-click extension icon
   - Select "Inspect popup"
   - Check console for errors

## 🔍 Step-by-Step Debugging

### **Step 1: Basic Loading**
1. Go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select chrome-extension folder
5. Check for immediate errors

### **Step 2: Background Script**
1. Look for "Service worker" link in extension details
2. Click it to open DevTools
3. Check console for errors
4. If errors, use background-simple.js

### **Step 3: Popup Testing**
1. Click extension icon
2. If popup doesn't open, right-click icon → "Inspect popup"
3. Check console for JavaScript errors
4. Test basic functionality

### **Step 4: Content Script**
1. Open `http://localhost:5000`
2. Open DevTools (F12)
3. Check console for content script errors
4. Look for "PQC Extension: Content script initialized"

### **Step 5: Permissions**
1. Check that extension has access to localhost:5000
2. Verify in extension details page
3. Grant permissions if prompted

## 🚀 Working Configuration

If all else fails, use this minimal working setup:

### **manifest.json** (minimal):
```json
{
  "manifest_version": 3,
  "name": "PQC Chat Search Extension",
  "version": "1.0.0",
  "permissions": ["activeTab", "storage"],
  "host_permissions": ["http://localhost:5000/*"],
  "background": {
    "service_worker": "background-simple.js"
  },
  "action": {
    "default_popup": "popup.html"
  },
  "content_scripts": [
    {
      "matches": ["http://localhost:5000/*"],
      "js": ["content.js"]
    }
  ]
}
```

### **Test Steps**:
1. Use background-simple.js as background.js
2. Load extension with minimal manifest
3. Test popup opens
4. Test basic search functionality
5. Add features back gradually

## 📞 Still Having Issues?

1. **Check Chrome Console**: Look for specific error messages
2. **Try Incognito Mode**: Test if extensions work in incognito
3. **Restart Chrome**: Sometimes helps with service worker issues
4. **Clear Extension Data**: Remove and re-add extension
5. **Check Permissions**: Ensure localhost access is granted

The simplified background script should resolve most service worker and context menu issues!