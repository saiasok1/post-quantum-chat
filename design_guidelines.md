# Design Guidelines: Post-Quantum Cryptography Chat Application

## Design Approach
**Reference-Based Approach** drawing inspiration from Signal's security-focused design, Telegram's clean messaging UI, and Linear's modern developer aesthetics. The design emphasizes trust, clarity, and technical precision while maintaining an approachable interface for secure communication.

## Core Design Principles
1. **Security Visibility**: Encryption status and PQC indicators are always prominent
2. **Technical Transparency**: Complex cryptographic operations presented clearly
3. **Trust Through Design**: Professional aesthetic that instills confidence
4. **Efficient Communication**: Minimal friction for sending encrypted messages

## Color Palette

### Dark Mode (Primary)
- **Background**: 220 15% 8% (deep blue-black)
- **Surface**: 220 12% 12% (elevated panels)
- **Surface Elevated**: 220 10% 16% (chat bubbles, cards)
- **Primary**: 210 100% 60% (encrypted status, CTAs)
- **Success**: 142 76% 45% (active encryption, verified)
- **Warning**: 38 92% 50% (key generation, pending)
- **Accent**: 170 80% 50% (quantum-safe indicators, highlights)
- **Text Primary**: 0 0% 95%
- **Text Secondary**: 220 10% 65%
- **Border**: 220 12% 20%

### Light Mode
- **Background**: 0 0% 98%
- **Surface**: 0 0% 100%
- **Surface Elevated**: 220 20% 98%
- **Primary**: 210 100% 50%
- **Success**: 142 76% 40%
- **Warning**: 38 92% 45%
- **Accent**: 170 70% 45%
- **Text Primary**: 220 15% 10%
- **Text Secondary**: 220 10% 40%

## Typography
- **Font Families**: 
  - Display/Headers: 'Inter', system-ui, sans-serif (600-700 weight)
  - Body/Messages: 'Inter', system-ui, sans-serif (400-500 weight)
  - Technical/Monospace: 'JetBrains Mono', monospace (cryptographic keys, hashes)
- **Scale**: 12px (meta), 14px (body), 16px (messages), 20px (headers), 28px (page titles)

## Layout System
**Spacing Primitives**: Use Tailwind units of 2, 3, 4, 6, 8, 12 for consistent rhythm
- Micro spacing: p-2, gap-2 (UI elements)
- Component spacing: p-4, gap-4 (cards, sections)
- Section spacing: p-6, p-8 (major containers)
- Page margins: p-12 (outer containers)

## Component Library

### Core UI Elements

**Chat Message Bubbles**
- Own messages: Aligned right, primary color background, white text
- Received messages: Aligned left, surface elevated background, text primary
- Border radius: rounded-2xl (sent), rounded-bl-sm (received - chat tail effect)
- Padding: p-3 (text), p-2 (images with caption below)
- Max width: max-w-md for text, max-w-lg for images
- Timestamp: text-xs, text-secondary, mt-1

**Encryption Status Indicators**
- Badge component showing "PQC Encrypted" with shield icon
- Kyber/Dilithium algorithm pills (text-xs, rounded-full, px-2 py-1)
- Color-coded: success green for active encryption, warning amber for key exchange
- Position: Fixed at top of chat header, inline with conversation title

**Key Exchange Panel**
- Card component (surface elevated, rounded-lg, p-6)
- Step indicator showing: Generate → Exchange → Verify
- Visual fingerprint display (monospace, grid of colored blocks based on key hash)
- Copy buttons for public key sharing
- Progress animations for key generation (subtle pulse, no spinners)

**Image Preview/Upload**
- Thumbnail grid for image selection (grid-cols-3, gap-2)
- Full-size preview modal with encryption confirmation
- Encrypted indicator overlay on sent images (lock icon, subtle)
- Image messages: rounded-xl, max-h-96, object-cover

### Navigation

**Top Bar**
- Fixed header: backdrop-blur-lg, bg-background/90
- Left: Connection status (online/offline pill with pulse animation)
- Center: Conversation partner name + PQC verification badge
- Right: Settings icon, encryption details button
- Height: h-16, border-b with border color

**Side Panel** (Key Management - toggleable)
- Width: w-80, slide-in from right
- Contains: Active keys, algorithm info, regenerate options
- Collapsible sections for technical details
- Monospace display for key fingerprints

### Forms & Inputs

**Message Input**
- Sticky bottom: fixed bottom-0, backdrop-blur-lg
- Textarea with auto-resize, min-h-12, max-h-32
- Rounded-2xl, surface elevated background
- Right side: Image upload icon, Send button (primary)
- Padding: p-4, gap-3

**File Upload**
- Drag-and-drop zone: border-2 border-dashed, rounded-lg
- Hover state: border-primary, bg-primary/5
- File type indicator icons (image format badges)

### Data Display

**Connection Status Panel**
- Card showing: WebSocket status, peer ID, connection quality
- Real-time latency display (ms, with color coding)
- PQC algorithm in use (Kyber-768, Dilithium-2)
- Last key rotation timestamp

**Message History**
- Virtualized scroll for performance (infinite scroll pattern)
- Date separators: sticky, text-sm, text-secondary, centered
- Grouped messages (same sender within 2min): reduced spacing
- Encryption status per message (inline badge, subtle)

### Overlays & Modals

**Settings Modal**
- Centered overlay: max-w-2xl, rounded-2xl
- Tabbed interface: Security, Appearance, Advanced
- Algorithm selection (Kyber/Dilithium variants)
- Dark/Light mode toggle with system preference option
- Key rotation frequency settings

**Encryption Details Popover**
- Technical readout: algorithm versions, key sizes, rotation status
- Certificate chain visualization (if applicable)
- Session security score (visual meter)

## Visual Enhancements

**Quantum-Safe Visual Identity**
- Subtle particle/network effect in header background (CSS-based, minimal)
- Encryption lock icon: gradient from primary to accent
- Hexagonal patterns for technical sections (borders, backgrounds)
- Glow effects on active encryption states (box-shadow with primary color)

**Trust Indicators**
- Verified checkmark for confirmed PQC keys (accent color)
- Fingerprint comparison UI (side-by-side color grids)
- Security level meter (high/medium indicators)

## Responsive Behavior
- Desktop (lg): Side panel visible, full message width
- Tablet (md): Collapsible side panel, adjusted message max-width
- Mobile: Stack layout, bottom sheet for key details, simplified header

## Images
No hero images required. This is a utility-focused application.

**UI Icons**: Use Heroicons for all interface elements (shield, lock, check-circle, arrow-path, photo, paper-airplane)

**Placeholder Images**: For image message demos, use gradient placeholders with lock overlay icon to indicate encryption