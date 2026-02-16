# PQC Secure Chat Application

## Overview

A real-time chat application implementing post-quantum cryptography (PQC) for secure messaging. The system uses ML-KEM-768 for key encapsulation and ML-DSA-65 for digital signatures, providing quantum-resistant end-to-end encryption for text and image messages. Built as a peer-to-peer WebSocket-based chat with a modern, security-focused UI inspired by Signal and Telegram.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture

**Framework & Build System**
- React 18 with TypeScript for type safety
- Vite as the build tool and development server
- Wouter for lightweight client-side routing
- TanStack Query (React Query) for server state management

**UI Component System**
- Shadcn/ui component library with Radix UI primitives
- Tailwind CSS for styling with custom design tokens
- Dark mode by default with light mode support via ThemeProvider
- Design system follows security-focused aesthetics (see design_guidelines.md)
- Custom color palette emphasizing encryption status visibility

**Post-Quantum Cryptography**
- Uses @noble/post-quantum library for PQC operations
- ML-KEM-768 (Kyber) for key encapsulation mechanism
- ML-DSA-65 (Dilithium) for digital signatures
- Client-side encryption/decryption in `/client/src/lib/pqc.ts`
- Key pair generation and management handled entirely in browser

**State Management Pattern**
- Local state with React hooks for UI interactions
- WebSocket connection state managed in main ChatPage component
- Encryption keys stored in component state (ephemeral, not persisted)
- Message history maintained in local state array

### Backend Architecture

**Server Framework**
- Express.js for HTTP server and API routing
- Native Node.js HTTP server for WebSocket upgrade
- Development mode uses Vite middleware for HMR

**Real-Time Communication**
- WebSocket server using 'ws' library at `/ws` endpoint
- Peer-to-peer message relay pattern (server doesn't decrypt)
- Connection tracking with unique peer IDs per client
- Message types: connection, chat, key-exchange, peer-status

**Message Storage**
- In-memory storage implementation (MemStorage class)
- No persistent database by default
- Messages stored with UUID, timestamp, and encryption metadata
- Storage interface allows for future database implementations

**Image Handling**
- Multer for multipart form data processing
- Sharp for image optimization and resizing
- Images converted to base64 for WebSocket transmission
- Server acts as pass-through without decryption

### Data Architecture

**Schema Design**
- Zod schemas for runtime type validation
- Message schema: id, senderId, receiverId, content, type (text/image), encrypted flag, timestamp
- PQC key pair schema: publicKey, privateKey, algorithm, timestamp
- Peer schema: id, publicKey, status (online/offline/key-exchange), lastSeen
- WebSocket message discriminated union for type safety

**Data Flow**
1. Client generates ML-KEM and ML-DSA key pairs locally
2. Public keys exchanged via WebSocket
3. Shared secret derived using peer's public key
4. Messages encrypted client-side before transmission
5. Server relays encrypted messages without decryption
6. Receiving client decrypts using shared secret

### Security Model

**End-to-End Encryption**
- No server-side message decryption capability
- Quantum-resistant algorithms (NIST PQC standards)
- Key exchange happens once per session
- Encryption status visible in UI at all times

**Trust Model**
- Server-relayed but client-encrypted architecture
- No authentication system (peer-to-peer trust)
- Public key fingerprinting for manual verification
- Ephemeral keys (not persisted beyond session)

## External Dependencies

### Core Libraries
- **@noble/post-quantum**: NIST-approved PQC algorithms (ML-KEM, ML-DSA)
- **ws**: WebSocket server implementation
- **express**: HTTP server and routing
- **drizzle-orm**: SQL query builder (configured but not actively used)
- **@neondatabase/serverless**: Serverless Postgres driver (available for future use)

### UI & Styling
- **@radix-ui/react-***: Accessible component primitives (40+ components)
- **tailwindcss**: Utility-first CSS framework
- **class-variance-authority**: Type-safe variant management
- **lucide-react**: Icon library

### Development Tools
- **vite**: Frontend build tool with HMR
- **typescript**: Type system for JavaScript
- **drizzle-kit**: Database schema management CLI
- **esbuild**: Production server bundling

### Image Processing
- **multer**: File upload middleware
- **sharp**: High-performance image processing

### Database Configuration
- Configured for PostgreSQL via Drizzle ORM
- Connection string expected in DATABASE_URL environment variable
- Schema defined in `/shared/schema.ts`
- Migrations output to `/migrations` directory
- Currently using in-memory storage; database integration available when needed