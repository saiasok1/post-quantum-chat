# Post-Quantum Chat Application

## Project Overview

This is a full-stack, real-time chat application with a strong focus on security, implementing post-quantum cryptography (PQC) for end-to-end encryption. The project is built with TypeScript and structured as a monorepo with a `client`, `server`, and `shared` directory.

The design philosophy, detailed in `design_guidelines.md`, is inspired by Signal and Telegram, emphasizing security visibility, technical transparency, and a clean, modern user interface.

### Core Technologies

- **Frontend:** React, Vite, TypeScript, Tailwind CSS
- **Backend:** Node.js, Express, TypeScript, WebSockets (`ws`)
- **Database:** Neon (serverless Postgres) with Drizzle ORM
- **Cryptography:** `@noble/post-quantum` for PQC algorithms (Kyber/ML-KEM and Dilithium/ML-DSA).
- **UI Components:** `shadcn/ui` and Radix UI, following a detailed design system.
- **Schema Validation:** `zod` for type-safe data structures across the stack.
- **Authentication:** Passport.js with session management.

## Getting Started

### Prerequisites

- Node.js and npm

### Installation

Install the project dependencies from the root directory:

```bash
npm install
```

### Development

To run the application in development mode, use the following command. This will start the Express server with `tsx` for live reloading and use Vite to serve the frontend with hot module replacement.

```bash
npm run dev
```

The server will be available at `http://localhost:5000` (or the port specified in the `.env` file).

### Building for Production

To build the frontend and backend for production, run:

```bash
npm run build
```

This command executes two main steps:
1.  `vite build`: Compiles the React frontend into the `dist/public` directory.
2.  `esbuild`: Compiles the server-side TypeScript into the `dist` directory.

### Running in Production

After building the project, you can start the production server:

```bash
npm run start
```

This command runs the compiled server from `dist/index.js`.

### Database

The project uses Drizzle ORM. To push schema changes from `shared/schema.ts` to the Neon database, run:

```bash
npm run db:push
```

### Type Checking

To run the TypeScript compiler and check for type errors across the entire project, use:

```bash
npm run check
```

## Project Structure

- `client/`: Contains the React frontend application source code.
  - `src/pages/ChatPage.tsx`: The main chat interface component.
  - `src/components/`: Reusable React components.
  - `src/lib/pqc.ts`: Likely contains the client-side post-quantum cryptography logic.
- `server/`: Contains the Node.js/Express backend application source code.
  - `index.ts`: The main server entry point.
  - `routes.ts`: Defines the HTTP API and WebSocket handling.
- `shared/`: Contains code shared between the client and server.
  - `schema.ts`: Defines all data transfer objects (DTOs) and database schemas using `zod`.
- `dist/`: The output directory for production builds.
- `design_guidelines.md`: A comprehensive guide to the project's design system, component behavior, and visual identity.
- `drizzle.config.ts`: Configuration file for the Drizzle ORM.
- `vite.config.ts`: Configuration for the Vite build tool.

## Development Conventions

- **Styling:** The UI is built with Tailwind CSS and `shadcn/ui`. The visual identity (colors, typography, spacing) is strictly defined in `design_guidelines.md`.
- **State Management:** Client-side server state is managed by `@tanstack/react-query`.
- **Cryptography:** The core security feature is the implementation of post-quantum cryptography for key exchange (Kyber/ML-KEM) and digital signatures (Dilithium/ML-DSA). The WebSocket communication protocol defined in `shared/schema.ts` includes explicit types for `key-exchange`.
- **API:** The backend exposes both a RESTful HTTP API and a WebSocket endpoint for real-time communication. All data structures are validated with `zod` schemas from the `shared` directory.
