# Technology Stack

## Core Technologies
- **Runtime**: Node.js with TypeScript (ES modules)
- **Frontend**: React 18 with Vite build system
- **Backend**: Express.js server
- **Database**: PostgreSQL with Drizzle ORM
- **Real-time**: WebSocket connections
- **Styling**: Tailwind CSS with shadcn/ui components

## Key Libraries & Frameworks
- **UI Components**: Radix UI primitives with shadcn/ui
- **State Management**: TanStack Query for server state
- **Routing**: Wouter for client-side routing
- **Forms**: React Hook Form with Zod validation
- **Animations**: Framer Motion
- **Icons**: Lucide React
- **Cryptography**: @noble/post-quantum for PQC algorithms
- **File Uploads**: Multer for image handling

## Development Tools
- **Build**: Vite for frontend, esbuild for server bundling
- **Type Checking**: TypeScript with strict mode
- **Database**: Drizzle Kit for migrations
- **Environment**: cross-env for cross-platform scripts

## Common Commands

### Development
```bash
npm run dev          # Start development server with hot reload
npm run check        # TypeScript type checking
npm run db:push      # Push database schema changes
```

### Production
```bash
npm run build        # Build both client and server
npm start           # Start production server
```

## Architecture Notes
- Monorepo structure with shared types between client/server
- Path aliases: `@/*` for client, `@shared/*` for shared types
- Environment variables loaded from `.env` file
- Database connection via Neon serverless PostgreSQL