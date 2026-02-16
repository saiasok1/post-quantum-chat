# Project Structure

## Root Directory Organization
```
├── client/          # React frontend application
├── server/          # Express.js backend
├── shared/          # Shared types and schemas
├── .kiro/           # Kiro IDE configuration
├── node_modules/    # Dependencies
└── dist/            # Production build output
```

## Client Structure (`client/`)
- `index.html` - Main HTML template with fonts and meta tags
- `src/` - React application source code
  - Uses `@/` path alias for imports
  - Tailwind CSS for styling
  - shadcn/ui component library

## Server Structure (`server/`)
- `index.ts` - Main Express server with middleware setup
- `routes.ts` - API route definitions
- `storage.ts` - Database operations and queries
- `vite.ts` - Development server integration

## Shared Structure (`shared/`)
- `schema.ts` - Zod schemas for type validation
  - Message types (text/image)
  - PQC key pair definitions
  - WebSocket message schemas
  - Peer/user types

## Configuration Files
- `package.json` - Dependencies and npm scripts
- `tsconfig.json` - TypeScript configuration with path aliases
- `vite.config.ts` - Frontend build configuration
- `drizzle.config.ts` - Database ORM configuration
- `tailwind.config.ts` - Styling framework setup
- `components.json` - shadcn/ui component configuration

## Key Conventions
- **Import Aliases**: Use `@/` for client code, `@shared/` for shared types
- **File Extensions**: `.ts` for server, `.tsx` for React components
- **Schema Validation**: All data structures defined in `shared/schema.ts`
- **Environment**: Configuration via `.env` file (not committed)
- **Build Output**: Client builds to `dist/public/`, server to `dist/`