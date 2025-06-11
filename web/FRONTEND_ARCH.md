# 🏗️ Frank Auth - Complete Project Structure with UI Dashboard

```
frank/
├── cmd/                              # Backend commands
│   ├── server/                       # Main server (API + Frontend serving)
│   │   ├── main.go
│   │   └── wire.go
│   ├── migrate/
│   │   └── main.go
│   └── cli/
│       └── main.go
│
├── web/                             # 🎨 Frontend Dashboard (Next.js)
│   ├── apps/
│   │   ├── dashboard/               # Main admin dashboard
│   │   │   ├── src/
│   │   │   │   ├── app/             # Next.js 14 App Router
│   │   │   │   │   ├── (auth)/      # Auth layout group
│   │   │   │   │   │   ├── login/
│   │   │   │   │   │   ├── signup/
│   │   │   │   │   │   ├── mfa/
│   │   │   │   │   │   └── sso/
│   │   │   │   │   ├── (internal)/  # Internal users (Platform Staff)
│   │   │   │   │   │   ├── admin/
│   │   │   │   │   │   │   ├── organizations/
│   │   │   │   │   │   │   ├── users/
│   │   │   │   │   │   │   ├── billing/
│   │   │   │   │   │   │   ├── compliance/
│   │   │   │   │   │   │   └── system-logs/
│   │   │   │   │   │   └── analytics/
│   │   │   │   │   ├── (external)/  # External users (Customer Orgs)
│   │   │   │   │   │   ├── org/
│   │   │   │   │   │   │   ├── [orgId]/
│   │   │   │   │   │   │   │   ├── dashboard/
│   │   │   │   │   │   │   │   ├── users/        # End user management
│   │   │   │   │   │   │   │   ├── auth-config/  # OAuth, SAML setup
│   │   │   │   │   │   │   │   ├── api-keys/
│   │   │   │   │   │   │   │   ├── webhooks/
│   │   │   │   │   │   │   │   ├── audit-logs/
│   │   │   │   │   │   │   │   ├── members/      # Org member management
│   │   │   │   │   │   │   │   ├── roles/        # RBAC management
│   │   │   │   │   │   │   │   ├── sessions/
│   │   │   │   │   │   │   │   ├── security/     # MFA, Passkeys
│   │   │   │   │   │   │   │   └── settings/
│   │   │   │   │   │   │   └── billing/
│   │   │   │   │   │   └── onboarding/
│   │   │   │   │   ├── api/         # API routes (proxy to Go backend)
│   │   │   │   │   ├── globals.css
│   │   │   │   │   ├── layout.tsx
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── components/      # Reusable UI components
│   │   │   │   │   ├── ui/          # Base components (shadcn/ui)
│   │   │   │   │   │   ├── button.tsx
│   │   │   │   │   │   ├── input.tsx
│   │   │   │   │   │   ├── table.tsx
│   │   │   │   │   │   ├── dialog.tsx
│   │   │   │   │   │   ├── toast.tsx
│   │   │   │   │   │   └── ...
│   │   │   │   │   ├── auth/        # Auth-specific components
│   │   │   │   │   │   ├── login-form.tsx
│   │   │   │   │   │   ├── mfa-setup.tsx
│   │   │   │   │   │   ├── passkey-setup.tsx
│   │   │   │   │   │   ├── oauth-buttons.tsx
│   │   │   │   │   │   └── session-manager.tsx
│   │   │   │   │   ├── dashboard/   # Dashboard-specific components
│   │   │   │   │   │   ├── sidebar.tsx
│   │   │   │   │   │   ├── header.tsx
│   │   │   │   │   │   ├── stats-cards.tsx
│   │   │   │   │   │   ├── user-table.tsx
│   │   │   │   │   │   ├── audit-log-viewer.tsx
│   │   │   │   │   │   └── org-switcher.tsx
│   │   │   │   │   ├── forms/       # Complex forms
│   │   │   │   │   │   ├── user-form.tsx
│   │   │   │   │   │   ├── org-form.tsx
│   │   │   │   │   │   ├── role-form.tsx
│   │   │   │   │   │   └── oauth-config-form.tsx
│   │   │   │   │   └── charts/      # Analytics charts
│   │   │   │   │       ├── user-analytics.tsx
│   │   │   │   │       ├── login-trends.tsx
│   │   │   │   │       └── security-metrics.tsx
│   │   │   │   ├── lib/             # Utilities and configurations
│   │   │   │   │   ├── api.ts       # API client (typed)
│   │   │   │   │   ├── auth.ts      # Auth utilities
│   │   │   │   │   ├── permissions.ts # Permission checking
│   │   │   │   │   ├── utils.ts     # General utilities
│   │   │   │   │   ├── constants.ts # App constants
│   │   │   │   │   ├── hooks/       # Custom React hooks
│   │   │   │   │   │   ├── use-auth.ts
│   │   │   │   │   │   ├── use-org.ts
│   │   │   │   │   │   ├── use-users.ts
│   │   │   │   │   │   ├── use-permissions.ts
│   │   │   │   │   │   └── use-websocket.ts
│   │   │   │   │   ├── stores/      # State management (Zustand)
│   │   │   │   │   │   ├── auth-store.ts
│   │   │   │   │   │   ├── org-store.ts
│   │   │   │   │   │   └── ui-store.ts
│   │   │   │   │   └── validations/ # Form validations (Zod)
│   │   │   │   │       ├── auth.ts
│   │   │   │   │       ├── user.ts
│   │   │   │   │       ├── org.ts
│   │   │   │   │       └── rbac.ts
│   │   │   │   ├── styles/          # Global styles
│   │   │   │   │   ├── globals.css
│   │   │   │   │   └── components.css
│   │   │   │   └── types/           # TypeScript types
│   │   │   │       ├── api.ts       # API response types
│   │   │   │       ├── auth.ts      # Auth types
│   │   │   │       ├── user.ts      # User types
│   │   │   │       ├── org.ts       # Organization types
│   │   │   │       └── rbac.ts      # RBAC types
│   │   │   ├── public/              # Static assets
│   │   │   │   ├── images/
│   │   │   │   ├── icons/
│   │   │   │   └── logos/
│   │   │   ├── next.config.js
│   │   │   ├── tailwind.config.js
│   │   │   ├── tsconfig.json
│   │   │   ├── package.json
│   │   │   └── components.json      # shadcn/ui config
│   │   │
│   │   └── docs/                    # Documentation site (Next.js)
│   │       ├── src/
│   │       │   ├── app/
│   │       │   │   ├── docs/
│   │       │   │   │   ├── quick-start/
│   │       │   │   │   ├── api-reference/
│   │       │   │   │   ├── sdks/
│   │       │   │   │   ├── guides/
│   │       │   │   │   └── compliance/
│   │       │   │   ├── api/         # API documentation endpoints
│   │       │   │   ├── layout.tsx
│   │       │   │   └── page.tsx
│   │       │   ├── components/
│   │       │   │   ├── docs/
│   │       │   │   ├── code-block.tsx
│   │       │   │   └── api-playground.tsx
│   │       │   └── lib/
│   │       ├── next.config.js
│   │       ├── tailwind.config.js
│   │       └── package.json
│   │
│   ├── packages/                    # Shared packages (Monorepo)
│   │   ├── ui/                      # Shared UI components
│   │   │   ├── src/
│   │   │   │   ├── components/
│   │   │   │   ├── hooks/
│   │   │   │   ├── utils/
│   │   │   │   └── index.ts
│   │   │   ├── package.json
│   │   │   └── tsconfig.json
│   │   │
│   │   ├── api-client/              # Typed API client
│   │   │   ├── src/
│   │   │   │   ├── client.ts
│   │   │   │   ├── types/
│   │   │   │   │   ├── auth.ts
│   │   │   │   │   ├── users.ts
│   │   │   │   │   ├── orgs.ts
│   │   │   │   │   └── rbac.ts
│   │   │   │   ├── endpoints/
│   │   │   │   │   ├── auth.ts
│   │   │   │   │   ├── users.ts
│   │   │   │   │   ├── orgs.ts
│   │   │   │   │   └── rbac.ts
│   │   │   │   └── index.ts
│   │   │   ├── package.json
│   │   │   └── tsconfig.json
│   │   │
│   │   ├── auth-sdk/                # Client SDK (for customers)
│   │   │   ├── src/
│   │   │   │   ├── index.ts
│   │   │   │   ├── auth.ts
│   │   │   │   ├── session.ts
│   │   │   │   ├── user.ts
│   │   │   │   └── hooks/           # React hooks
│   │   │   │       ├── use-auth.ts
│   │   │   │       ├── use-user.ts
│   │   │   │       └── use-session.ts
│   │   │   ├── package.json
│   │   │   └── README.md
│   │   │
│   │   └── config/                  # Shared configurations
│   │       ├── eslint-config/
│   │       ├── typescript-config/
│   │       └── tailwind-config/
│   │
│   ├── package.json                 # Root package.json (workspaces)
│   ├── turbo.json                   # Turborepo configuration
│   ├── pnpm-workspace.yaml          # PNPM workspaces
│   └── .env.example
│
├── internal/                        # Backend (unchanged)
│   ├── server/
│   │   ├── server.go                # 🔄 Modified to serve frontend
│   │   └── router.go
│   ├── routes/
│   │   ├── routes.go
│   │   ├── routes_frontend.go       # 🆕 Frontend serving routes
│   │   └── ...
│   └── ...
│
├── ent/                            # Database schema (unchanged)
├── pkg/                            # Shared packages (unchanged)
├── migrations/                     # Database migrations (unchanged)
├── templates/                      # Email templates (unchanged)
├── docs/                          # Backend docs (unchanged)
├── scripts/
│   ├── build.sh                   # 🔄 Updated to build frontend
│   ├── dev.sh                     # 🆕 Development script
│   └── deploy.sh                  # 🔄 Updated deployment
├── docker/
│   ├── Dockerfile                 # 🔄 Multi-stage build
│   ├── Dockerfile.frontend        # 🆕 Frontend-only build
│   └── docker-compose.yml         # 🔄 Updated compose
└── Makefile                       # 🔄 Updated with frontend commands
```

## 🎛️ **Key Architecture Decisions**

### **1. Monorepo Structure with Turborepo**
- **Dashboard App**: Main admin interface
- **Docs App**: API documentation and guides
- **Shared Packages**: Reusable UI components and API clients
- **Fast Builds**: Turborepo for efficient build caching

### **2. Three-Tier UI Layout**
- **Route Groups**: Next.js app router groups for different user types
- **Internal Routes**: `/admin/*` for platform staff
- **External Routes**: `/org/[orgId]/*` for customer organizations
- **Auth Routes**: Shared authentication pages

### **3. Component Architecture**
- **shadcn/ui**: Modern, accessible base components
- **Custom Components**: Auth-specific and dashboard components
- **Shared UI Package**: Reusable across apps

### **4. State Management**
- **Server State**: TanStack Query for API data
- **Client State**: Zustand for UI state
- **Auth State**: Custom auth provider

### **5. Development Experience**
- **TypeScript**: Full type safety
- **API Client**: Auto-generated from Go backend
- **Hot Reload**: Fast development iteration
- **Linting**: ESLint + Prettier configuration