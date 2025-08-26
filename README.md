# ALX Polly - Polling Application

A modern, responsive polling application built with Next.js 15, TypeScript, and Shadcn/ui components.

## Features

### 🗳️ Core Polling Features
- Create polls with multiple choice options
- Real-time voting and results
- Poll categories and filtering
- Public and private polls
- Poll sharing capabilities

### 🔐 Authentication (Planned)
- User registration and login
- Protected routes for poll creation
- User dashboard for poll management
- Profile management

### 📊 Analytics & Insights (Planned)
- Real-time vote tracking
- Poll performance metrics
- Visual charts and graphs
- Export poll results

## Tech Stack

- **Framework**: Next.js 15 with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS v4
- **Components**: Shadcn/ui
- **Validation**: Zod
- **Authentication**: (To be implemented)
- **Database**: (To be implemented)

## Project Structure

```
alx-polly/
├── app/
│   ├── (auth)/                 # Authentication routes (grouped)
│   │   ├── login/
│   │   └── signup/
│   ├── api/                    # API routes
│   │   ├── auth/
│   │   └── polls/
│   ├── dashboard/              # User dashboard
│   ├── polls/                  # Poll-related pages
│   │   ├── create/
│   │   ├── [id]/
│   │   └── page.tsx
│   ├── layout.tsx
│   └── page.tsx               # Homepage
├── components/
│   ├── auth/                  # Authentication components
│   ├── layout/                # Layout components
│   ├── polls/                 # Poll-related components
│   └── ui/                    # Shadcn/ui components
├── hooks/                     # Custom React hooks
├── lib/                       # Utility functions
│   ├── auth/
│   ├── validations/
│   └── utils.ts
└── types/                     # TypeScript type definitions
```

## Getting Started

### Prerequisites
- Node.js 18+ and npm
- Git

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd alx-polly
```

2. Install dependencies:
```bash
npm install
```

3. Run the development server:
```bash
npm run dev
```

4. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server

## Development Roadmap

### Phase 1: UI Foundation ✅
- [x] Project setup with Next.js 15 and Shadcn/ui
- [x] Basic routing structure
- [x] Homepage design
- [x] Authentication pages (login/signup)
- [x] Poll creation interface
- [x] Poll viewing interface
- [x] Dashboard layout

### Phase 2: Backend Integration (Next)
- [ ] Database setup (PostgreSQL/MongoDB)
- [ ] Authentication system
- [ ] Poll CRUD operations
- [ ] Voting mechanism
- [ ] User management

### Phase 3: Advanced Features
- [ ] Real-time updates (WebSockets)
- [ ] Poll analytics
- [ ] Social sharing
- [ ] Email notifications
- [ ] Mobile responsiveness improvements

### Phase 4: Performance & Polish
- [ ] Performance optimization
- [ ] SEO improvements
- [ ] Testing (unit, integration, e2e)
- [ ] Documentation
- [ ] Deployment setup

## Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Current Status

This is a foundational scaffolding with:
- ✅ Complete UI components and page layouts
- ✅ Navigation and routing structure
- ✅ TypeScript types and validation schemas
- ✅ Custom hooks for data management
- ✅ API route placeholders
- ⏳ Backend functionality (in progress)
- ⏳ Authentication system (planned)
- ⏳ Database integration (planned)

## Notes for Development

- All API calls are currently mocked with placeholder data
- Authentication state is simulated (see `hooks/use-auth.ts`)
- Database integration needs to be implemented
- Form validation is set up but needs backend integration
- Responsive design is implemented but may need refinement

## License

This project is part of the ALX Software Engineering program.
