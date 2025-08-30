# Deployment Guide for Vercel

## Environment Variables Setup

To deploy this application on Vercel, you need to configure the following environment variables:

### Required Environment Variables

1. **NEXT_PUBLIC_SUPABASE_URL**
   - Your Supabase project URL
   - Example: `https://your-project-id.supabase.co`

2. **NEXT_PUBLIC_SUPABASE_ANON_KEY**
   - Your Supabase anonymous/public key
   - Example: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`

### How to Add Environment Variables on Vercel

1. Go to your Vercel dashboard
2. Select your project
3. Go to "Settings" → "Environment Variables"
4. Add the following variables:
   - **Name**: `NEXT_PUBLIC_SUPABASE_URL`
   - **Value**: Your Supabase project URL
   - **Environment**: Production, Preview, Development

   - **Name**: `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - **Value**: Your Supabase anonymous key
   - **Environment**: Production, Preview, Development

### Finding Your Supabase Credentials

1. Go to [Supabase Dashboard](https://app.supabase.com)
2. Select your project
3. Go to "Settings" → "API"
4. Copy the "Project URL" and "Project API keys" → "anon public"

### Local Development

For local development, make sure you have a `.env.local` file with:

```
NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
```

### Troubleshooting

If you get build errors related to Supabase:
1. Verify all environment variables are correctly set
2. Make sure the variable names match exactly (case-sensitive)
3. Redeploy after adding/updating environment variables
