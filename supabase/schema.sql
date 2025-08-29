-- Database schema for ALX Polly application

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Polls table
CREATE TABLE polls (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title TEXT NOT NULL,
  description TEXT,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'closed', 'draft')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  allow_multiple_votes BOOLEAN DEFAULT false,
  is_public BOOLEAN DEFAULT true
);

-- Poll options table
CREATE TABLE poll_options (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  poll_id UUID NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  option_text TEXT NOT NULL,
  option_order INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Poll votes table
CREATE TABLE poll_votes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  poll_id UUID NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  option_id UUID NOT NULL REFERENCES poll_options(id) ON DELETE CASCADE,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  voter_ip INET,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  
  -- Ensure one vote per user per poll (if user is logged in)
  UNIQUE(poll_id, user_id)
);

-- Indexes for better performance
CREATE INDEX idx_polls_user_id ON polls(user_id);
CREATE INDEX idx_polls_status ON polls(status);
CREATE INDEX idx_polls_created_at ON polls(created_at);
CREATE INDEX idx_poll_options_poll_id ON poll_options(poll_id);
CREATE INDEX idx_poll_votes_poll_id ON poll_votes(poll_id);
CREATE INDEX idx_poll_votes_option_id ON poll_votes(option_id);

-- Row Level Security (RLS) policies
ALTER TABLE polls ENABLE ROW LEVEL SECURITY;
ALTER TABLE poll_options ENABLE ROW LEVEL SECURITY;
ALTER TABLE poll_votes ENABLE ROW LEVEL SECURITY;

-- Polls policies
CREATE POLICY "Users can view public polls" ON polls
  FOR SELECT USING (is_public = true OR auth.uid() = user_id);

CREATE POLICY "Users can create their own polls" ON polls
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own polls" ON polls
  FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own polls" ON polls
  FOR DELETE USING (auth.uid() = user_id);

-- Poll options policies
CREATE POLICY "Users can view poll options for accessible polls" ON poll_options
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM polls 
      WHERE polls.id = poll_options.poll_id 
      AND (polls.is_public = true OR polls.user_id = auth.uid())
    )
  );

CREATE POLICY "Users can create options for their own polls" ON poll_options
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM polls 
      WHERE polls.id = poll_options.poll_id 
      AND polls.user_id = auth.uid()
    )
  );

CREATE POLICY "Users can update options for their own polls" ON poll_options
  FOR UPDATE USING (
    EXISTS (
      SELECT 1 FROM polls 
      WHERE polls.id = poll_options.poll_id 
      AND polls.user_id = auth.uid()
    )
  );

CREATE POLICY "Users can delete options for their own polls" ON poll_options
  FOR DELETE USING (
    EXISTS (
      SELECT 1 FROM polls 
      WHERE polls.id = poll_options.poll_id 
      AND polls.user_id = auth.uid()
    )
  );

-- Poll votes policies
CREATE POLICY "Users can view votes for accessible polls" ON poll_votes
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM polls 
      WHERE polls.id = poll_votes.poll_id 
      AND (polls.is_public = true OR polls.user_id = auth.uid())
    )
  );

CREATE POLICY "Users can vote on public polls" ON poll_votes
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM polls 
      WHERE polls.id = poll_votes.poll_id 
      AND polls.is_public = true 
      AND polls.status = 'active'
    )
  );

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to automatically update updated_at
CREATE TRIGGER update_polls_updated_at 
  BEFORE UPDATE ON polls 
  FOR EACH ROW 
  EXECUTE FUNCTION update_updated_at_column();

-- View for poll statistics
CREATE OR REPLACE VIEW poll_stats AS
SELECT 
  p.id,
  p.title,
  p.status,
  p.created_at,
  COUNT(DISTINCT pv.id) as total_votes,
  COUNT(DISTINCT po.id) as total_options
FROM polls p
LEFT JOIN poll_options po ON p.id = po.poll_id
LEFT JOIN poll_votes pv ON p.id = pv.poll_id
GROUP BY p.id, p.title, p.status, p.created_at;
