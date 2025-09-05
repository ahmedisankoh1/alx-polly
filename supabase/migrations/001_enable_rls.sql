-- Enable Row Level Security (RLS) on all tables
-- This migration fixes CRITICAL-002: Missing Row Level Security

-- Enable RLS on polls table
ALTER TABLE polls ENABLE ROW LEVEL SECURITY;

-- Enable RLS on votes table  
ALTER TABLE votes ENABLE ROW LEVEL SECURITY;

-- Polls: Users can only access their own polls
CREATE POLICY "Users can view own polls" ON polls
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update own polls" ON polls
  FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own polls" ON polls
  FOR DELETE USING (auth.uid() = user_id);

-- Allow anyone to view polls for voting (public polls)
CREATE POLICY "Anyone can view polls for voting" ON polls
  FOR SELECT USING (true);

-- Votes: Anyone can view votes (for results)
CREATE POLICY "Anyone can view votes" ON votes
  FOR SELECT USING (true);

-- Votes: Authenticated users can create votes
CREATE POLICY "Authenticated users can vote" ON votes
  FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

-- Prevent duplicate voting (one vote per user per poll)
CREATE POLICY "One vote per user per poll" ON votes
  FOR INSERT WITH CHECK (
    NOT EXISTS (
      SELECT 1 FROM votes 
      WHERE votes.poll_id = votes.poll_id 
      AND votes.user_id = auth.uid()
    )
  );
