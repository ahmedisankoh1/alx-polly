import { createClient } from '@/lib/supabase/client'
import { Database, Poll, PollInsert, PollOption, PollWithOptions } from '@/types/database'

export type SupabaseClient = ReturnType<typeof createClient>

export class PollService {
  private supabase: SupabaseClient

  constructor() {
    this.supabase = createClient()
  }

  // Create a new poll with options
  async createPoll(pollData: {
    title: string
    description?: string
    options: string[]
    userId: string
    isPublic?: boolean
    allowMultipleVotes?: boolean
  }) {
    const { title, description, options, userId, isPublic = true, allowMultipleVotes = false } = pollData

    // Start a transaction-like operation
    try {
      // 1. Create the poll
      const { data: poll, error: pollError } = await this.supabase
        .from('polls')
        .insert({
          title,
          description,
          user_id: userId,
          is_public: isPublic,
          allow_multiple_votes: allowMultipleVotes,
          status: 'active'
        })
        .select()
        .single()

      if (pollError) throw pollError

      // 2. Create poll options
      const optionsToInsert = options
        .filter(option => option.trim() !== '') // Remove empty options
        .map((option, index) => ({
          poll_id: poll.id,
          option_text: option.trim(),
          option_order: index + 1
        }))

      const { data: pollOptions, error: optionsError } = await this.supabase
        .from('poll_options')
        .insert(optionsToInsert)
        .select()

      if (optionsError) {
        // If options creation fails, delete the poll
        await this.supabase.from('polls').delete().eq('id', poll.id)
        throw optionsError
      }

      return {
        poll,
        options: pollOptions,
        success: true
      }
    } catch (error) {
      console.error('Error creating poll:', String(error))
      return {
        poll: null,
        options: null,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      }
    }
  }

  // Get all polls for a user
  async getUserPolls(userId: string) {
    const { data, error } = await this.supabase
      .from('polls')
      .select(`
        *,
        poll_options (*)
      `)
      .eq('user_id', userId)
      .order('created_at', { ascending: false })

    if (error) {
      console.error('Error fetching user polls:', error)
      return { polls: [], error: error.message || 'Failed to fetch user polls' }
    }

    return { polls: data as PollWithOptions[], error: null }
  }

  // Get public polls
  async getPublicPolls(limit = 10) {
    const { data, error } = await this.supabase
      .from('polls')
      .select(`
        *,
        poll_options (*),
        poll_votes (count)
      `)
      .eq('is_public', true)
      .eq('status', 'active')
      .order('created_at', { ascending: false })
      .limit(limit)

    if (error) {
      console.error('Error fetching public polls:', error)
      return { polls: [], error: error.message || 'Failed to fetch polls' }
    }

    return { polls: data, error: null }
  }

  // Get a single poll with options and vote counts
  async getPollById(pollId: string) {
    const { data, error } = await this.supabase
      .from('polls')
      .select(`
        *,
        poll_options (*),
        poll_votes (
          id,
          option_id,
          user_id,
          created_at
        )
      `)
      .eq('id', pollId)
      .single()

    if (error) {
      console.error('Error fetching poll:', error)
      return { poll: null, error: error.message || 'Failed to fetch poll' }
    }

    return { poll: data, error: null }
  }

  // Vote on a poll
  async voteOnPoll(pollId: string, optionId: string, userId?: string) {
    try {
      // Check if user already voted (if logged in)
      if (userId) {
        const { data: existingVote } = await this.supabase
          .from('poll_votes')
          .select('id')
          .eq('poll_id', pollId)
          .eq('user_id', userId)
          .single()

        if (existingVote) {
          return { success: false, error: 'You have already voted on this poll' }
        }
      }

      const { error } = await this.supabase
        .from('poll_votes')
        .insert({
          poll_id: pollId,
          option_id: optionId,
          user_id: userId || null
        })

      if (error) throw error

      return { success: true, error: null }
    } catch (error) {
      console.error('Error voting on poll:', String(error))
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error occurred' 
      }
    }
  }

  // Update poll status
  async updatePollStatus(pollId: string, status: 'active' | 'closed' | 'draft') {
    const { error } = await this.supabase
      .from('polls')
      .update({ status })
      .eq('id', pollId)

    if (error) {
      console.error('Error updating poll status:', error)
      return { success: false, error: error.message || 'Failed to update poll status' }
    }

    return { success: true, error: null }
  }

  // Delete a poll
  async deletePoll(pollId: string) {
    const { error } = await this.supabase
      .from('polls')
      .delete()
      .eq('id', pollId)

    if (error) {
      console.error('Error deleting poll:', error)
      return { success: false, error: error.message || 'Failed to delete poll' }
    }

    return { success: true, error: null }
  }

  // Get poll statistics
  async getPollStats(pollId: string) {
    const { data, error } = await this.supabase
      .from('poll_options')
      .select(`
        id,
        option_text,
        poll_votes (count)
      `)
      .eq('poll_id', pollId)
      .order('option_order')

    if (error) {
      console.error('Error fetching poll stats:', error)
      return { stats: [], error: error.message || 'Failed to fetch poll stats' }
    }

    const stats = data.map(option => ({
      optionId: option.id,
      optionText: option.option_text,
      voteCount: option.poll_votes?.[0]?.count || 0
    }))

    return { stats, error: null }
  }
}

// Export a singleton instance
export const pollService = new PollService()
