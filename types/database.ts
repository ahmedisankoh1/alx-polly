export type Database = {
  public: {
    Tables: {
      polls: {
        Row: {
          id: string
          title: string
          description: string | null
          user_id: string
          status: 'active' | 'closed' | 'draft'
          created_at: string
          updated_at: string
          expires_at: string | null
          allow_multiple_votes: boolean
          is_public: boolean
        }
        Insert: {
          id?: string
          title: string
          description?: string | null
          user_id: string
          status?: 'active' | 'closed' | 'draft'
          created_at?: string
          updated_at?: string
          expires_at?: string | null
          allow_multiple_votes?: boolean
          is_public?: boolean
        }
        Update: {
          id?: string
          title?: string
          description?: string | null
          user_id?: string
          status?: 'active' | 'closed' | 'draft'
          created_at?: string
          updated_at?: string
          expires_at?: string | null
          allow_multiple_votes?: boolean
          is_public?: boolean
        }
      }
      poll_options: {
        Row: {
          id: string
          poll_id: string
          option_text: string
          option_order: number
          created_at: string
        }
        Insert: {
          id?: string
          poll_id: string
          option_text: string
          option_order: number
          created_at?: string
        }
        Update: {
          id?: string
          poll_id?: string
          option_text?: string
          option_order?: number
          created_at?: string
        }
      }
      poll_votes: {
        Row: {
          id: string
          poll_id: string
          option_id: string
          user_id: string | null
          voter_ip: string | null
          created_at: string
        }
        Insert: {
          id?: string
          poll_id: string
          option_id: string
          user_id?: string | null
          voter_ip?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          poll_id?: string
          option_id?: string
          user_id?: string | null
          voter_ip?: string | null
          created_at?: string
        }
      }
    }
    Views: {
      poll_stats: {
        Row: {
          id: string
          title: string
          status: 'active' | 'closed' | 'draft'
          created_at: string
          total_votes: number
          total_options: number
        }
      }
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
    }
  }
}

export type Poll = Database['public']['Tables']['polls']['Row']
export type PollInsert = Database['public']['Tables']['polls']['Insert']
export type PollUpdate = Database['public']['Tables']['polls']['Update']

export type PollOption = Database['public']['Tables']['poll_options']['Row']
export type PollOptionInsert = Database['public']['Tables']['poll_options']['Insert']

export type PollVote = Database['public']['Tables']['poll_votes']['Row']
export type PollVoteInsert = Database['public']['Tables']['poll_votes']['Insert']

export type PollWithOptions = Poll & {
  poll_options: PollOption[]
}

export type PollWithStats = Poll & {
  total_votes: number
  total_options: number
}
