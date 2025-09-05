"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from "next/cache";

// CREATE POLL
export async function createPoll(formData: FormData) {
  const supabase = await createClient();

  const question = formData.get("question") as string;
  const options = formData.getAll("options").filter(Boolean) as string[];

  // Input validation
  if (!question || question.trim().length === 0) {
    return { error: "Question is required." };
  }
  if (question.length > 200) {
    return { error: "Question must be less than 200 characters." };
  }
  if (options.length < 2) {
    return { error: "At least two options are required." };
  }
  if (options.length > 10) {
    return { error: "Maximum 10 options allowed." };
  }
  if (options.some(opt => opt.length > 100)) {
    return { error: "Options must be less than 100 characters each." };
  }
  if (options.some(opt => opt.trim().length === 0)) {
    return { error: "All options must have content." };
  }

  // Get user from session
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) {
    console.error('Auth error:', userError);
    return { error: "Authentication failed. Please try again." };
  }
  if (!user) {
    return { error: "You must be logged in to create a poll." };
  }

  const { error } = await supabase.from("polls").insert([
    {
      user_id: user.id,
      question: question.trim(),
      options: options.map(opt => opt.trim()),
    },
  ]);

  if (error) {
    console.error('Database error:', error);
    return { error: "Failed to create poll. Please try again." };
  }

  revalidatePath("/polls");
  return { error: null };
}

// GET USER POLLS
export async function getUserPolls() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { polls: [], error: "Not authenticated" };

  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error) return { polls: [], error: error.message };
  return { polls: data ?? [], error: null };
}

// GET POLL BY ID
export async function getPollById(id: string) {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("id", id)
    .single();

  if (error) return { poll: null, error: error.message };
  return { poll: data, error: null };
}

// SUBMIT VOTE
export async function submitVote(pollId: string, optionIndex: number) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  // Require authentication to vote
  if (!user) return { error: 'You must be logged in to vote.' };

  // Check for existing vote
  const { data: existingVote } = await supabase
    .from("votes")
    .select("id")
    .eq("poll_id", pollId)
    .eq("user_id", user.id)
    .single();

  if (existingVote) {
    return { error: 'You have already voted on this poll.' };
  }

  const { error } = await supabase.from("votes").insert([
    {
      poll_id: pollId,
      user_id: user.id,
      option_index: optionIndex,
    },
  ]);

  if (error) return { error: error.message };
  return { error: null };
}

// DELETE POLL
export async function deletePoll(id: string) {
  const supabase = await createClient();
  
  // Verify ownership before deletion
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { error: "Unauthorized" };

  const { data: poll } = await supabase
    .from("polls")
    .select("user_id")
    .eq("id", id)
    .single();
    
  if (!poll || poll.user_id !== user.id) {
    return { error: "Unauthorized" };
  }

  const { error } = await supabase
    .from("polls")
    .delete()
    .eq("id", id)
    .eq("user_id", user.id);
    
  if (error) return { error: error.message };
  revalidatePath("/polls");
  return { error: null };
}

// UPDATE POLL
export async function updatePoll(pollId: string, formData: FormData) {
  const supabase = await createClient();

  const question = formData.get("question") as string;
  const options = formData.getAll("options").filter(Boolean) as string[];

  // Input validation
  if (!question || question.trim().length === 0) {
    return { error: "Question is required." };
  }
  if (question.length > 200) {
    return { error: "Question must be less than 200 characters." };
  }
  if (options.length < 2) {
    return { error: "At least two options are required." };
  }
  if (options.length > 10) {
    return { error: "Maximum 10 options allowed." };
  }
  if (options.some(opt => opt.length > 100)) {
    return { error: "Options must be less than 100 characters each." };
  }
  if (options.some(opt => opt.trim().length === 0)) {
    return { error: "All options must have content." };
  }

  // Get user from session
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) {
    console.error('Auth error:', userError);
    return { error: "Authentication failed. Please try again." };
  }
  if (!user) {
    return { error: "You must be logged in to update a poll." };
  }

  // Only allow updating polls owned by the user
  const { error } = await supabase
    .from("polls")
    .update({ 
      question: question.trim(), 
      options: options.map(opt => opt.trim()) 
    })
    .eq("id", pollId)
    .eq("user_id", user.id);

  if (error) {
    console.error('Database error:', error);
    return { error: "Failed to update poll. Please try again." };
  }

  return { error: null };
}
