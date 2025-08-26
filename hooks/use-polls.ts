"use client";

import { useState, useEffect } from "react";
import { Poll } from "@/types";

export function usePolls() {
  const [polls, setPolls] = useState<Poll[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchPolls();
  }, []);

  const fetchPolls = async () => {
    try {
      setIsLoading(true);
      // TODO: Replace with actual API call
      const response = await fetch("/api/polls");
      
      if (!response.ok) {
        throw new Error("Failed to fetch polls");
      }

      const data = await response.json();
      setPolls(data.polls || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const refetch = () => {
    fetchPolls();
  };

  return { polls, isLoading, error, refetch };
}

export function usePoll(pollId: string) {
  const [poll, setPoll] = useState<Poll | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (pollId) {
      fetchPoll(pollId);
    }
  }, [pollId]);

  const fetchPoll = async (id: string) => {
    try {
      setIsLoading(true);
      // TODO: Replace with actual API call
      const response = await fetch(`/api/polls/${id}`);
      
      if (!response.ok) {
        throw new Error("Failed to fetch poll");
      }

      const data = await response.json();
      setPoll(data.poll);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const vote = async (optionId: string) => {
    try {
      // TODO: Implement voting API call
      const response = await fetch(`/api/polls/${pollId}/vote`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ optionId }),
      });

      if (!response.ok) {
        throw new Error("Failed to submit vote");
      }

      // Refetch poll data to get updated results
      fetchPoll(pollId);
    } catch (err) {
      throw err;
    }
  };

  return { poll, isLoading, error, vote };
}

export function useCreatePoll() {
  const [isLoading, setIsLoading] = useState(false);

  const createPoll = async (pollData: {
    title: string;
    description?: string;
    options: string[];
  }) => {
    setIsLoading(true);
    try {
      // TODO: Implement actual poll creation API call
      const response = await fetch("/api/polls", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(pollData),
      });

      if (!response.ok) {
        throw new Error("Failed to create poll");
      }

      const data = await response.json();
      return data.poll;
    } catch (error) {
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  return { createPoll, isLoading };
}
