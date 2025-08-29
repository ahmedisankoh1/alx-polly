"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useAuth } from "@/contexts/auth-context";
import { pollService } from "@/lib/services/pollService";

interface PollData {
  id: string;
  title: string;
  description: string | null;
  status: string;
  created_at: string;
  poll_options: Array<{
    id: string;
    option_text: string;
    option_order: number;
  }>;
  poll_votes: Array<{
    id: string;
    option_id: string;
    user_id: string;
    created_at: string;
  }>;
}

export default function PollPage() {
  const params = useParams();
  const pollId = params.id as string;
  const { user } = useAuth();
  
  const [poll, setPoll] = useState<PollData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [voting, setVoting] = useState(false);
  const [hasVoted, setHasVoted] = useState(false);

  useEffect(() => {
    const fetchPoll = async () => {
      if (!pollId) return;
      
      setLoading(true);
      try {
        const result = await pollService.getPollById(pollId);
        if (result.error) {
          setError(result.error);
        } else if (result.poll) {
          setPoll(result.poll);
          // Check if user has already voted
          if (user) {
            const userVote = result.poll.poll_votes.find(
              (vote: any) => vote.user_id === user.id
            );
            setHasVoted(!!userVote);
          }
        }
      } catch (err) {
        setError("Failed to load poll");
      } finally {
        setLoading(false);
      }
    };

    fetchPoll();
  }, [pollId, user]);

  const handleVote = async (optionId: string) => {
    if (!poll || voting || hasVoted || !user) return;
    
    setVoting(true);
    try {
      const result = await pollService.voteOnPoll(poll.id, optionId, user.id);
      if (result.success) {
        // Refresh poll data to show updated vote counts
        const updatedResult = await pollService.getPollById(pollId);
        if (updatedResult.poll) {
          setPoll(updatedResult.poll);
          setHasVoted(true);
        }
      } else {
        setError(result.error || "Failed to submit vote");
      }
    } catch (err) {
      setError("Failed to submit vote");
    } finally {
      setVoting(false);
    }
  };

  const getVoteCount = (optionId: string) => {
    if (!poll) return 0;
    return poll.poll_votes.filter(vote => vote.option_id === optionId).length;
  };

  const getTotalVotes = () => {
    if (!poll) return 0;
    return poll.poll_votes.length;
  };

  const getVotePercentage = (optionId: string) => {
    const totalVotes = getTotalVotes();
    if (totalVotes === 0) return 0;
    const optionVotes = getVoteCount(optionId);
    return Math.round((optionVotes / totalVotes) * 100);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  if (loading) {
    return (
      <div className="container mx-auto px-4 py-8 flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600 mx-auto mb-4"></div>
          <p>Loading poll...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-2xl">
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-red-600 mb-4">{error}</p>
              <Button onClick={() => window.location.reload()}>
                Try Again
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!poll) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-2xl">
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-gray-600">Poll not found</p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const totalVotes = getTotalVotes();
  const sortedOptions = [...poll.poll_options].sort((a, b) => a.option_order - b.option_order);
  const isActive = poll.status === "active";
  const showResults = hasVoted || !isActive;

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <div className="mb-8">
        <div className="flex items-center gap-4 mb-4">
          <h1 className="text-3xl font-bold">{poll.title}</h1>
          <Badge variant={isActive ? "default" : "secondary"}>
            {poll.status}
          </Badge>
        </div>
        {poll.description && (
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            {poll.description}
          </p>
        )}
        <div className="flex items-center gap-4 text-sm text-gray-600">
          <span>Created {formatDate(poll.created_at)}</span>
          <span>•</span>
          <span>{totalVotes} {totalVotes === 1 ? 'vote' : 'votes'}</span>
        </div>
      </div>

      <div className="grid lg:grid-cols-3 gap-8">
        {/* Voting/Results Section */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>
                {showResults ? "Results" : "Cast Your Vote"}
              </CardTitle>
              <CardDescription>
                {showResults 
                  ? "See how the community voted"
                  : "Select an option to participate in this poll"
                }
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {sortedOptions.map((option) => {
                const voteCount = getVoteCount(option.id);
                const percentage = getVotePercentage(option.id);
                
                return (
                  <div key={option.id} className="space-y-2">
                    {showResults ? (
                      // Results view
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="font-medium">{option.option_text}</span>
                          <span className="text-sm text-gray-600">
                            {voteCount} votes ({percentage}%)
                          </span>
                        </div>
                        <Progress value={percentage} className="h-2" />
                      </div>
                    ) : (
                      // Voting view
                      <div
                        className="p-4 border rounded-lg cursor-pointer transition-colors hover:bg-gray-50 dark:hover:bg-gray-800"
                        onClick={() => handleVote(option.id)}
                      >
                        <div className="flex items-center gap-3">
                          <span className="font-medium">{option.option_text}</span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}

              {!user && isActive && !showResults && (
                <div className="pt-4 p-4 bg-blue-50 border border-blue-200 rounded-md dark:bg-blue-900/20 dark:border-blue-800">
                  <p className="text-blue-700 dark:text-blue-300 text-sm">
                    Please log in to vote on this poll.
                  </p>
                </div>
              )}

              {hasVoted && (
                <div className="pt-4 text-center text-green-600 font-medium">
                  ✅ Thank you for voting!
                </div>
              )}

              {voting && (
                <div className="pt-4 text-center text-blue-600 font-medium">
                  Submitting your vote...
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Poll Info Sidebar */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Poll Statistics</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between">
                <span className="text-gray-600">Total Votes</span>
                <span className="font-medium">{totalVotes}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Status</span>
                <Badge variant={isActive ? "default" : "secondary"}>
                  {poll.status}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Created</span>
                <span className="font-medium">{formatDate(poll.created_at)}</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Share This Poll</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button 
                variant="outline" 
                className="w-full"
                onClick={() => {
                  navigator.clipboard.writeText(window.location.href);
                  alert('Link copied to clipboard!');
                }}
              >
                Copy Link
              </Button>
              <Button 
                variant="outline" 
                className="w-full"
                onClick={() => {
                  const text = `Check out this poll: ${poll.title}`;
                  const url = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(window.location.href)}`;
                  window.open(url, '_blank');
                }}
              >
                Share on Twitter
              </Button>
              <Button 
                variant="outline" 
                className="w-full"
                onClick={() => {
                  const url = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(window.location.href)}`;
                  window.open(url, '_blank');
                }}
              >
                Share on LinkedIn
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
