"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

// Mock data - replace with real data fetching based on params.id
const mockPoll = {
  id: "1",
  title: "What's your favorite programming language?",
  description: "Help us understand the community preferences for backend development in 2025",
  author: "John Doe",
  status: "active",
  createdAt: "2025-08-20",
  totalVotes: 127,
  options: [
    { id: "1", text: "JavaScript/TypeScript", votes: 45, percentage: 35.4 },
    { id: "2", text: "Python", votes: 38, percentage: 29.9 },
    { id: "3", text: "Java", votes: 25, percentage: 19.7 },
    { id: "4", text: "Go", votes: 12, percentage: 9.4 },
    { id: "5", text: "Rust", votes: 7, percentage: 5.5 },
  ],
};

interface PollPageProps {
  params: { id: string };
}

export default function PollPage({ params }: PollPageProps) {
  const [selectedOption, setSelectedOption] = useState<string | null>(null);
  const [hasVoted, setHasVoted] = useState(false);
  const [isVoting, setIsVoting] = useState(false);

  const handleVote = async () => {
    if (!selectedOption) return;
    
    setIsVoting(true);
    
    // TODO: Implement voting logic
    console.log("Voting for option:", selectedOption);
    
    // Simulate API call
    setTimeout(() => {
      setHasVoted(true);
      setIsVoting(false);
    }, 1000);
  };

  const isActive = mockPoll.status === "active";
  const showResults = hasVoted || !isActive;

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <div className="mb-8">
        <div className="flex items-center gap-4 mb-4">
          <h1 className="text-3xl font-bold">{mockPoll.title}</h1>
          <Badge variant={isActive ? "default" : "secondary"}>
            {mockPoll.status}
          </Badge>
        </div>
        <p className="text-gray-600 dark:text-gray-400 mb-4">
          {mockPoll.description}
        </p>
        <div className="flex items-center gap-4 text-sm text-gray-600">
          <span>By {mockPoll.author}</span>
          <span>•</span>
          <span>Created {mockPoll.createdAt}</span>
          <span>•</span>
          <span>{mockPoll.totalVotes} total votes</span>
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
              {mockPoll.options.map((option) => (
                <div key={option.id} className="space-y-2">
                  {showResults ? (
                    // Results view
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="font-medium">{option.text}</span>
                        <span className="text-sm text-gray-600">
                          {option.votes} votes ({option.percentage}%)
                        </span>
                      </div>
                      <Progress value={option.percentage} className="h-2" />
                    </div>
                  ) : (
                    // Voting view
                    <div
                      className={`p-4 border rounded-lg cursor-pointer transition-colors ${
                        selectedOption === option.id
                          ? "border-blue-500 bg-blue-50 dark:bg-blue-900/20"
                          : "hover:bg-gray-50 dark:hover:bg-gray-800"
                      }`}
                      onClick={() => setSelectedOption(option.id)}
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-4 h-4 rounded-full border-2 flex items-center justify-center ${
                            selectedOption === option.id
                              ? "border-blue-500"
                              : "border-gray-300"
                          }`}
                        >
                          {selectedOption === option.id && (
                            <div className="w-2 h-2 rounded-full bg-blue-500" />
                          )}
                        </div>
                        <span className="font-medium">{option.text}</span>
                      </div>
                    </div>
                  )}
                </div>
              ))}

              {!showResults && isActive && (
                <div className="pt-4">
                  <Button
                    onClick={handleVote}
                    disabled={!selectedOption || isVoting}
                    className="w-full"
                  >
                    {isVoting ? "Submitting..." : "Submit Vote"}
                  </Button>
                </div>
              )}

              {hasVoted && (
                <div className="pt-4 text-center text-green-600 font-medium">
                  ✅ Thank you for voting!
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
                <span className="font-medium">{mockPoll.totalVotes}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Status</span>
                <Badge variant={isActive ? "default" : "secondary"}>
                  {mockPoll.status}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Created</span>
                <span className="font-medium">{mockPoll.createdAt}</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Share This Poll</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button variant="outline" className="w-full">
                Copy Link
              </Button>
              <Button variant="outline" className="w-full">
                Share on Twitter
              </Button>
              <Button variant="outline" className="w-full">
                Share on LinkedIn
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
