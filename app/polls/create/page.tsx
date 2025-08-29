"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/contexts/auth-context";
import { pollService } from "@/lib/services/pollService";

export default function CreatePollPage() {
  const [pollData, setPollData] = useState({
    title: "",
    description: "",
    options: ["", ""],
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  
  const { user } = useAuth();
  const router = useRouter();

  const addOption = () => {
    setPollData(prev => ({
      ...prev,
      options: [...prev.options, ""]
    }));
  };

  const removeOption = (index: number) => {
    setPollData(prev => ({
      ...prev,
      options: prev.options.filter((_, i) => i !== index)
    }));
  };

  const updateOption = (index: number, value: string) => {
    setPollData(prev => ({
      ...prev,
      options: prev.options.map((option, i) => i === index ? value : option)
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    // Validation
    if (!user) {
      setError("You must be logged in to create a poll");
      setIsLoading(false);
      return;
    }

    const validOptions = pollData.options.filter(option => option.trim() !== "");
    if (validOptions.length < 2) {
      setError("You must provide at least 2 options");
      setIsLoading(false);
      return;
    }

    try {
      const result = await pollService.createPoll({
        title: pollData.title,
        description: pollData.description || undefined,
        options: validOptions,
        userId: user.id,
        isPublic: true,
        allowMultipleVotes: false
      });

      if (result.success && result.poll) {
        // Redirect to the newly created poll
        router.push(`/polls/${result.poll.id}`);
      } else {
        setError(result.error || "Failed to create poll");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-2xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Create New Poll</h1>
        <p className="text-gray-600 dark:text-gray-400">
          Design your poll and gather valuable insights from your audience
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Poll Details</CardTitle>
          <CardDescription>
            Add your poll question and response options
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="p-3 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md dark:bg-red-900/20 dark:border-red-800 dark:text-red-400">
                {error}
              </div>
            )}
            
            {!user && (
              <div className="p-3 text-sm text-blue-600 bg-blue-50 border border-blue-200 rounded-md dark:bg-blue-900/20 dark:border-blue-800 dark:text-blue-400">
                Please log in to create a poll.
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="title">Poll Question *</Label>
              <Input
                id="title"
                placeholder="What would you like to ask?"
                value={pollData.title}
                onChange={(e) => setPollData(prev => ({ ...prev, title: e.target.value }))}
                required
                disabled={isLoading || !user}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">Description (Optional)</Label>
              <Input
                id="description"
                placeholder="Add more context to your poll..."
                value={pollData.description}
                onChange={(e) => setPollData(prev => ({ ...prev, description: e.target.value }))}
                disabled={isLoading || !user}
              />
            </div>

            <div className="space-y-4">
              <Label>Response Options *</Label>
              {pollData.options.map((option, index) => (
                <div key={index} className="flex gap-2">
                  <Input
                    placeholder={`Option ${index + 1}`}
                    value={option}
                    onChange={(e) => updateOption(index, e.target.value)}
                    required
                    disabled={isLoading || !user}
                  />
                  {pollData.options.length > 2 && (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => removeOption(index)}
                      disabled={isLoading || !user}
                    >
                      Remove
                    </Button>
                  )}
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                onClick={addOption}
                disabled={pollData.options.length >= 10 || isLoading || !user}
              >
                Add Option
              </Button>
            </div>

            <div className="flex gap-4 pt-4">
              <Button type="submit" disabled={isLoading || !user} className="flex-1">
                {isLoading ? "Creating Poll..." : "Create Poll"}
              </Button>
              <Button type="button" variant="outline" disabled={isLoading || !user}>
                Save as Draft
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
