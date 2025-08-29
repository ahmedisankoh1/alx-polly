"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/contexts/auth-context";
import { pollService } from "@/lib/services/pollService";

interface PollData {
  id: string;
  title: string;
  description: string | null;
  status: string;
  created_at: string;
  user_id: string;
  is_public: boolean;
  poll_options: Array<{
    id: string;
    option_text: string;
    option_order: number;
  }>;
  poll_votes: Array<{
    id: string;
    option_id: string;
    created_at: string;
  }>;
}

export default function PollsPage() {
  const { user, loading: authLoading } = useAuth();
  const [polls, setPolls] = useState<PollData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [mounted, setMounted] = useState(false);

  // Handle client-side mounting to prevent hydration mismatches
  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    const fetchPolls = async () => {
      setLoading(true);
      try {
        const result = await pollService.getPublicPolls(20);
        if (result.error) {
          setError(result.error);
        } else {
          setPolls(result.polls as PollData[]);
        }
      } catch (err) {
        setError("Failed to load polls");
      } finally {
        setLoading(false);
      }
    };

    fetchPolls();
  }, []);

  const filteredPolls = polls.filter(poll => 
    poll.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (poll.description && poll.description.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  const getVoteCount = (poll: PollData) => {
    return poll.poll_votes?.length || 0;
  };

  const getUserName = () => {
    if (!user) return '';
    
    // Try to get name from user metadata first
    if (user.user_metadata?.full_name) {
      return user.user_metadata.full_name;
    }
    
    // If no full name, extract name from email
    if (user.email) {
      const emailName = user.email.split('@')[0];
      // Capitalize first letter and replace dots/underscores with spaces
      return emailName
        .replace(/[._]/g, ' ')
        .split(' ')
        .map(part => part.charAt(0).toUpperCase() + part.slice(1))
        .join(' ');
    }
    
    return 'User';
  };
  // Don't render auth-dependent content until mounted on client
  if (!mounted) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold">Browse Polls</h1>
            <p className="text-gray-600 dark:text-gray-400">
              Discover and participate in community polls
            </p>
          </div>
        </div>
        <div className="flex gap-4 mb-8">
          <div className="h-10 w-80 bg-gray-200 animate-pulse rounded"></div>
          <div className="h-10 w-20 bg-gray-200 animate-pulse rounded"></div>
          <div className="h-10 w-20 bg-gray-200 animate-pulse rounded"></div>
        </div>
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600 mx-auto mb-4"></div>
            <p>Loading...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      {/* User Greeting - only show if auth is loaded and user exists */}
      {!authLoading && user && (
        <div className="mb-6 p-4 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 rounded-lg border border-blue-100 dark:border-blue-800">
          <h2 className="text-xl font-semibold text-blue-900 dark:text-blue-100">
            Hello, {getUserName()}! 👋
          </h2>
          <p className="text-blue-700 dark:text-blue-300 text-sm mt-1">
            Welcome back! Discover new polls or create your own to engage with the community.
          </p>
        </div>
      )}

      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold">Browse Polls</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Discover and participate in community polls
          </p>
        </div>
        <div className="flex gap-2">
          {/* Only show buttons when auth state is determined */}
          {!authLoading && (
            <>
              {user ? (
                <Button asChild>
                  <Link href="/polls/create">Create Poll</Link>
                </Button>
              ) : (
                <>
                  <Button asChild variant="outline">
                    <Link href="/login">Sign In</Link>
                  </Button>
                  <Button asChild>
                    <Link href="/signup">Sign Up</Link>
                  </Button>
                </>
              )}
            </>
          )}
        </div>
      </div>

      {/* Search */}
      <div className="flex gap-4 mb-8">
        <Input
          placeholder="Search polls..."
          className="max-w-sm"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <Button variant="outline">Filter</Button>
        <Button variant="outline">Sort</Button>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600 mx-auto mb-4"></div>
            <p>Loading polls...</p>
          </div>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="text-center py-12">
          <p className="text-red-600 mb-4">{error}</p>
          <Button onClick={() => window.location.reload()}>
            Try Again
          </Button>
        </div>
      )}

      {/* Polls Grid */}
      {!loading && !error && (
        <>
          <div className="grid gap-6">
            {filteredPolls.length > 0 ? (
              filteredPolls.map((poll) => (
                <Card key={poll.id} className="hover:shadow-md transition-shadow">
                  <CardHeader>
                    <div className="flex justify-between items-start mb-2">
                      <div className="flex-1">
                        <CardTitle className="mb-2">{poll.title}</CardTitle>
                        {poll.description && (
                          <CardDescription>{poll.description}</CardDescription>
                        )}
                      </div>
                      <Badge variant={poll.status === "active" ? "default" : "secondary"}>
                        {poll.status}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div className="text-sm text-gray-600">
                        {getVoteCount(poll)} votes • Created {formatDate(poll.created_at)}
                      </div>
                      <div className="flex gap-2">
                        <Button asChild variant="outline" size="sm">
                          <Link href={`/polls/${poll.id}`}>
                            {poll.status === "active" ? "Vote" : "View Results"}
                          </Link>
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="sm"
                          onClick={() => {
                            navigator.clipboard.writeText(`${window.location.origin}/polls/${poll.id}`);
                            alert('Poll link copied to clipboard!');
                          }}
                        >
                          Share
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            ) : (
              <div className="text-center py-12">
                <p className="text-gray-600 mb-4">
                  {searchTerm ? 'No polls found matching your search.' : 'No polls available yet.'}
                </p>
                {!authLoading && user && !searchTerm && (
                  <Button asChild>
                    <Link href="/polls/create">Create the First Poll</Link>
                  </Button>
                )}
                {!authLoading && !user && !searchTerm && (
                  <div className="space-y-2">
                    <p className="text-sm text-gray-500">Sign in to create and vote on polls</p>
                    <div className="flex gap-2 justify-center">
                      <Button asChild variant="outline">
                        <Link href="/login">Sign In</Link>
                      </Button>
                      <Button asChild>
                        <Link href="/signup">Sign Up</Link>
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Load More */}
          {filteredPolls.length > 0 && (
            <div className="text-center mt-8">
              <Button variant="outline">Load More Polls</Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
