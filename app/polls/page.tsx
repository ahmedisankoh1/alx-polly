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
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-gray-50 to-blue-50 dark:from-gray-900 dark:via-slate-900 dark:to-gray-800">
      <div className="container mx-auto px-4 py-8">
        {/* User Greeting - Enhanced Design */}
        {!authLoading && user && (
          <div className="mb-8 p-6 bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl border border-blue-200 dark:border-blue-700 shadow-lg">
            <div className="flex items-center space-x-4">
              <div className="flex items-center justify-center w-12 h-12 bg-white/20 rounded-full">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">
                  Hello, {getUserName()}! 👋
                </h2>
                <p className="text-blue-100 text-sm mt-1">
                  Welcome back! Discover new polls or create your own to engage with the community.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Header Section */}
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center mb-8 gap-4">
          <div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 to-gray-600 dark:from-white dark:to-gray-300 bg-clip-text text-transparent">
              Browse Polls
            </h1>
            <p className="text-gray-600 dark:text-gray-400 text-lg mt-2">
              Discover and participate in community polls
            </p>
          </div>
          <div className="flex gap-3">
            {/* Only show buttons when auth state is determined */}
            {!authLoading && (
              <>
                {user ? (
                  <Button asChild size="lg" className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white shadow-lg hover:shadow-xl transition-all duration-300">
                    <Link href="/polls/create" className="flex items-center space-x-2">
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                      </svg>
                      <span>Create Poll</span>
                    </Link>
                  </Button>
                ) : (
                  <div className="flex gap-3">
                    <Button asChild variant="outline" size="lg" className="border-2 hover:bg-gray-50 dark:hover:bg-gray-800">
                      <Link href="/login" className="flex items-center space-x-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                        </svg>
                        <span>Sign In</span>
                      </Link>
                    </Button>
                    <Button asChild size="lg" className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700">
                      <Link href="/signup" className="flex items-center space-x-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
                        </svg>
                        <span>Sign Up</span>
                      </Link>
                    </Button>
                  </div>
                )}
              </>
            )}
          </div>
        </div>

        {/* Enhanced Search Section */}
        <div className="bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm rounded-2xl p-6 mb-8 shadow-sm border border-gray-200/50 dark:border-gray-700/50">
          <div className="flex flex-col lg:flex-row gap-4">
            <div className="relative flex-1">
              <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <Input
                placeholder="Search polls by title or description..."
                className="pl-10 pr-4 py-3 text-lg bg-gray-50 dark:bg-gray-900 border-gray-200 dark:border-gray-700 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            <div className="flex gap-3">
              <Button variant="outline" className="px-6 py-3 rounded-xl border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800">
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.707A1 1 0 013 7V4z" />
                </svg>
                Filter
              </Button>
              <Button variant="outline" className="px-6 py-3 rounded-xl border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800">
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                </svg>
                Sort
              </Button>
            </div>
          </div>
        </div>

      {/* Enhanced Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-20">
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-600 to-purple-600 rounded-full mb-6 shadow-lg">
              <div className="w-8 h-8 border-4 border-white border-t-transparent rounded-full animate-spin"></div>
            </div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Loading Polls</h3>
            <p className="text-gray-600 dark:text-gray-400">Fetching the latest polls for you...</p>
          </div>
        </div>
      )}

      {/* Enhanced Error State */}
      {error && (
        <div className="text-center py-20">
          <div className="max-w-md mx-auto">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-red-100 dark:bg-red-900/20 rounded-full mb-6">
              <svg className="w-8 h-8 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Something went wrong</h3>
            <p className="text-red-600 dark:text-red-400 mb-6">{error}</p>
            <Button 
              onClick={() => window.location.reload()}
              className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
            >
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Try Again
            </Button>
          </div>
        </div>
      )}

      {/* Enhanced Polls Grid */}
      {!loading && !error && (
        <>
          <div className="grid gap-8">
            {filteredPolls.length > 0 ? (
              filteredPolls.map((poll) => (
                <Card key={poll.id} className="group hover:shadow-2xl hover:-translate-y-1 transition-all duration-300 border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm rounded-2xl overflow-hidden">
                  <CardHeader className="pb-4">
                    <div className="flex justify-between items-start gap-4">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-3">
                          <div className="flex items-center justify-center w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl text-white shadow-lg">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                            </svg>
                          </div>
                          <Badge 
                            variant={poll.status === "active" ? "default" : "secondary"}
                            className={`px-3 py-1 rounded-full text-xs font-medium ${
                              poll.status === "active" 
                                ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" 
                                : "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200"
                            }`}
                          >
                            {poll.status === "active" ? "🟢 Active" : "⏸️ Closed"}
                          </Badge>
                        </div>
                        <CardTitle className="text-xl font-bold text-gray-900 dark:text-white mb-2 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                          {poll.title}
                        </CardTitle>
                        {poll.description && (
                          <CardDescription className="text-gray-600 dark:text-gray-300 leading-relaxed">
                            {poll.description}
                          </CardDescription>
                        )}
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                        <div className="flex items-center space-x-1">
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                          </svg>
                          <span className="font-medium">{getVoteCount(poll)} votes</span>
                        </div>
                        <div className="flex items-center space-x-1">
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                          </svg>
                          <span>Created {formatDate(poll.created_at)}</span>
                        </div>
                      </div>
                      <div className="flex gap-3">
                        <Button asChild variant="outline" size="sm" className="rounded-xl border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                          <Link href={`/polls/${poll.id}`} className="flex items-center space-x-2">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={poll.status === "active" ? "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" : "M15 12a3 3 0 11-6 0 3 3 0 016 0z"} />
                            </svg>
                            <span>{poll.status === "active" ? "Vote Now" : "View Results"}</span>
                          </Link>
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="sm"
                          className="rounded-xl hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                          onClick={() => {
                            navigator.clipboard.writeText(`${window.location.origin}/polls/${poll.id}`);
                            alert('Poll link copied to clipboard!');
                          }}
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.367 2.684 3 3 0 00-5.367-2.684z" />
                          </svg>
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            ) : (
              <div className="text-center py-20">
                <div className="max-w-md mx-auto">
                  <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-gray-100 to-gray-200 dark:from-gray-800 dark:to-gray-700 rounded-full mb-6">
                    <svg className="w-10 h-10 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                  </div>
                  <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                    {searchTerm ? 'No polls found' : 'No polls yet'}
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400 mb-8">
                    {searchTerm 
                      ? 'Try adjusting your search terms or browse all available polls.' 
                      : 'Be the first to create a poll and start gathering opinions from the community.'}
                  </p>
                  {!authLoading && user && !searchTerm && (
                    <Button asChild size="lg" className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white shadow-lg">
                      <Link href="/polls/create" className="flex items-center space-x-2">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                        </svg>
                        <span>Create the First Poll</span>
                      </Link>
                    </Button>
                  )}
                  {!authLoading && !user && !searchTerm && (
                    <div className="space-y-4">
                      <p className="text-sm text-gray-500 dark:text-gray-400">Sign in to create and vote on polls</p>
                      <div className="flex gap-3 justify-center">
                        <Button asChild variant="outline" size="lg" className="border-2">
                          <Link href="/login" className="flex items-center space-x-2">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                            </svg>
                            <span>Sign In</span>
                          </Link>
                        </Button>
                        <Button asChild size="lg" className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700">
                          <Link href="/signup" className="flex items-center space-x-2">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
                            </svg>
                            <span>Sign Up</span>
                          </Link>
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
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
    </div>
  );
}
