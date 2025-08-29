"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/contexts/auth-context";
import { pollService } from "@/lib/services/pollService";
import { PollWithOptions } from "@/types/database";

export default function DashboardPage() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [polls, setPolls] = useState<PollWithOptions[]>([]);
  const [pollsLoading, setPollsLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!loading && !user) {
      router.push("/login");
    }
  }, [user, loading, router]);

  useEffect(() => {
    const fetchUserPolls = async () => {
      if (!user) return;
      
      setPollsLoading(true);
      try {
        const result = await pollService.getUserPolls(user.id);
        if (result.error) {
          setError(result.error);
        } else {
          setPolls(result.polls);
        }
      } catch (err) {
        setError("Failed to load polls");
      } finally {
        setPollsLoading(false);
      }
    };

    if (user) {
      fetchUserPolls();
    }
  }, [user]);

  if (loading) {
    return (
      <div className="container mx-auto px-4 py-8 flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600 mx-auto mb-4"></div>
          <p>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return null; // Will redirect to login
  }

  const getUserDisplayName = () => {
    if (user.user_metadata?.full_name) {
      return user.user_metadata.full_name;
    }
    return user.email?.split("@")[0] || "User";
  };

  const getTotalVotes = (poll: PollWithOptions) => {
    // This would need to be calculated from poll_votes, for now showing mock data
    return Math.floor(Math.random() * 100) + 10;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString();
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Welcome back, {getUserDisplayName()}! Manage your polls and view analytics
          </p>
        </div>
        <Button asChild>
          <Link href="/polls/create">Create New Poll</Link>
        </Button>
      </div>

      {/* Stats Overview */}
      <div className="grid md:grid-cols-4 gap-6 mb-8">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Polls</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{polls.length}</div>
            <p className="text-xs text-gray-600">All time</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Active Polls</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {polls.filter(poll => poll.status === 'active').length}
            </div>
            <p className="text-xs text-gray-600">Currently open</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Draft Polls</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {polls.filter(poll => poll.status === 'draft').length}
            </div>
            <p className="text-xs text-gray-600">Unpublished</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Options</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {polls.reduce((acc, poll) => acc + poll.poll_options.length, 0)}
            </div>
            <p className="text-xs text-gray-600">Across all polls</p>
          </CardContent>
        </Card>
      </div>

      {/* Recent Polls */}
      <Card>
        <CardHeader>
          <CardTitle>Your Recent Polls</CardTitle>
          <CardDescription>
            Manage and view your latest polls
          </CardDescription>
        </CardHeader>
        <CardContent>
          {error && (
            <div className="p-3 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md dark:bg-red-900/20 dark:border-red-800 dark:text-red-400 mb-4">
              {error}
            </div>
          )}
          
          {pollsLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600"></div>
              <span className="ml-2">Loading your polls...</span>
            </div>
          ) : polls.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                You haven't created any polls yet.
              </p>
              <Button asChild>
                <Link href="/polls/create">Create Your First Poll</Link>
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {polls.map((poll) => (
                <div key={poll.id} className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="font-medium">{poll.title}</h3>
                      <Badge variant={poll.status === "active" ? "default" : poll.status === "draft" ? "secondary" : "outline"}>
                        {poll.status}
                      </Badge>
                    </div>
                    <p className="text-sm text-gray-600">
                      {poll.poll_options.length} options • Created {formatDate(poll.created_at)}
                    </p>
                    {poll.description && (
                      <p className="text-sm text-gray-500 mt-1">{poll.description}</p>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <Button asChild variant="outline" size="sm">
                      <Link href={`/polls/${poll.id}`}>View</Link>
                    </Button>
                    <Button variant="outline" size="sm">
                      Edit
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
