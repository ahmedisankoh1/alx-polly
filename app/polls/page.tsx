import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";

// Mock data - replace with real data fetching
const mockPolls = [
  {
    id: "1",
    title: "What's your favorite programming language?",
    description: "Help us understand the community preferences",
    author: "John Doe",
    status: "active",
    votes: 127,
    createdAt: "2025-08-20",
    category: "Technology",
  },
  {
    id: "2", 
    title: "Best time for team meetings?",
    description: "Finding the optimal meeting schedule for our team",
    author: "Jane Smith",
    status: "active",
    votes: 45,
    createdAt: "2025-08-18",
    category: "Work",
  },
  {
    id: "3",
    title: "Which framework should we use for the next project?",
    description: "Technical decision for our upcoming development project",
    author: "Mike Johnson",
    status: "closed",
    votes: 89,
    createdAt: "2025-08-22",
    category: "Technology",
  },
  {
    id: "4",
    title: "Preferred lunch location for company event?",
    description: "Planning our next team lunch gathering",
    author: "Sarah Wilson",
    status: "active",
    votes: 23,
    createdAt: "2025-08-25",
    category: "Social",
  },
];

export default function PollsPage() {
  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold">All Polls</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Discover and participate in community polls
          </p>
        </div>
        <Button asChild>
          <Link href="/polls/create">Create Poll</Link>
        </Button>
      </div>

      {/* Search and Filters */}
      <div className="flex gap-4 mb-8">
        <Input
          placeholder="Search polls..."
          className="max-w-sm"
        />
        <Button variant="outline">Filter</Button>
        <Button variant="outline">Sort</Button>
      </div>

      {/* Polls Grid */}
      <div className="grid gap-6">
        {mockPolls.map((poll) => (
          <Card key={poll.id} className="hover:shadow-md transition-shadow">
            <CardHeader>
              <div className="flex justify-between items-start mb-2">
                <div className="flex-1">
                  <CardTitle className="mb-2">{poll.title}</CardTitle>
                  <CardDescription>{poll.description}</CardDescription>
                </div>
                <Badge variant={poll.status === "active" ? "default" : "secondary"}>
                  {poll.status}
                </Badge>
              </div>
              <div className="flex items-center justify-between text-sm text-gray-600">
                <span>By {poll.author}</span>
                <span>{poll.category}</span>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-sm text-gray-600">
                  {poll.votes} votes • Created {poll.createdAt}
                </div>
                <div className="flex gap-2">
                  <Button asChild variant="outline" size="sm">
                    <Link href={`/polls/${poll.id}`}>
                      {poll.status === "active" ? "Vote" : "View Results"}
                    </Link>
                  </Button>
                  <Button variant="ghost" size="sm">
                    Share
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Load More */}
      <div className="text-center mt-8">
        <Button variant="outline">Load More Polls</Button>
      </div>
    </div>
  );
}
