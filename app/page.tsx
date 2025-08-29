"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/contexts/auth-context";

export default function Home() {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    // Redirect authenticated users to polls page
    if (!loading && user) {
      router.push("/polls");
    }
  }, [user, loading, router]);
  // Show loading state while checking authentication
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600 mx-auto mb-4"></div>
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-12">
          <h1 className="text-4xl md:text-6xl font-bold text-gray-900 dark:text-white mb-4">
            ALX <span className="text-blue-600">Polly</span>
          </h1>
          <p className="text-xl text-gray-600 dark:text-gray-300 mb-8">
            Create, share, and participate in polls with ease
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button asChild size="lg">
              <Link href="/signup">Get Started</Link>
            </Button>
            <Button asChild variant="outline" size="lg">
              <Link href="/polls">Browse Polls</Link>
            </Button>
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                🗳️ Easy Polling
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Create polls in seconds with our intuitive interface. Add multiple choice options and customize your poll settings.
              </CardDescription>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                📊 Real-time Results
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Watch votes come in live with beautiful charts and analytics. See results update in real-time as people vote.
              </CardDescription>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                🔐 Secure Voting
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Ensure fair voting with user authentication and anti-spam measures. Every vote counts and is protected.
              </CardDescription>
            </CardContent>
          </Card>
        </div>

        <div className="text-center mt-16">
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Ready to get started?
          </p>
          <Button asChild>
            <Link href="/signup">Sign Up Now</Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
