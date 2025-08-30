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
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-gray-900 dark:via-slate-900 dark:to-gray-800">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-20">
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-blue-600 rounded-2xl mb-8 shadow-lg">
            <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
            </svg>
          </div>
          <h1 className="text-5xl md:text-7xl font-bold text-gray-900 dark:text-white mb-6">
            ALX <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600">Polly</span>
          </h1>
          <p className="text-xl md:text-2xl text-gray-600 dark:text-gray-300 mb-12 max-w-3xl mx-auto leading-relaxed">
            Create engaging polls, gather meaningful insights, and make data-driven decisions with our powerful polling platform
          </p>
          <div className="flex flex-col sm:flex-row gap-6 justify-center mb-16">
            <Button asChild size="lg" className="text-lg px-8 py-6 rounded-full shadow-lg hover:shadow-xl transition-all duration-300">
              <Link href="/signup">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                </svg>
                Get Started Free
              </Link>
            </Button>
            <Button asChild variant="outline" size="lg" className="text-lg px-8 py-6 rounded-full border-2 hover:bg-white/10 transition-all duration-300">
              <Link href="/polls">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
                Explore Polls
              </Link>
            </Button>
          </div>
        </div>

                {/* Features Section */}
        <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          <Card className="group hover:shadow-2xl hover:-translate-y-2 transition-all duration-300 border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm">
            <CardHeader className="text-center pb-4">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-500 to-blue-600 rounded-2xl mb-4 mx-auto group-hover:scale-110 transition-transform duration-300">
                <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
              </div>
              <CardTitle className="text-xl font-bold text-gray-900 dark:text-white">
                Easy Poll Creation
              </CardTitle>
            </CardHeader>
            <CardContent className="text-center">
              <CardDescription className="text-gray-600 dark:text-gray-300 leading-relaxed">
                Create engaging polls in seconds with our intuitive drag-and-drop interface. Add multiple choice options, images, and customize settings effortlessly.
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="group hover:shadow-2xl hover:-translate-y-2 transition-all duration-300 border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm">
            <CardHeader className="text-center pb-4">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-green-500 to-emerald-600 rounded-2xl mb-4 mx-auto group-hover:scale-110 transition-transform duration-300">
                <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <CardTitle className="text-xl font-bold text-gray-900 dark:text-white">
                Real-time Analytics
              </CardTitle>
            </CardHeader>
            <CardContent className="text-center">
              <CardDescription className="text-gray-600 dark:text-gray-300 leading-relaxed">
                Watch votes pour in with live updates and beautiful visualizations. Get instant insights with detailed analytics and export-ready reports.
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="group hover:shadow-2xl hover:-translate-y-2 transition-all duration-300 border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm">
            <CardHeader className="text-center pb-4">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-purple-500 to-purple-600 rounded-2xl mb-4 mx-auto group-hover:scale-110 transition-transform duration-300">
                <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <CardTitle className="text-xl font-bold text-gray-900 dark:text-white">
                Secure & Private
              </CardTitle>
            </CardHeader>
            <CardContent className="text-center">
              <CardDescription className="text-gray-600 dark:text-gray-300 leading-relaxed">
                Enterprise-grade security with user authentication, spam protection, and privacy controls. Your data is safe and votes are always legitimate.
              </CardDescription>
            </CardContent>
          </Card>
        </div>

        {/* CTA Section */}
        <div className="text-center mt-20">
          <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-3xl p-12 max-w-4xl mx-auto text-white shadow-2xl">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Ready to Start Polling?</h2>
            <p className="text-xl mb-8 text-blue-100">Join thousands of users creating impactful polls every day</p>
            <Button asChild size="lg" variant="secondary" className="text-lg px-8 py-6 rounded-full shadow-lg hover:shadow-xl transition-all duration-300">
              <Link href="/signup">
                Create Your First Poll
                <svg className="w-5 h-5 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                </svg>
              </Link>
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
