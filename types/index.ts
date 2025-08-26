export interface User {
  id: string;
  name: string;
  email: string;
  avatar?: string;
  createdAt: string;
  updatedAt: string;
}

export interface PollOption {
  id: string;
  text: string;
  votes: number;
  percentage?: number;
}

export interface Poll {
  id: string;
  title: string;
  description?: string;
  options: PollOption[];
  author: string;
  authorId: string;
  status: "active" | "closed" | "draft";
  totalVotes: number;
  category?: string;
  isAnonymous: boolean;
  allowMultipleVotes: boolean;
  endDate?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Vote {
  id: string;
  pollId: string;
  optionId: string;
  userId?: string;
  ipAddress?: string;
  createdAt: string;
}

export interface CreatePollRequest {
  title: string;
  description?: string;
  options: string[];
  category?: string;
  isAnonymous?: boolean;
  allowMultipleVotes?: boolean;
  endDate?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  name: string;
  email: string;
  password: string;
  confirmPassword: string;
}

export interface AuthResponse {
  user: User;
  token: string;
}

export interface ApiResponse<T = any> {
  data?: T;
  message?: string;
  error?: string;
  status: number;
}
