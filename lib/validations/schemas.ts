import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const registerSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters"),
  email: z.string().email("Please enter a valid email address"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

export const createPollSchema = z.object({
  title: z.string().min(1, "Poll title is required").max(200, "Title too long"),
  description: z.string().max(500, "Description too long").optional(),
  options: z.array(z.string().min(1, "Option cannot be empty"))
    .min(2, "At least 2 options required")
    .max(10, "Maximum 10 options allowed"),
  category: z.string().optional(),
  isAnonymous: z.boolean().default(false),
  allowMultipleVotes: z.boolean().default(false),
  endDate: z.string().optional(),
});

export const voteSchema = z.object({
  optionId: z.string().min(1, "Option selection is required"),
  pollId: z.string().min(1, "Poll ID is required"),
});

export type LoginFormData = z.infer<typeof loginSchema>;
export type RegisterFormData = z.infer<typeof registerSchema>;
export type CreatePollFormData = z.infer<typeof createPollSchema>;
export type VoteFormData = z.infer<typeof voteSchema>;
