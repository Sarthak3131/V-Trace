export interface User {
  id: string;
  name: string;
  email: string;
  role: 'user' | 'admin' | 'moderator';
}

export interface Content {
  _id: string;
  title: string;
  contentType: string;
  originalHash: string;
  status: string;
  isPublic: boolean;
  owner: { name: string };
  createdAt: string;
}

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  contents: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}
