export type GitHubConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

export interface GitHubConnection {
  connected: boolean;
  username: string | null;
  avatarUrl: string | null;
  status: GitHubConnectionStatus;
  errorMessage?: string | null;
}

export interface Project {
  id: string;
  repositoryId: string;
  repositoryName: string;
  repositoryFullName?: string;
  owner: string;
  private: boolean;
  defaultBranch: string;
  connectedAt: string;
  description?: string;
  htmlUrl?: string;
  localPath?: string;
}

export interface GitHubRepository {
  id: string;
  name: string;
  fullName: string;
  owner: string;
  private: boolean;
  description: string | null;
  defaultBranch: string;
  htmlUrl: string;
}
