export type RemoteRunner = {
  runnerPubkey: string;
  name: string;
  relayUrl: string;
  protocolVersion: number;
  runnerVersion: string | null;
  online: boolean;
  lastSeen: number | null;
  runtimes: string[];
  agentCount: number;
  retiredWorkspaces: string[];
};
