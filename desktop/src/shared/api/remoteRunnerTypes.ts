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

export type ManagedAgentBackend =
  | { type: "local" }
  | { type: "provider"; id: string; config: Record<string, unknown> }
  | { type: "runner"; runner_pubkey: string };

export type RemoteManagedAgentState = {
  /** Paired runner identity; absent for local and legacy provider agents. */
  runnerId: string | null;
  desiredGeneration: number | null;
  observedGeneration: number | null;
  /** Runner/container state, deliberately separate from relay presence. */
  deploymentState: string | null;
  lastRunnerError: string | null;
};
