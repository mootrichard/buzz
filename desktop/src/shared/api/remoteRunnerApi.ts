import type { RemoteRunner } from "@/shared/api/remoteRunnerTypes";

type InvokeTauri = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

export function createRemoteRunnerApi(invokeTauri: InvokeTauri) {
  return {
    listRemoteRunners: () => invokeTauri<RemoteRunner[]>("list_remote_runners"),
    getRemoteRunnerProtocolVersion: () =>
      invokeTauri<number | null>("get_remote_runner_protocol_version"),
    inspectRemoteRunnerPairingUri: (uri: string) =>
      invokeTauri<string>("inspect_remote_runner_pairing_uri", { uri }),
    pairRemoteRunner: (uri: string, confirmedSas: string, name?: string) =>
      invokeTauri<RemoteRunner>("pair_remote_runner", {
        uri,
        confirmedSas,
        name: name ?? null,
      }),
    revokeRemoteRunner: async (runnerPubkey: string) => {
      await invokeTauri<void>("revoke_remote_runner", { runnerPubkey });
    },
    purgeRemoteRunnerWorkspace: async (
      runnerPubkey: string,
      agentPubkey: string,
    ) => {
      await invokeTauri<void>("purge_remote_runner_workspace", {
        runnerPubkey,
        agentPubkey,
      });
    },
  };
}
