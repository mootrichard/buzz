use std::collections::BTreeMap;

use buzz_runner::docker::{ContainerEngine, ContainerSpec, DockerCli};

#[tokio::test]
#[ignore = "requires a local Docker daemon and network access"]
async fn creates_container_with_runner_security_contract() {
    let engine = DockerCli;
    let image = "alpine:3.20";
    let resolved = engine.resolve_image(image).await.expect("resolve image");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let workspace = temporary.path().join("workspace");
    let secrets = temporary.path().join("secrets");
    std::fs::create_dir_all(&workspace).expect("workspace");
    std::fs::create_dir_all(&secrets).expect("secrets");
    let name = format!("buzz-runner-integration-{}", std::process::id());
    let spec = ContainerSpec {
        name: name.clone(),
        image: image.into(),
        image_digest: resolved.digest,
        immutable_image: resolved.reference,
        workspace_dir: workspace,
        secrets_dir: secrets,
        cpu_limit: "2".into(),
        memory_limit: "4g".into(),
        labels: BTreeMap::from([
            ("com.buzz.runner".into(), "runner".into()),
            ("com.buzz.owner".into(), "owner".into()),
            ("com.buzz.agent".into(), "agent".into()),
            ("com.buzz.deployment-generation".into(), "1".into()),
            ("com.buzz.runtime-id".into(), "buzz-agent".into()),
        ]),
    };
    engine.create(&spec).await.expect("create container");
    let output = tokio::process::Command::new("docker")
        .args(["inspect", &name])
        .output()
        .await
        .expect("inspect container");
    engine.remove(&name).await.expect("remove container");
    assert!(output.status.success());
    let inspection: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("decode inspect");
    let container = &inspection[0];
    assert_eq!(container["HostConfig"]["ReadonlyRootfs"], true);
    assert_eq!(container["HostConfig"]["Privileged"], false);
    assert_eq!(container["HostConfig"]["NanoCpus"], 2_000_000_000u64);
    assert_eq!(container["HostConfig"]["Memory"], 4_294_967_296u64);
    assert!(container["HostConfig"]["CapDrop"]
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value == "ALL")));
    assert!(container["HostConfig"]["SecurityOpt"]
        .as_array()
        .is_some_and(|values| values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|entry| entry.contains("no-new-privileges"))
        })));
    assert!(container["Mounts"].as_array().is_some_and(|mounts| mounts
        .iter()
        .any(|mount| { mount["Destination"] == "/run/buzz-secrets" && mount["RW"] == false })));
    assert!(container["Mounts"].as_array().is_some_and(|mounts| mounts
        .iter()
        .any(|mount| { mount["Destination"] == "/workspace" && mount["RW"] == true })));
}
