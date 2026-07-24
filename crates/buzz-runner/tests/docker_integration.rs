use std::collections::BTreeMap;

use buzz_runner::docker::{ContainerEngine, ContainerSpec, DockerCli};

#[tokio::test]
#[ignore = "requires a local Docker daemon"]
async fn resolves_a_locally_built_image_without_pulling_it() {
    let engine = DockerCli;
    let temporary = tempfile::tempdir().expect("temporary directory");
    std::fs::write(
        temporary.path().join("Dockerfile"),
        "FROM scratch\nLABEL com.buzz.test=local-image\n",
    )
    .expect("write Dockerfile");
    let tag = format!("buzz-runner-local-resolution-test:{}", std::process::id());
    let build = tokio::process::Command::new("docker")
        .args(["build", "--quiet", "--tag", &tag, "."])
        .current_dir(temporary.path())
        .output()
        .await
        .expect("build local image");
    assert!(
        build.status.success(),
        "docker build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let resolved = engine
        .resolve_image(&tag)
        .await
        .expect("resolve local image");
    let remove = tokio::process::Command::new("docker")
        .args(["image", "rm", &tag])
        .output()
        .await
        .expect("remove local image tag");
    assert!(remove.status.success());
    assert!(resolved.reference.starts_with("sha256:"));
    assert_eq!(resolved.reference, resolved.digest);
}

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
