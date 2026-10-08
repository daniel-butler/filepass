//! Revoke tests: the spec's Revoke check order (`DELETE /d/{id}/{urlname}`)
//! and the `revoke` metric event.

mod common;

use std::time::Duration;

use common::TestServer;
use filepass::obs::Recorder;
use filepass::store;

/// True if `recorder` holds a `name` event carrying every one of `labels`.
fn has_event(recorder: &Recorder, name: &str, labels: &[(&str, &str)]) -> bool {
    recorder.events().iter().any(|e| {
        e.name == name
            && labels
                .iter()
                .all(|(k, v)| e.labels.iter().any(|(ek, ev)| ek == k && ev == v))
    })
}

/// An uploaded file's download URL, split into its base and path segments.
struct Uploaded {
    base: String,
    id: String,
    urlname: String,
}

impl Uploaded {
    fn url(&self) -> String {
        format!("{}/d/{}/{}", self.base, self.id, self.urlname)
    }

    /// The same download URL, but with an unrelated, well-formed id.
    fn with_unknown_id(&self) -> String {
        format!("{}/d/{}/{}", self.base, store::new_id(), self.urlname)
    }
}

/// Uploads `body` as `agent` and returns its download URL, split apart.
async fn upload(server: &TestServer, body: Vec<u8>, agent: &str) -> Uploaded {
    let resp = server.put("/my_file.txt", body, Some(agent), None).await;
    assert_eq!(resp.status(), 201);
    let url = resp.text().await.expect("upload body").trim().to_string();
    let rest = url.split("/d/").nth(1).expect("download URL has /d/");
    let (id, urlname) = rest.split_once('/').expect("id/urlname");
    Uploaded {
        base: server.url.clone(),
        id: id.to_string(),
        urlname: urlname.to_string(),
    }
}

#[tokio::test]
async fn delete_order() {
    let server = TestServer::start().await;
    let file = upload(&server, b"abc".to_vec(), "planner").await;

    // No token: 401.
    let resp = server.delete(&file.url(), None).await;
    assert_eq!(resp.status(), 401);
    assert!(has_event(
        &server.metrics,
        "revoke",
        &[("agent", "-"), ("result", "unauthorized")]
    ));

    // Unknown id: 404.
    let resp = server
        .delete(&file.with_unknown_id(), Some("planner"))
        .await;
    assert_eq!(resp.status(), 404);
    assert!(has_event(
        &server.metrics,
        "revoke",
        &[("agent", "planner"), ("result", "not_found")]
    ));

    // Another agent's token: 403.
    let resp = server.delete(&file.url(), Some("builder")).await;
    assert_eq!(resp.status(), 403);
    assert!(has_event(
        &server.metrics,
        "revoke",
        &[("agent", "builder"), ("result", "forbidden")]
    ));

    // The uploader: 204, file revoked.
    let resp = server.delete(&file.url(), Some("planner")).await;
    assert_eq!(resp.status(), 204);
    assert!(has_event(
        &server.metrics,
        "revoke",
        &[("agent", "planner"), ("result", "ok")]
    ));

    // Already revoked: 410.
    let resp = server.delete(&file.url(), Some("planner")).await;
    assert_eq!(resp.status(), 410);
    assert!(has_event(
        &server.metrics,
        "revoke",
        &[("agent", "planner"), ("result", "gone")]
    ));

    // The download itself is gone too.
    let resp = server.get(&file.url()).await;
    assert_eq!(resp.status(), 410);
}

#[tokio::test]
async fn revoke_failure_is_500_link_dead() {
    let server = TestServer::start().await;
    let file = upload(&server, b"abc".to_vec(), "planner").await;

    server.state.store.set_fail_meta_writes(true);
    let resp = server.delete(&file.url(), Some("planner")).await;
    assert_eq!(resp.status(), 500);
    assert!(has_event(
        &server.metrics,
        "revoke",
        &[("agent", "planner"), ("result", "error")]
    ));

    // The link is dead in memory even though the disk write failed.
    let resp = server.get(&file.url()).await;
    assert_eq!(resp.status(), 410);

    server.state.store.set_fail_meta_writes(false);
    server.state.store.age_ending(Duration::from_secs(61));
    server.sweeper.run_once().await;

    let json_path = server
        .dir
        .path()
        .join("files")
        .join(format!("{}.json", file.id));
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(json_path).expect("json exists"))
            .expect("json parses");
    assert_eq!(raw["state"], "revoked");
}
