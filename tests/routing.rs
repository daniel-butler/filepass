//! Routing tests: the spec's Routing table (method-vs-path matching,
//! `404` vs `405`), the exact `400` hint body for `PUT /`, and that the
//! fallback's bad-path handling still emits the `upload` metric.

mod common;

use common::TestServer;

#[tokio::test]
async fn healthz_ok() {
    let server = TestServer::start().await;

    let resp = server.get(&format!("{}/healthz", server.url)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "ok");
}

#[tokio::test]
async fn put_root_is_400_with_hint() {
    let server = TestServer::start().await;

    let resp = server.put("/", Vec::new(), Some("planner"), None).await;
    assert_eq!(resp.status(), 400);
    assert_eq!(
        resp.text().await.expect("body"),
        "name the file: PUT /<filename> (curl -T - needs an explicit name)"
    );
}

#[tokio::test]
async fn put_root_without_token_is_401() {
    let server = TestServer::start().await;

    let resp = server.put("/", Vec::new(), None, None).await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn put_deep_paths_400() {
    let server = TestServer::start().await;

    let resp = server.put("/a/b", Vec::new(), Some("planner"), None).await;
    assert_eq!(resp.status(), 400);

    let resp = server
        .put("/d/a/b", Vec::new(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn post_is_405() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/x", server.url))
        .send()
        .await
        .expect("POST should complete");
    assert_eq!(resp.status(), 405);
}

#[tokio::test]
async fn get_single_segment_is_405() {
    let server = TestServer::start().await;

    let resp = server.get(&format!("{}/favicon.ico", server.url)).await;
    assert_eq!(resp.status(), 405);
}

#[tokio::test]
async fn unknown_get_is_404() {
    let server = TestServer::start().await;

    let resp = server.get(&format!("{}/a/b/c", server.url)).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn fallback_emits_upload_metric() {
    let server = TestServer::start().await;

    let resp = server.put("/", Vec::new(), None, None).await;
    assert_eq!(resp.status(), 401);
    assert_eq!(
        server.metrics.count("upload", ("result", "unauthorized")),
        1
    );
    assert_eq!(server.metrics.count("upload", ("agent", "-")), 1);

    let resp = server.put("/", Vec::new(), Some("planner"), None).await;
    assert_eq!(resp.status(), 400);
    assert_eq!(server.metrics.count("upload", ("result", "bad_request")), 1);
}
