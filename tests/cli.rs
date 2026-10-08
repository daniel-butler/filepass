//! CLI tests: `filepass token` and `filepass serve --config` startup
//! failures. These drive the real binary (`env!("CARGO_BIN_EXE_filepass")`)
//! since they exercise process exit codes and stderr, not the library.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use filepass::auth::hash_token;

fn filepass() -> Command {
    Command::new(env!("CARGO_BIN_EXE_filepass"))
}

/// A fresh `0700` temp dir, as `Store::open` requires of `data_dir`.
fn private_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    dir
}

#[test]
fn token_command_prints_token_and_hash() {
    let output = filepass()
        .arg("token")
        .output()
        .expect("run filepass token");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let mut lines = stdout.lines();
    let token_line = lines.next().expect("token line");
    let hash_line = lines.next().expect("hash line");

    let token = token_line
        .strip_prefix("token: ")
        .expect("token line has `token: ` prefix");
    let hash = hash_line
        .strip_prefix("token_sha256: ")
        .expect("hash line has `token_sha256: ` prefix");

    assert!(token.starts_with("fp_"), "token was {token:?}");
    assert_eq!(hash.len(), 64, "hash was {hash:?}");
    assert_eq!(
        hash,
        hex::encode(hash_token(token)),
        "printed hash must be sha256(token)"
    );
}

#[test]
fn serve_rejects_bad_config() {
    let config_dir = private_tempdir();
    let config_path = config_dir.path().join("filepass.toml");
    fs::write(
        &config_path,
        r#"
            listen      = "127.0.0.1:0"
            public_url  = "http://localhost"
            data_dir    = "/tmp/filepass-cli-test-unused"
            upload_rate = 0
        "#,
    )
    .expect("write config");

    let output = filepass()
        .args([
            "serve",
            "--config",
            config_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("run filepass serve");

    assert!(
        !output.status.success(),
        "a zero upload_rate must not start the server"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("upload_rate"),
        "stderr must name the bad key; stderr was {stderr:?}"
    );
}

#[test]
fn serve_refuses_bad_data_dir_mode() {
    let data_dir = tempfile::tempdir().expect("create temp dir");
    fs::set_permissions(data_dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod 0755");

    let config_dir = private_tempdir();
    let config_path = config_dir.path().join("filepass.toml");
    fs::write(
        &config_path,
        format!(
            r#"
                listen     = "127.0.0.1:0"
                public_url = "http://localhost"
                data_dir   = "{}"
            "#,
            data_dir.path().display()
        ),
    )
    .expect("write config");

    let output = filepass()
        .args([
            "serve",
            "--config",
            config_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("run filepass serve");

    assert!(
        !output.status.success(),
        "a data_dir with mode 0755 must not start the server"
    );
}

#[test]
fn serve_names_a_missing_data_dir() {
    let config_dir = private_tempdir();
    let data_dir = config_dir.path().join("never-created");
    let config_path = config_dir.path().join("filepass.toml");
    fs::write(
        &config_path,
        format!(
            r#"
                listen     = "127.0.0.1:0"
                public_url = "http://localhost"
                data_dir   = "{}"
            "#,
            data_dir.display()
        ),
    )
    .expect("write config");

    let output = filepass()
        .args([
            "serve",
            "--config",
            config_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("run filepass serve");

    assert!(
        !output.status.success(),
        "a missing data_dir must not start the server"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&data_dir.display().to_string()),
        "stderr must name the missing data_dir; stderr was {stderr:?}"
    );
}

#[test]
fn version_flag_prints_the_crate_version() {
    let output = filepass()
        .arg("--version")
        .output()
        .expect("run filepass --version");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert_eq!(
        stdout.trim(),
        format!("filepass {}", env!("CARGO_PKG_VERSION"))
    );
}
