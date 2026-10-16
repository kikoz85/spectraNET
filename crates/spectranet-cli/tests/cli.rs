//! End-to-end tests of the `snet` binary against the mock source.

use assert_cmd::Command;
use predicates::prelude::*;

/// `snet` isolated from any snetd installed on this machine: tests that want a service start
/// their own and point `SNET_SOCKET` (or `--socket`) at it.
fn snet() -> Command {
    let mut cmd = Command::cargo_bin("snet").unwrap();
    cmd.env_remove("CLICOLOR_FORCE");
    cmd.env("SNET_SOCKET", "/nonexistent/snet-tests.sock");
    cmd
}

#[test]
fn list_prints_table_and_summary() {
    snet()
        .args(["--mock", "list", "--interval", "10ms"])
        .assert()
        .success()
        .stdout(predicate::str::contains("APPLICATION"))
        .stdout(predicate::str::contains("Google Chrome (2)"))
        .stdout(predicate::str::contains("svc_update"))
        .stdout(predicate::str::contains("6 applications (7 processes)"))
        // Not a terminal: no escape codes.
        .stdout(predicate::str::contains("\x1b[").not());
}

#[test]
fn list_json_is_valid_and_filtered() {
    let output = snet()
        .args(["--mock", "list", "-i", "10ms", "--json", "--flagged"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot["source"], "mock");
    let mut verdicts: Vec<_> = snapshot["processes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["verdict"].as_str().unwrap().to_owned())
        .collect();
    verdicts.sort();
    assert_eq!(verdicts, ["alert", "warn"]);
}

#[test]
fn watch_json_emits_one_line_per_sample() {
    let output = snet()
        .args(["--mock", "watch", "-i", "10ms", "--count", "3", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let lines: Vec<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), 3);
    for line in lines {
        serde_json::from_str::<serde_json::Value>(&line).unwrap();
    }
}

#[test]
fn color_always_forces_escape_codes() {
    snet()
        .args(["--mock", "--color", "always", "list", "-i", "10ms"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b["));
}

#[test]
fn invalid_interval_is_a_usage_error() {
    snet()
        .args(["--mock", "list", "--interval", "soon"])
        .assert()
        .code(2);
}

#[test]
fn completions_are_generated() {
    snet()
        .args(["generate", "completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef snet"));
}

#[test]
fn by_process_lists_helpers_separately() {
    snet()
        .args(["--mock", "list", "-i", "10ms", "--by-process"])
        .assert()
        .success()
        .stdout(predicate::str::contains("7 applications"))
        .stdout(predicate::str::contains("Google Chrome (2)").not());
}

#[test]
fn json_carries_application_membership() {
    let output = snet()
        .args(["--mock", "list", "-i", "10ms", "--json", "--name", "chrome"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let processes = snapshot["processes"].as_array().unwrap();
    assert_eq!(processes.len(), 2);
    for p in processes {
        assert_eq!(p["process"]["app"]["name"], "Google Chrome");
        assert_eq!(
            p["process"]["app"]["path"],
            "/Applications/Google Chrome.app"
        );
    }
    let mains: Vec<_> = processes
        .iter()
        .map(|p| p["process"]["app"]["main"].as_bool().unwrap())
        .collect();
    assert_eq!(mains, [true, false]);
}

/// Real end-to-end check on macOS: this test process moves a known amount of data over a
/// loopback connection while `snet` watches it, and `snet` must attribute it to our PID.
#[cfg(target_os = "macos")]
#[test]
fn live_list_reports_traffic_of_a_known_process() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut sink = vec![0u8; 64 * 1024];
        while conn.read(&mut sink).map(|n| n > 0).unwrap_or(false) {}
    });
    let mut client = TcpStream::connect(addr).unwrap();
    // Keep sending at roughly 1 MiB/s for the whole sampling window.
    let sender = thread::spawn(move || {
        let chunk = vec![1u8; 64 * 1024];
        for _ in 0..40 {
            client.write_all(&chunk).unwrap();
            thread::sleep(Duration::from_millis(60));
        }
    });

    let pid = std::process::id().to_string();
    let output = snet()
        .args(["list", "--json", "-i", "1s", "--pid", &pid])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    sender.join().unwrap();
    server.join().unwrap();

    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot["source"], "macos");
    let processes = snapshot["processes"].as_array().unwrap();
    assert_eq!(processes.len(), 1, "exactly our process");
    let flows = processes[0]["flows"].as_array().unwrap();
    let ours = flows
        .iter()
        .find(|f| f["remote"] == addr.to_string())
        .expect("the client connection is listed");
    let tx_rate = ours["tx_rate"].as_u64().unwrap();
    // ~1 MiB/s expected; allow wide margin for scheduling jitter on busy machines.
    assert!(
        tx_rate > 300 * 1024 && tx_rate < 3 * 1024 * 1024,
        "tx_rate = {tx_rate}"
    );
}

#[test]
fn numeric_hides_hostnames() {
    snet()
        .args(["--mock", "list", "-c", "-i", "10ms"])
        .assert()
        .success()
        .stdout(predicate::str::contains("www.google.com:443"));
    snet()
        .args(["--mock", "-n", "list", "-c", "-i", "10ms"])
        .assert()
        .success()
        .stdout(predicate::str::contains("142.250.180.206:443"))
        .stdout(predicate::str::contains("www.google.com").not());
}

/// Without capture rights, live listing still works and explains why hostnames are missing;
/// with -n the explanation is not needed and must not appear.
#[cfg(target_os = "macos")]
#[test]
fn live_without_root_explains_missing_hostnames() {
    // Only meaningful where packet capture is actually forbidden to us (not root, no
    // ChmodBPF-style group access).
    let denied = std::fs::File::open("/dev/bpf0")
        .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
    if !denied {
        return;
    }
    snet()
        .args(["list", "-i", "100ms"])
        .assert()
        .success()
        .stderr(predicate::str::contains("needs root"));
    snet()
        .args(["-n", "list", "-i", "100ms"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty());
}

/// A real snetd service (mock traffic) on a private socket, for the duration of a test.
struct Service {
    socket: std::path::PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Service {
    fn start() -> Self {
        use spectranet_daemon::service::{Config, run};
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let socket = dir.path().join("snetd.sock");
        #[cfg(windows)]
        let socket = {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            std::path::PathBuf::from(format!(
                r"\\.\pipe\snet-cli-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
        };
        let config = Config {
            socket,
            database: dir.path().join("usage.sqlite"),
            interval: std::time::Duration::from_millis(100),
            flush_every: std::time::Duration::from_millis(300),
            socket_group: None,
            feeds_dir: dir.path().join("feeds"),
            update_feeds: false,
            policy: spectranet_daemon::actions::Policy::default(),
            metrics: None,
            category_updates: false,
            feeds_disabled: Vec::new(),
            history_days: 0,
            settings: Default::default(),
            check_targets: Vec::new(),
            latency_watch_minutes: 0,
        };
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = {
            let (config, stop) = (config.clone(), stop.clone());
            std::thread::spawn(move || {
                run(
                    &config,
                    Box::new(spectranet_capture::mock::MockSource::new(4)),
                    &stop,
                )
                .unwrap();
            })
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while spectranet_proto::Client::connect(&config.socket, std::time::Duration::from_secs(1))
            .is_err()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "service did not start"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Self {
            socket: config.socket,
            stop,
            handle: Some(handle),
            _dir: dir,
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn list_uses_the_service_without_waiting() {
    let service = Service::start();
    let begun = std::time::Instant::now();
    let output = snet()
        .args(["list", "--json", "-i", "10s"])
        .env("SNET_SOCKET", &service.socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        begun.elapsed() < std::time::Duration::from_secs(3),
        "no 10 s warm-up with snetd"
    );
    let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot["source"], "mock", "data came from the service");
}

#[test]
fn watch_and_numeric_work_through_the_service() {
    let service = Service::start();
    snet()
        .args(["--socket"])
        .arg(&service.socket)
        .args(["-n", "watch", "-c", "-i", "100ms", "--count", "2"])
        .assert()
        .success()
        .stdout(predicate::str::contains("142.250.180.206:443"))
        .stdout(predicate::str::contains("www.google.com").not());
}

#[test]
fn status_and_history_through_the_service() {
    let service = Service::start();
    snet()
        .arg("status")
        .env("SNET_SOCKET", &service.socket)
        .assert()
        .success()
        .stdout(predicate::str::contains("is running"))
        .stdout(predicate::str::contains("source:   mock"));

    std::thread::sleep(std::time::Duration::from_millis(500));
    snet()
        .args(["history", "--days", "7"])
        .env("SNET_SOCKET", &service.socket)
        .assert()
        .success()
        .stdout(predicate::str::contains("Data usage, last 7 days"))
        .stdout(predicate::str::contains("Google Chrome"))
        .stdout(predicate::str::contains("6 applications"));

    let output = snet()
        .args(["history", "--json"])
        .env("SNET_SOCKET", &service.socket)
        .output()
        .unwrap();
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|r| r["rx"].as_u64().unwrap() > 0)
    );
}

#[cfg(unix)]
#[test]
fn service_commands_report_when_snetd_is_absent() {
    let missing = std::env::temp_dir().join(format!("snet-absent-{}.sock", std::process::id()));
    for cmd in ["status", "history"] {
        snet()
            .arg(cmd)
            .env("SNET_SOCKET", &missing)
            .assert()
            .code(69)
            .stderr(predicate::str::contains("sudo snetd install"));
    }
    // Monitoring still works without the service.
    snet()
        .args(["--mock", "list", "-i", "10ms"])
        .env("SNET_SOCKET", &missing)
        .assert()
        .success();
}

#[test]
fn history_rejects_absurd_ranges() {
    snet().args(["history", "--days", "0"]).assert().code(2);
    snet()
        .args(["history", "--days", "100000"])
        .assert()
        .code(2);
}

#[test]
fn alerts_through_the_service() {
    let service = Service::start();
    // The mock workload includes unencrypted HTTP from svc_update to a public address.
    std::thread::sleep(std::time::Duration::from_millis(400));
    snet()
        .args(["alerts", "--since", "1h"])
        .env("SNET_SOCKET", &service.socket)
        .assert()
        .success()
        .stdout(predicate::str::contains("svc_update"))
        .stdout(predicate::str::contains("unencrypted HTTP"));
    let output = snet()
        .args(["alerts", "--json", "--limit", "1"])
        .env("SNET_SOCKET", &service.socket)
        .output()
        .unwrap();
    let events: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(events.as_array().unwrap().len(), 1);
    snet()
        .arg("status")
        .env("SNET_SOCKET", &service.socket)
        .assert()
        .success()
        .stdout(predicate::str::contains("alerts:"))
        .stdout(predicate::str::contains("Spamhaus DROP"))
        .stdout(predicate::str::contains("not downloaded yet"));
}

#[test]
fn record_then_analyze_with_mock_traffic() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("session.jsonl");
    snet()
        .args([
            "--mock",
            "record",
            "--name",
            "svc_update",
            "--duration",
            "400ms",
            "-i",
            "50ms",
            "-o",
        ])
        .arg(&file)
        .assert()
        .success()
        .stderr(predicate::str::contains("saved"))
        .stderr(predicate::str::contains("snet analyze"));

    let text = std::fs::read_to_string(&file).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["type"], "header");
    assert_eq!(lines.last().unwrap()["type"], "footer");
    let samples: Vec<_> = lines.iter().filter(|l| l["type"] == "sample").collect();
    assert!(samples.len() >= 3, "{} samples", samples.len());
    for s in &samples {
        let procs = s["snapshot"]["processes"].as_array().unwrap();
        assert!(
            procs.iter().all(|p| p["process"]["name"] == "svc_update"),
            "filter applied"
        );
    }

    snet()
        .arg("analyze")
        .arg(&file)
        .assert()
        .success()
        .stdout(predicate::str::contains("FINDINGS"))
        .stdout(predicate::str::contains("ALERT"))
        .stdout(predicate::str::contains("Tor exit node"))
        .stdout(predicate::str::contains("unencrypted HTTP"))
        .stdout(predicate::str::contains("185.220.101.5:80"));

    let json = snet()
        .args(["analyze", "--json"])
        .arg(&file)
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["truncated"], false);
    assert_eq!(report["apps"][0]["name"], "svc_update");
}

#[test]
fn record_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("exists.jsonl");
    std::fs::write(&file, "keep me").unwrap();
    snet()
        .args(["--mock", "record", "--duration", "100ms", "-o"])
        .arg(&file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("never overwritten"));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep me");
}

#[test]
fn record_through_the_service_and_interrupted_files() {
    let service = Service::start();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("svc.jsonl");
    snet()
        .args(["record", "--name", "chrome", "--duration", "700ms", "-o"])
        .arg(&file)
        .env("SNET_SOCKET", &service.socket)
        .assert()
        .success();
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("\"source\":\"snetd\""));
    let stamps: Vec<u64> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "sample")
        .map(|v| v["snapshot"]["timestamp_ms"].as_u64().unwrap())
        .collect();
    assert!(stamps.len() >= 4, "{stamps:?}");
    assert!(
        stamps.windows(2).all(|w| w[1] > w[0]),
        "each service sample exactly once"
    );

    // Cut the file mid-line, as a crash would.
    let cut = &text[..text.len() - 40];
    let broken = dir.path().join("broken.jsonl");
    std::fs::write(&broken, cut).unwrap();
    snet()
        .arg("analyze")
        .arg(&broken)
        .assert()
        .success()
        .stdout(predicate::str::contains("interrupted"))
        .stdout(predicate::str::contains("unreadable lines were skipped"));
}

#[test]
fn analyze_reports_missing_files() {
    snet()
        .args(["analyze", "/nonexistent/x.jsonl"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("opening"));
}
