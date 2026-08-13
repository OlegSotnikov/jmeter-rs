// SPDX-License-Identifier: Apache-2.0
//! Small public-API acceptance contracts for the Java-free standalone path.
//!
//! Compatibility slice: `ELEM-001`, `JTL-001..005`, `TEST-001`, `TEST-005`.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "the fixture setup and assertions are explicit test boundaries"
)]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};

use jmeter_rs::{LaunchEnvironment, RunCategory, execute_invocation, parse};
use jmeter_rs_results::{SampleSaveConfiguration, read_csv};

static NEXT_FIXTURE_ROOT: AtomicUsize = AtomicUsize::new(0);

/// One exact loopback listener owned by this test.  The listener is
/// nonblocking so a failed admission can signal it and join without a sleep
/// or a broad process cleanup operation.
struct LoopbackServer {
    address: SocketAddr,
    accepted: Arc<AtomicBool>,
    stop: SyncSender<()>,
    join: Option<JoinHandle<Result<Vec<u8>, String>>>,
}

impl LoopbackServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
        listener
            .set_nonblocking(true)
            .expect("make loopback fixture nonblocking");
        let address = listener.local_addr().expect("loopback fixture address");
        let (stop, stop_receiver) = mpsc::sync_channel(1);
        let accepted = Arc::new(AtomicBool::new(false));
        let accepted_by_server = Arc::clone(&accepted);
        let join =
            thread::spawn(move || serve_loopback(listener, stop_receiver, accepted_by_server));
        Self {
            address,
            accepted,
            stop,
            join: Some(join),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn connection_observed(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.accepted)
    }

    fn finish(mut self) -> Result<Vec<u8>, String> {
        let join = self.join.take().expect("loopback fixture join handle");
        join.join()
            .map_err(|_| "loopback fixture thread panicked".to_owned())?
    }

    fn stop(mut self) -> Result<Vec<u8>, String> {
        let _ = self.stop.send(());
        self.finish()
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn serve_loopback(
    listener: TcpListener,
    stop_receiver: Receiver<()>,
    accepted: Arc<AtomicBool>,
) -> Result<Vec<u8>, String> {
    loop {
        match stop_receiver.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => {
                return Err("loopback fixture stopped before a request".to_owned());
            }
            Err(TryRecvError::Empty) => {}
        }

        match listener.accept() {
            Ok((mut stream, _peer)) => {
                accepted.store(true, Ordering::Release);
                return serve_connection(&mut stream, &stop_receiver);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::yield_now();
            }
            Err(error) => return Err(format!("loopback accept failed: {error}")),
        }
    }
}

fn serve_connection(
    stream: &mut TcpStream,
    stop_receiver: &Receiver<()>,
) -> Result<Vec<u8>, String> {
    stream
        .set_nonblocking(true)
        .map_err(|error| format!("loopback stream nonblocking setup failed: {error}"))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        match stop_receiver.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => {
                return Err("loopback fixture stopped while reading".to_owned());
            }
            Err(TryRecvError::Empty) => {}
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Err("loopback client closed before request headers".to_owned()),
            Ok(read) => {
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                if request.len() > 16 * 1024 {
                    return Err("loopback request headers exceeded the fixture bound".to_owned());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::yield_now();
            }
            Err(error) => return Err(format!("loopback request read failed: {error}")),
        }
    }
    stream
        .set_nonblocking(false)
        .map_err(|error| format!("loopback stream blocking setup failed: {error}"))?;
    if !request.starts_with(b"GET /health HTTP/1.1\r\n") {
        return Err("loopback fixture received an unexpected request".to_owned());
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnative-ok")
        .map_err(|error| format!("loopback response write failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("loopback response flush failed: {error}"))?;
    Ok(request)
}

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn new(label: &str) -> Self {
        let serial = NEXT_FIXTURE_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{label}-{}-{serial}", std::process::id()));
        fs::create_dir(&path).expect("create private fixture root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn native_http_plan(port: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3">
  <hashTree>
    <TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="standalone plan" enabled="true">
      <boolProp name="TestPlan.functional_mode">false</boolProp>
      <boolProp name="TestPlan.serialize_threadgroups">false</boolProp>
      <elementProp name="TestPlan.user_defined_variables" elementType="Arguments" guiclass="ArgumentsPanel" testclass="Arguments" testname="variables" enabled="true">
        <collectionProp name="Arguments.arguments"/>
      </elementProp>
      <collectionProp name="TestPlan.thread_groups"/>
      <stringProp name="TestPlan.user_define_classpath"></stringProp>
    </TestPlan>
    <hashTree>
      <ThreadGroup guiclass="ThreadGroupGui" testclass="ThreadGroup" testname="one user" enabled="true">
        <stringProp name="ThreadGroup.on_sample_error">continue</stringProp>
        <elementProp name="ThreadGroup.main_controller" elementType="LoopController" guiclass="LoopControlPanel" testclass="LoopController" testname="one loop" enabled="true">
          <boolProp name="LoopController.continue_forever">false</boolProp>
          <stringProp name="LoopController.loops">1</stringProp>
        </elementProp>
        <stringProp name="ThreadGroup.num_threads">1</stringProp>
        <stringProp name="ThreadGroup.ramp_time">0</stringProp>
        <longProp name="ThreadGroup.start_time">0</longProp>
        <longProp name="ThreadGroup.end_time">0</longProp>
        <boolProp name="ThreadGroup.scheduler">false</boolProp>
        <stringProp name="ThreadGroup.duration"></stringProp>
        <stringProp name="ThreadGroup.delay"></stringProp>
        <boolProp name="ThreadGroup.same_user_on_next_iteration">true</boolProp>
      </ThreadGroup>
      <hashTree>
        <HTTPSamplerProxy guiclass="HttpTestSampleGui" testclass="HTTPSamplerProxy" testname="native-loopback" enabled="true">
          <stringProp name="HTTPSampler.domain">127.0.0.1</stringProp>
          <intProp name="HTTPSampler.port">{port}</intProp>
          <stringProp name="HTTPSampler.protocol">http</stringProp>
          <stringProp name="HTTPSampler.path">/health</stringProp>
          <stringProp name="HTTPSampler.method">GET</stringProp>
          <boolProp name="HTTPSampler.follow_redirects">false</boolProp>
          <boolProp name="HTTPSampler.auto_redirects">false</boolProp>
          <boolProp name="HTTPSampler.use_keepalive">true</boolProp>
          <stringProp name="HTTPSampler.implementation">HttpClient4</stringProp>
        </HTTPSamplerProxy>
        <hashTree/>
      </hashTree>
    </hashTree>
  </hashTree>
</jmeterTestPlan>
"#
    )
}

#[test]
fn standalone_native_http_publishes_finalized_jtl_and_counts_samples() {
    let server = LoopbackServer::start();
    let root = FixtureRoot::new("jmeter-rs-standalone-http");
    fs::write(
        root.path().join("plan.jmx"),
        native_http_plan(server.port()),
    )
    .expect("write standalone HTTP plan");

    let invocation = parse([
        "-n",
        "-t",
        "plan.jmx",
        "-Jjmeter-rs.http.capability=http.native/1",
        "-l",
        "results.jtl",
    ])
    .expect("parse native standalone invocation");
    let launch = LaunchEnvironment::new(root.path())
        .with_locale("en-US")
        .with_timezone("UTC")
        .with_now_millis(0);
    let outcome = execute_invocation(&invocation, &launch).expect("native HTTP run succeeds");
    let request = server.finish().expect("loopback request is served");
    assert!(request.starts_with(b"GET /health HTTP/1.1\r\n"));

    assert_eq!(outcome.category, RunCategory::Normal);
    assert_eq!(outcome.samples, 1);
    assert_eq!(outcome.sample_failures, 0);
    let result_path = root.path().join("results.jtl");
    assert_eq!(outcome.result_file.as_deref(), Some(result_path.as_path()));
    let bytes = fs::read(&result_path).expect("read published JTL");
    assert!(
        !bytes.is_empty(),
        "published JTL must not be an empty artifact"
    );

    let events = read_csv(bytes.as_slice(), SampleSaveConfiguration::default())
        .expect("decode published JTL");
    assert_eq!(events.len(), 1);
    let result = events[0].result();
    assert_eq!(result.label(), "native-loopback");
    assert_eq!(result.response_code(), Some("200"));
    assert!(result.is_successful());

    let staging_entries = fs::read_dir(root.path())
        .expect("read private fixture root")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".jmeter-rs-result-")
        })
        .count();
    assert_eq!(
        staging_entries, 0,
        "finalization must remove private staging"
    );
}

#[test]
fn non_native_http_requirement_is_rejected_before_outputs_or_network() {
    let server = LoopbackServer::start();
    let connection_observed = server.connection_observed();
    let root = FixtureRoot::new("jmeter-rs-standalone-admission");
    fs::write(
        root.path().join("plan.jmx"),
        native_http_plan(server.port()),
    )
    .expect("write non-native HTTP plan");

    let invocation = parse([
        "-n",
        "-t",
        "plan.jmx",
        "-l",
        "results.jtl",
        "-j",
        "run.log",
        "-e",
        "-o",
        "report",
    ])
    .expect("parse non-native invocation");
    let error = execute_invocation(
        &invocation,
        &LaunchEnvironment::new(root.path())
            .with_locale("en-US")
            .with_timezone("UTC")
            .with_now_millis(0),
    )
    .expect_err("preserved JMeter HTTP provider must be unavailable without the selector");
    assert_eq!(error.code(), "http.compatibility-pack-required");
    assert!(!root.path().join("results.jtl").exists());
    assert!(!root.path().join("run.log").exists());
    assert!(!root.path().join("report").exists());
    assert!(!root.path().join("jmeter.log").exists());
    let stopped = server.stop();
    assert!(
        stopped.is_err(),
        "fixture should stop without serving a request"
    );
    assert!(!connection_observed.load(Ordering::Acquire));
}
