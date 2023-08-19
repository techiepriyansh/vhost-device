// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod rxops;
mod rxqueue;
mod thread_backend;
mod txbuf;
mod vhu_vsock;
mod vhu_vsock_thread;
mod vsock_conn;

use std::{
    collections::{HashMap, VecDeque},
    convert::TryFrom,
    path::Path,
    process::exit,
    sync::{Arc, Mutex, RwLock},
    thread,
};

use crate::vhu_vsock::{CidMap, VhostUserVsockBackend, VsockConfig};
use clap::{Args, Parser};
use inotify::{EventMask, Inotify, WatchMask};
use log::{error, info, warn};
use serde::Deserialize;
use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

type ConfigMap = HashMap<u64, Arc<RwLock<VsockConfig>>>;
type JoinHandle = thread::JoinHandle<Result<(), BackendError>>;

const DEFAULT_GUEST_CID: u64 = 3;
const DEFAULT_TX_BUFFER_SIZE: u32 = 64 * 1024;
const DEFAULT_GROUP_NAME: &str = "default";

#[derive(Debug, ThisError)]
enum CliError {
    #[error("No arguments provided")]
    NoArgsProvided,
    #[error("Failed to parse configuration file")]
    ConfigParse,
}

#[derive(Debug, ThisError)]
enum VmArgsParseError {
    #[error("Bad argument")]
    BadArgument,
    #[error("Invalid key `{0}`")]
    InvalidKey(String),
    #[error("Unable to convert string to integer: {0}")]
    ParseInteger(std::num::ParseIntError),
    #[error("Required key `{0}` not found")]
    RequiredKeyNotFound(String),
}

#[derive(Debug, ThisError)]
enum BackendError {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_vsock::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
}

#[derive(Args, Clone, Debug)]
struct VsockParam {
    /// Context identifier of the guest which uniquely identifies the device for its lifetime.
    #[arg(
        long,
        default_value_t = DEFAULT_GUEST_CID,
        conflicts_with = "config",
        conflicts_with = "vm"
    )]
    guest_cid: u64,

    /// Unix socket to which a hypervisor connects to and sets up the control path with the device.
    #[arg(long, conflicts_with = "config", conflicts_with = "vm")]
    socket: String,

    /// Unix socket to which a host-side application connects to.
    #[arg(long, conflicts_with = "config", conflicts_with = "vm")]
    uds_path: String,

    /// The size of the buffer used for the TX virtqueue
    #[clap(long, default_value_t = DEFAULT_TX_BUFFER_SIZE, conflicts_with = "config", conflicts_with = "vm")]
    tx_buffer_size: u32,

    /// The list of group names to which the device belongs.
    /// A group is a set of devices that allow sibling communication between their guests.
    #[arg(
        long,
        default_value_t = String::from(DEFAULT_GROUP_NAME),
        conflicts_with = "config",
        conflicts_with = "vm",
        verbatim_doc_comment
    )]
    groups: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ConfigFileVsockParam {
    guest_cid: Option<u64>,
    socket: String,
    uds_path: String,
    tx_buffer_size: Option<u32>,
    groups: Option<String>,
}

#[derive(Debug, Clone)]
struct CliVsockConfig {
    vsock_configs: Vec<VsockConfig>,
    watched_config: Option<String>,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct VsockArgs {
    #[command(flatten)]
    param: Option<VsockParam>,

    /// Device parameters corresponding to a VM in the form of comma separated key=value pairs.
    /// The allowed keys are: guest_cid, socket, uds_path, tx_buffer_size and group.
    /// Example:
    ///   --vm guest-cid=3,socket=/tmp/vhost3.socket,uds-path=/tmp/vm3.vsock,tx-buffer-size=65536,groups=group1+group2
    /// Multiple instances of this argument can be provided to configure devices for multiple guests.
    #[arg(long, conflicts_with = "config", verbatim_doc_comment, value_parser = parse_vm_params)]
    vm: Option<Vec<VsockConfig>>,

    /// Load from a given configuration file
    #[arg(long)]
    config: Option<String>,

    /// Watch the configuration file for changes and update the configuration accordingly at runtime.
    /// This option is only valid when used with the `config` option.
    #[arg(long, requires = "config")]
    watch: bool,
}

fn parse_vm_params(s: &str) -> Result<VsockConfig, VmArgsParseError> {
    let mut guest_cid = None;
    let mut socket = None;
    let mut uds_path = None;
    let mut tx_buffer_size = None;
    let mut groups = None;

    for arg in s.trim().split(',') {
        let mut parts = arg.split('=');
        let key = parts.next().ok_or(VmArgsParseError::BadArgument)?;
        let val = parts.next().ok_or(VmArgsParseError::BadArgument)?;

        match key {
            "guest_cid" | "guest-cid" => {
                guest_cid = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }
            "socket" => socket = Some(val.to_string()),
            "uds_path" | "uds-path" => uds_path = Some(val.to_string()),
            "tx_buffer_size" | "tx-buffer-size" => {
                tx_buffer_size = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }
            "groups" => groups = Some(val.split('+').map(String::from).collect()),
            _ => return Err(VmArgsParseError::InvalidKey(key.to_string())),
        }
    }

    Ok(VsockConfig::new(
        guest_cid.unwrap_or(DEFAULT_GUEST_CID),
        socket.ok_or_else(|| VmArgsParseError::RequiredKeyNotFound("socket".to_string()))?,
        uds_path.ok_or_else(|| VmArgsParseError::RequiredKeyNotFound("uds-path".to_string()))?,
        tx_buffer_size.unwrap_or(DEFAULT_TX_BUFFER_SIZE),
        groups.unwrap_or(vec![DEFAULT_GROUP_NAME.to_string()]),
    ))
}

pub(crate) fn parse_config(config: &str) -> Result<Vec<VsockConfig>, CliError> {
    let b = config::Config::builder()
        .add_source(config::File::new(config, config::FileFormat::Yaml))
        .build();
    if let Ok(s) = b {
        let mut v = s.get::<Vec<ConfigFileVsockParam>>("vms").unwrap();
        if !v.is_empty() {
            let parsed: Vec<VsockConfig> = v
                .drain(..)
                .map(|p| {
                    VsockConfig::new(
                        p.guest_cid.unwrap_or(DEFAULT_GUEST_CID),
                        p.socket.trim().to_string(),
                        p.uds_path.trim().to_string(),
                        p.tx_buffer_size.unwrap_or(DEFAULT_TX_BUFFER_SIZE),
                        p.groups.map_or(vec![DEFAULT_GROUP_NAME.to_string()], |g| {
                            g.trim().split('+').map(String::from).collect()
                        }),
                    )
                })
                .collect();
            Ok(parsed)
        } else {
            Err(CliError::ConfigParse)
        }
    } else {
        Err(CliError::ConfigParse)
    }
}

impl CliVsockConfig {
    pub fn new(vsock_configs: Vec<VsockConfig>, watched_config: Option<String>) -> Self {
        Self {
            vsock_configs,
            watched_config,
        }
    }
}

impl TryFrom<VsockArgs> for CliVsockConfig {
    type Error = CliError;

    fn try_from(cmd_args: VsockArgs) -> Result<Self, CliError> {
        // we try to use the configuration first, if failed,  then fall back to the manual settings.
        match &cmd_args.config {
            Some(c) => parse_config(c).map(|v| {
                Self::new(
                    v,
                    if cmd_args.watch {
                        cmd_args.config
                    } else {
                        None
                    },
                )
            }),
            _ => match cmd_args.vm {
                Some(v) => Ok(Self::new(v, None)),
                _ => cmd_args.param.map_or(Err(CliError::NoArgsProvided), |p| {
                    Ok(CliVsockConfig::new(
                        vec![VsockConfig::new(
                            p.guest_cid,
                            p.socket.trim().to_string(),
                            p.uds_path.trim().to_string(),
                            p.tx_buffer_size,
                            p.groups.trim().split('+').map(String::from).collect(),
                        )],
                        None,
                    ))
                }),
            },
        }
    }
}

/// This is the public API through which an external program starts the
/// vhost-device-vsock backend server.
pub(crate) fn start_backend_server_thread(
    config: Arc<RwLock<VsockConfig>>,
    cid_map: Arc<RwLock<CidMap>>,
) -> Result<(), BackendError> {
    loop {
        let config = config.read().unwrap().clone();

        let backend = Arc::new(
            VhostUserVsockBackend::new(config.clone(), cid_map.clone())
                .map_err(BackendError::CouldNotCreateBackend)?,
        );

        let listener = Listener::new(config.get_socket_path(), true).unwrap();

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(BackendError::CouldNotCreateDaemon)?;

        let mut vring_workers = daemon.get_epoll_handlers();

        for thread in backend.threads.iter() {
            thread
                .lock()
                .unwrap()
                .set_vring_worker(Some(vring_workers.remove(0)));
        }

        daemon.start(listener).unwrap();

        match daemon.wait() {
            Ok(()) => {
                info!("Stopping cleanly");
            }
            Err(vhost_user_backend::Error::HandleRequest(
                vhost_user::Error::PartialMessage | vhost_user::Error::Disconnected,
            )) => {
                info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
            }
            Err(e) => {
                warn!("Error running daemon: {:?}", e);
            }
        }

        // No matter the result, we need to shut down the worker thread.
        backend.exit_event.write(1).unwrap();
    }
}

pub(crate) fn start_backend_server(
    config: &VsockConfig,
    config_map: &mut ConfigMap,
    cid_map: Arc<RwLock<CidMap>>,
    handles: Arc<Mutex<VecDeque<JoinHandle>>>,
) {
    let c = Arc::new(RwLock::new(config.clone()));
    let guest_cid = config.get_guest_cid();
    config_map.insert(guest_cid, c.clone());

    let handle = thread::Builder::new()
        .name(format!("vhu-vsock-cid-{}", guest_cid))
        .spawn(move || start_backend_server_thread(c, cid_map))
        .unwrap();
    handles.lock().unwrap().push_back(handle);
}

pub(crate) fn start_config_watcher(
    config_map: ConfigMap,
    cid_map: Arc<RwLock<CidMap>>,
    handles: Arc<Mutex<VecDeque<JoinHandle>>>,
    watched_config: String,
) -> Result<(), BackendError> {
    let mut config_map = config_map;

    let mut inotify = Inotify::init().unwrap(); // could be wrapped as a BackendError

    let watched_config_path = Path::new(&watched_config);
    let watched_config_file_name = watched_config_path.file_name().unwrap();
    let watched_config_dir = watched_config_path.parent().unwrap();

    inotify
        .watches()
        .add(watched_config_dir, WatchMask::MOVED_TO)
        .unwrap(); // could be wrapped as a BackendError

    let mut buffer = [0u8; 4096];
    loop {
        let events = inotify.read_events_blocking(&mut buffer).unwrap();

        for event in events {
            if event.mask.contains(EventMask::MOVED_TO) {
                let dest_file_name = event.name.unwrap();
                if dest_file_name == watched_config_file_name {
                    let vsock_configs = parse_config(&watched_config).unwrap(); // could be wrapped as a BackendError
                    for c in vsock_configs.iter() {
                        let guest_cid = c.get_guest_cid();
                        if config_map.contains_key(&guest_cid) {
                            let config = config_map.get(&guest_cid).unwrap();
                            let mut config = config.write().unwrap();
                            *config = c.clone();
                        } else {
                            start_backend_server(
                                c,
                                &mut config_map,
                                cid_map.clone(),
                                handles.clone(),
                            );
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn start_backend_servers(cli_vsock_config: &CliVsockConfig) -> Result<(), BackendError> {
    let mut config_map: ConfigMap = HashMap::new();
    let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));
    let handles = Arc::new(Mutex::new(VecDeque::new()));

    for c in cli_vsock_config.vsock_configs.iter() {
        start_backend_server(c, &mut config_map, cid_map.clone(), handles.clone());
    }

    if let Some(watched_config) = cli_vsock_config.watched_config.clone() {
        let handles2 = handles.clone();
        let handle = thread::Builder::new()
            .name("vhu-vsock-config-watcher".to_string())
            .spawn(move || start_config_watcher(config_map, cid_map, handles2, watched_config))
            .unwrap();
        handles.lock().unwrap().push_back(handle);
    }

    loop {
        if handles.lock().unwrap().is_empty() {
            break;
        }

        let handle = handles.lock().unwrap().pop_front().unwrap();
        handle.join().unwrap()?;
    }

    Ok(())
}

fn main() {
    env_logger::init();

    let cli_vsock_config = match CliVsockConfig::try_from(VsockArgs::parse()) {
        Ok(c) => c,
        Err(e) => {
            println!("Error parsing arguments: {}", e);
            return;
        }
    };

    if let Err(e) = start_backend_servers(&cli_vsock_config) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    impl VsockArgs {
        fn from_args(
            guest_cid: u64,
            socket: &str,
            uds_path: &str,
            tx_buffer_size: u32,
            groups: &str,
        ) -> Self {
            VsockArgs {
                param: Some(VsockParam {
                    guest_cid,
                    socket: socket.to_string(),
                    uds_path: uds_path.to_string(),
                    tx_buffer_size,
                    groups: groups.to_string(),
                }),
                vm: None,
                config: None,
                watch: false,
            }
        }
        fn from_file(config: &str) -> Self {
            VsockArgs {
                param: None,
                vm: None,
                config: Some(config.to_string()),
                watch: false,
            }
        }
    }

    #[test]
    fn test_vsock_config_setup() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_path = test_dir.path().join("vhost4.socket").display().to_string();
        let uds_path = test_dir.path().join("vm4.vsock").display().to_string();
        let args = VsockArgs::from_args(3, &socket_path, &uds_path, 64 * 1024, "group1");

        let cli_vsock_config = CliVsockConfig::try_from(args);
        assert!(cli_vsock_config.is_ok());

        let configs = cli_vsock_config.unwrap().vsock_configs;
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(config.get_socket_path(), socket_path);
        assert_eq!(config.get_uds_path(), uds_path);
        assert_eq!(config.get_tx_buffer_size(), 64 * 1024);
        assert_eq!(config.get_groups(), vec!["group1".to_string()]);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_config_setup_from_vm_args() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_paths = [
            test_dir.path().join("vhost3.socket"),
            test_dir.path().join("vhost4.socket"),
            test_dir.path().join("vhost5.socket"),
        ];
        let uds_paths = [
            test_dir.path().join("vm3.vsock"),
            test_dir.path().join("vm4.vsock"),
            test_dir.path().join("vm5.vsock"),
        ];
        let params = format!(
            "--vm socket={vhost3_socket},uds_path={vm3_vsock} \
             --vm socket={vhost4_socket},uds-path={vm4_vsock},guest-cid=4,tx_buffer_size=65536,groups=group1 \
             --vm groups=group2+group3,guest-cid=5,socket={vhost5_socket},uds_path={vm5_vsock},tx-buffer-size=32768",
            vhost3_socket = socket_paths[0].display(),
            vhost4_socket = socket_paths[1].display(),
            vhost5_socket = socket_paths[2].display(),
            vm3_vsock = uds_paths[0].display(),
            vm4_vsock = uds_paths[1].display(),
            vm5_vsock = uds_paths[2].display(),
        );

        let mut params = params.split_whitespace().collect::<Vec<&str>>();
        params.insert(0, ""); // to make the test binary name agnostic

        let args = VsockArgs::parse_from(params);

        let cli_vsock_config = CliVsockConfig::try_from(args);
        assert!(cli_vsock_config.is_ok());

        let configs = cli_vsock_config.unwrap().vsock_configs;
        assert_eq!(configs.len(), 3);

        let config = configs.get(0).unwrap();
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(
            config.get_socket_path(),
            socket_paths[0].display().to_string()
        );
        assert_eq!(config.get_uds_path(), uds_paths[0].display().to_string());
        assert_eq!(config.get_tx_buffer_size(), 65536);
        assert_eq!(config.get_groups(), vec![DEFAULT_GROUP_NAME.to_string()]);

        let config = configs.get(1).unwrap();
        assert_eq!(config.get_guest_cid(), 4);
        assert_eq!(
            config.get_socket_path(),
            socket_paths[1].display().to_string()
        );
        assert_eq!(config.get_uds_path(), uds_paths[1].display().to_string());
        assert_eq!(config.get_tx_buffer_size(), 65536);
        assert_eq!(config.get_groups(), vec!["group1".to_string()]);

        let config = configs.get(2).unwrap();
        assert_eq!(config.get_guest_cid(), 5);
        assert_eq!(
            config.get_socket_path(),
            socket_paths[2].display().to_string()
        );
        assert_eq!(config.get_uds_path(), uds_paths[2].display().to_string());
        assert_eq!(config.get_tx_buffer_size(), 32768);
        assert_eq!(
            config.get_groups(),
            vec!["group2".to_string(), "group3".to_string()]
        );

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_config_setup_from_file() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let config_path = test_dir.path().join("config.yaml");
        let socket_path = test_dir.path().join("vhost4.socket");
        let uds_path = test_dir.path().join("vm4.vsock");

        let mut yaml = File::create(&config_path).unwrap();
        yaml.write_all(
            format!(
                "vms:
    - guest_cid: 4
      socket: {}
      uds_path: {}
      tx_buffer_size: 32768
      groups: group1+group2",
                socket_path.display(),
                uds_path.display(),
            )
            .as_bytes(),
        )
        .unwrap();
        let args = VsockArgs::from_file(&config_path.display().to_string());

        let configs = CliVsockConfig::try_from(args).unwrap().vsock_configs;
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), 4);
        assert_eq!(config.get_socket_path(), socket_path.display().to_string());
        assert_eq!(config.get_uds_path(), uds_path.display().to_string());
        assert_eq!(config.get_tx_buffer_size(), 32768);
        assert_eq!(
            config.get_groups(),
            vec!["group1".to_string(), "group2".to_string()]
        );

        // Now test that optional parameters are correctly set to their default values.
        let mut yaml = File::create(&config_path).unwrap();
        yaml.write_all(
            format!(
                "vms:
    - socket: {}
      uds_path: {}",
                socket_path.display(),
                uds_path.display(),
            )
            .as_bytes(),
        )
        .unwrap();
        let args = VsockArgs::from_file(&config_path.display().to_string());

        let configs = CliVsockConfig::try_from(args).unwrap().vsock_configs;
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), DEFAULT_GUEST_CID);
        assert_eq!(config.get_socket_path(), socket_path.display().to_string());
        assert_eq!(config.get_uds_path(), uds_path.display().to_string());
        assert_eq!(config.get_tx_buffer_size(), DEFAULT_TX_BUFFER_SIZE);
        assert_eq!(config.get_groups(), vec![DEFAULT_GROUP_NAME.to_string()]);

        std::fs::remove_file(&config_path).unwrap();
        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_server() {
        const CID: u64 = 3;
        const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir
            .path()
            .join("test_vsock_server.socket")
            .display()
            .to_string();
        let vsock_socket_path = test_dir
            .path()
            .join("test_vsock_server.vsock")
            .display()
            .to_string();

        let config = VsockConfig::new(
            CID,
            vhost_socket_path,
            vsock_socket_path,
            CONN_TX_BUF_SIZE,
            vec![DEFAULT_GROUP_NAME.to_string()],
        );

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let backend = Arc::new(VhostUserVsockBackend::new(config, cid_map).unwrap());

        let daemon = VhostUserDaemon::new(
            String::from("vhost-device-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let vring_workers = daemon.get_epoll_handlers();

        // VhostUserVsockBackend support a single thread that handles the TX and RX queues
        assert_eq!(backend.threads.len(), 1);

        assert_eq!(vring_workers.len(), backend.threads.len());

        test_dir.close().unwrap();
    }
}
