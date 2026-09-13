#![forbid(unsafe_code)]

//! Generic Unix server for a durable fleet-root authority.
//!
//! The server owns no key itself.  A caller supplies a
//! [`FleetRootAuthoritySignerV1`] implementation (an HSM/remote signer
//! adapter in a deployment, or the feature-gated deterministic fixture in
//! tests), opens the durable authority namespace, and then hands that owner to
//! this transport.  The namespace is replayed and locked before the socket is
//! made reachable.

use std::{
    error::Error,
    fmt, fs, io,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

use crate::{
    read_frame_v1, write_frame_v1, DurableFleetRootSignerAuthorityV1, FleetRootAuthorityErrorV1,
    FleetRootAuthoritySignerV1, FleetRootRequestV1, FleetRootResponseV1,
    FleetSignerProtocolErrorV1, UnixFleetSignerErrorV1, MAX_FRAME_BYTES_V1, MAX_REQUEST_BYTES_V1,
};

const RESPONSE_STATUS_OK_V1: u8 = 0;
const RESPONSE_STATUS_REJECT_V1: u8 = 1;
const REJECT_PROTOCOL_V1: u8 = 7;
const REJECT_REPLAY_V1: u8 = 9;

/// Errors raised by the generic authority transport.
#[derive(Debug)]
pub enum UnixFleetAuthorityServerErrorV1 {
    InvalidConfig(&'static str),
    Io {
        stage: &'static str,
        source: io::Error,
    },
    Transport(UnixFleetSignerErrorV1),
    Authority(FleetRootAuthorityErrorV1),
    Protocol(FleetSignerProtocolErrorV1),
}

impl fmt::Display for UnixFleetAuthorityServerErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(
                    formatter,
                    "invalid Unix fleet authority server config: {reason}"
                )
            }
            Self::Io { stage, source } => {
                write!(
                    formatter,
                    "Unix fleet authority server I/O at {stage}: {source}"
                )
            }
            Self::Transport(error) => write!(formatter, "Unix fleet authority transport: {error}"),
            Self::Authority(error) => write!(formatter, "fleet authority: {error}"),
            Self::Protocol(error) => write!(formatter, "fleet authority protocol: {error}"),
        }
    }
}

impl Error for UnixFleetAuthorityServerErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Transport(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::InvalidConfig(_) => None,
        }
    }
}

/// A socket server over one durable fleet-root authority namespace.
pub struct UnixFleetRootAuthorityServerV1<S> {
    authority: DurableFleetRootSignerAuthorityV1<S>,
    socket_path: PathBuf,
}

impl<S: FleetRootAuthoritySignerV1> UnixFleetRootAuthorityServerV1<S> {
    /// Creates a server without binding a socket.  The authority must already
    /// have been opened, replayed, and exclusively locked by the caller.
    pub fn new(
        authority: DurableFleetRootSignerAuthorityV1<S>,
        socket_path: impl AsRef<Path>,
    ) -> Result<Self, UnixFleetAuthorityServerErrorV1> {
        let socket_path = socket_path.as_ref().to_path_buf();
        if !socket_path.is_absolute() {
            return Err(UnixFleetAuthorityServerErrorV1::InvalidConfig(
                "socket path must be absolute",
            ));
        }
        let parent = socket_path
            .parent()
            .ok_or(UnixFleetAuthorityServerErrorV1::InvalidConfig(
                "socket path has no parent",
            ))?;
        if !parent.is_absolute() {
            return Err(UnixFleetAuthorityServerErrorV1::InvalidConfig(
                "socket parent must be absolute",
            ));
        }
        Ok(Self {
            authority,
            socket_path,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn authority(&self) -> &DurableFleetRootSignerAuthorityV1<S> {
        &self.authority
    }

    pub fn authority_mut(&mut self) -> &mut DurableFleetRootSignerAuthorityV1<S> {
        &mut self.authority
    }

    /// Serves until the process is stopped. Every accepted connection carries
    /// one request; a malformed/replayed request receives a bounded rejection,
    /// while durable-authority corruption poisons the process and tears down
    /// the endpoint.
    pub fn serve(&mut self) -> Result<(), UnixFleetAuthorityServerErrorV1> {
        self.serve_inner(None)
    }

    /// Deterministic bounded server mode for black-box tests and supervisor
    /// probes. A zero limit is rejected rather than silently exposing a socket.
    pub fn serve_n(&mut self, request_count: usize) -> Result<(), UnixFleetAuthorityServerErrorV1> {
        if request_count == 0 {
            return Err(UnixFleetAuthorityServerErrorV1::InvalidConfig(
                "request count must be positive",
            ));
        }
        self.serve_inner(Some(request_count))
    }

    fn serve_inner(
        &mut self,
        request_limit: Option<usize>,
    ) -> Result<(), UnixFleetAuthorityServerErrorV1> {
        let listener = self.bind_socket()?;
        let result =
            (|| {
                let mut served = 0usize;
                for incoming in listener.incoming() {
                    let mut stream =
                        incoming.map_err(|source| UnixFleetAuthorityServerErrorV1::Io {
                            stage: "accept Unix connection",
                            source,
                        })?;
                    self.handle_stream(&mut stream)?;
                    served = served.checked_add(1).ok_or(
                        UnixFleetAuthorityServerErrorV1::InvalidConfig("request count overflow"),
                    )?;
                    if request_limit.is_some_and(|limit| served >= limit) {
                        break;
                    }
                }
                Ok(())
            })();
        drop(listener);
        self.remove_socket_if_owned();
        result
    }

    fn bind_socket(&self) -> Result<UnixListener, UnixFleetAuthorityServerErrorV1> {
        let parent =
            self.socket_path
                .parent()
                .ok_or(UnixFleetAuthorityServerErrorV1::InvalidConfig(
                    "socket path has no parent",
                ))?;
        fs::create_dir_all(parent).map_err(|source| UnixFleetAuthorityServerErrorV1::Io {
            stage: "create socket parent",
            source,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            UnixFleetAuthorityServerErrorV1::Io {
                stage: "protect socket parent",
                source,
            }
        })?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|source| UnixFleetAuthorityServerErrorV1::Io {
                stage: "inspect socket parent",
                source,
            })?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(UnixFleetAuthorityServerErrorV1::InvalidConfig(
                "socket parent must be a private 0700 directory",
            ));
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path) {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_socket()
                || metadata.permissions().mode() & 0o7777 != 0o600
            {
                return Err(UnixFleetAuthorityServerErrorV1::InvalidConfig(
                    "existing socket must be a private 0600 socket",
                ));
            }
            fs::remove_file(&self.socket_path).map_err(|source| {
                UnixFleetAuthorityServerErrorV1::Io {
                    stage: "remove stale authority socket",
                    source,
                }
            })?;
        }
        let listener = UnixListener::bind(&self.socket_path).map_err(|source| {
            UnixFleetAuthorityServerErrorV1::Io {
                stage: "bind authority socket",
                source,
            }
        })?;
        fs::set_permissions(&self.socket_path, fs::Permissions::from_mode(0o600)).map_err(
            |source| UnixFleetAuthorityServerErrorV1::Io {
                stage: "protect authority socket",
                source,
            },
        )?;
        Ok(listener)
    }

    fn handle_stream(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<(), UnixFleetAuthorityServerErrorV1> {
        let frame = match read_frame_v1(stream, MAX_FRAME_BYTES_V1) {
            Ok(frame) => frame,
            Err(UnixFleetSignerErrorV1::Protocol(error)) => {
                self.write_reject(stream, protocol_reject_code(&error))?;
                return Ok(());
            }
            Err(error) => return Err(UnixFleetAuthorityServerErrorV1::Transport(error)),
        };
        if frame.len() > MAX_REQUEST_BYTES_V1 {
            self.write_reject(stream, REJECT_PROTOCOL_V1)?;
            return Ok(());
        }
        let request = match FleetRootRequestV1::decode_exact(&frame) {
            Ok(request) => request,
            Err(error) => {
                self.write_reject(stream, protocol_reject_code(&error))?;
                return Ok(());
            }
        };
        let signature = match self.authority.sign_fleet_root_v1(&request) {
            Ok(signature) => signature,
            Err(FleetRootAuthorityErrorV1::ReplayConflict) => {
                self.write_reject(stream, REJECT_REPLAY_V1)?;
                return Ok(());
            }
            Err(FleetRootAuthorityErrorV1::BindingMismatch(_))
            | Err(FleetRootAuthorityErrorV1::Protocol(_)) => {
                self.write_reject(stream, REJECT_PROTOCOL_V1)?;
                return Ok(());
            }
            Err(error) => return Err(UnixFleetAuthorityServerErrorV1::Authority(error)),
        };
        let response = FleetRootResponseV1::from_request_signature(&request, signature)
            .map_err(UnixFleetAuthorityServerErrorV1::Protocol)?;
        let mut body = Vec::with_capacity(1 + response.try_exact_bytes().len());
        body.push(RESPONSE_STATUS_OK_V1);
        body.extend_from_slice(&response.try_exact_bytes());
        write_frame_v1(stream, &body).map_err(UnixFleetAuthorityServerErrorV1::Transport)
    }

    fn write_reject(
        &self,
        stream: &mut UnixStream,
        code: u8,
    ) -> Result<(), UnixFleetAuthorityServerErrorV1> {
        write_frame_v1(stream, &[RESPONSE_STATUS_REJECT_V1, code])
            .map_err(UnixFleetAuthorityServerErrorV1::Transport)
    }

    fn remove_socket_if_owned(&self) {
        let Ok(metadata) = fs::symlink_metadata(&self.socket_path) else {
            return;
        };
        if metadata.file_type().is_socket() && !metadata.file_type().is_symlink() {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

fn protocol_reject_code(error: &FleetSignerProtocolErrorV1) -> u8 {
    if matches!(error, FleetSignerProtocolErrorV1::ReplayConflict) {
        REJECT_REPLAY_V1
    } else {
        REJECT_PROTOCOL_V1
    }
}
