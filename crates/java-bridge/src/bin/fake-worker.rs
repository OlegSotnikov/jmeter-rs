// SPDX-License-Identifier: Apache-2.0
//! Deterministic local worker used by java-bridge process tests.

use jmeter_rs_bridge_protocol::{
    Cancellation, Frame, FrameCodec, MessageKind, RemoteError, RemoteErrorCode,
};
use std::env;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mode = env::var("BRIDGE_FAKE_MODE").unwrap_or_else(|_| "echo".to_owned());
    let codec = FrameCodec::new(4 * 1024 * 1024);
    let mut input = Vec::new();
    let mut chunk = [0_u8; 3];
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    loop {
        let read = stdin.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        input.extend_from_slice(&chunk[..read]);
        loop {
            let mut available = input.as_slice();
            let Some(frame) = codec.decode_next(&mut available).map_err(protocol_io)? else {
                break;
            };
            let consumed = input.len() - available.len();
            input.drain(..consumed);
            match frame.kind {
                MessageKind::Handshake => {
                    if mode == "crash_handshake" {
                        return Ok(());
                    }
                    if mode == "bad_version" {
                        let mut bytes = codec
                            .encode(&Frame::handshake(
                                frame.request_id,
                                frame.profile.unwrap_or_default(),
                                frame.capabilities,
                            ))
                            .map_err(protocol_io)?;
                        bytes[4] = 2;
                        stdout.write_all(&bytes)?;
                        stdout.flush()?;
                        continue;
                    }
                    if mode == "bad_profile" {
                        write_frame(
                            &mut stdout,
                            &codec,
                            Frame::handshake(frame.request_id, "other-profile", frame.capabilities),
                            false,
                        )?;
                        continue;
                    }
                    let capabilities = if mode == "missing_capability" {
                        Vec::new()
                    } else {
                        frame.capabilities
                    };
                    write_frame(
                        &mut stdout,
                        &codec,
                        Frame::handshake(
                            frame.request_id,
                            frame.profile.unwrap_or_default(),
                            capabilities,
                        ),
                        mode == "partial",
                    )?;
                    if mode == "no_read" {
                        // Leave the handshake response available, then stop
                        // consuming stdin. The supervisor must keep request
                        // deadlines/cancellation bounded while its dedicated
                        // writer is blocked in the OS pipe.
                        loop {
                            std::thread::park();
                        }
                    }
                }
                MessageKind::Request => {
                    if mode == "crash" {
                        return Ok(());
                    }
                    if mode == "timeout" {
                        continue;
                    }
                    if mode == "oversized_stdout" {
                        write_frame(
                            &mut stdout,
                            &codec,
                            Frame::new(MessageKind::Response, frame.request_id, vec![b'x'; 4096]),
                            false,
                        )?;
                        continue;
                    }
                    if mode == "remote_error" {
                        let error = RemoteError::new(
                            RemoteErrorCode::CapabilityUnavailable,
                            false,
                            "fake engine unavailable",
                        );
                        let response = codec
                            .error_frame(frame.request_id, error)
                            .map_err(protocol_io)?;
                        write_frame(&mut stdout, &codec, response, false)?;
                        continue;
                    }
                    if mode == "stderr_secret" {
                        eprintln!("worker diagnostic token=secret-value");
                    }
                    write_frame(
                        &mut stdout,
                        &codec,
                        Frame::new(MessageKind::Response, frame.request_id, frame.payload),
                        mode == "partial",
                    )?;
                }
                MessageKind::Cancel => {
                    if mode == "timeout" {
                        write_frame(
                            &mut stdout,
                            &codec,
                            Frame::new(MessageKind::Response, frame.request_id, Vec::new())
                                .with_cancellation(Cancellation::Cancelled),
                            false,
                        )?;
                    }
                }
                MessageKind::Response | MessageKind::Error => {}
            }
        }
    }
}

fn write_frame(
    stdout: &mut impl Write,
    codec: &FrameCodec,
    frame: Frame,
    partial: bool,
) -> io::Result<()> {
    let bytes = codec.encode(&frame).map_err(protocol_io)?;
    if partial {
        for byte in bytes {
            stdout.write_all(&[byte])?;
            stdout.flush()?;
        }
    } else {
        stdout.write_all(&bytes)?;
        stdout.flush()?;
    }
    Ok(())
}

fn protocol_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
