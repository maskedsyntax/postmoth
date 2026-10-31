//! Length-prefixed JSON framing used by Chromium native messaging.
//!
//! Each message is a `u32` length in native byte order followed by that many
//! bytes of UTF-8 JSON. We cap frames far below Chromium's limits because our
//! messages are tiny; anything larger is a protocol violation.

use serde::{Serialize, de::DeserializeOwned};
use std::io::{self, Read, Write};

/// Maximum accepted frame payload size in bytes.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("frame of {0} bytes exceeds limit")]
    TooLarge(u32),
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Read one frame. Returns `Ok(None)` on clean EOF before a length prefix.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_ne_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write one frame and flush.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    w.write_all(&len.to_ne_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Read and deserialize one JSON message.
pub fn read_json<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>, FrameError> {
    match read_frame(r)? {
        None => Ok(None),
        Some(buf) => Ok(Some(serde_json::from_slice(&buf)?)),
    }
}

/// Serialize and write one JSON message.
pub fn write_json<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    let buf = serde_json::to_vec(msg)?;
    write_frame(w, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip() {
        let mut buf = Vec::new();
        write_json(&mut buf, &serde_json::json!({"a": 1})).expect("write");
        let mut cur = Cursor::new(buf);
        let v: serde_json::Value = read_json(&mut cur).expect("read").expect("some");
        assert_eq!(v["a"], 1);
        assert!(read_frame(&mut cur).expect("eof").is_none());
    }

    #[test]
    fn rejects_oversize_prefix_without_allocating() {
        let mut cur = Cursor::new(u32::MAX.to_ne_bytes().to_vec());
        assert!(matches!(read_frame(&mut cur), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn truncated_payload_is_error() {
        let mut bytes = 10u32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"abc");
        let mut cur = Cursor::new(bytes);
        assert!(matches!(read_frame(&mut cur), Err(FrameError::Io(_))));
    }

    #[test]
    fn invalid_json_is_error() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{nope").expect("write");
        let mut cur = Cursor::new(buf);
        assert!(matches!(
            read_json::<_, serde_json::Value>(&mut cur),
            Err(FrameError::Json(_))
        ));
    }
}
