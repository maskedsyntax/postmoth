//! Async version of [`crate::framing`] for tokio streams. Same wire format,
//! same limits.

use crate::framing::{FrameError, MAX_FRAME_LEN};
use serde::{Serialize, de::DeserializeOwned};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read one frame. `Ok(None)` on clean EOF before a length prefix.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_ne_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
) -> Result<(), FrameError> {
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    w.write_all(&len.to_ne_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_json<R: AsyncRead + Unpin, T: DeserializeOwned>(
    r: &mut R,
) -> Result<Option<T>, FrameError> {
    match read_frame(r).await? {
        None => Ok(None),
        Some(buf) => Ok(Some(serde_json::from_slice(&buf)?)),
    }
}

pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> Result<(), FrameError> {
    let buf = serde_json::to_vec(msg)?;
    write_frame(w, &buf).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interoperates_with_sync_framing() {
        let mut buf = Vec::new();
        crate::framing::write_json(&mut buf, &serde_json::json!({"x": 2})).expect("write");
        let mut r = buf.as_slice();
        let v: serde_json::Value = read_json(&mut r).await.expect("read").expect("some");
        assert_eq!(v["x"], 2);
        assert!(read_frame(&mut r).await.expect("eof").is_none());

        let mut out = Vec::new();
        write_json(&mut out, &v).await.expect("write");
        let back: serde_json::Value = crate::framing::read_json(&mut out.as_slice())
            .expect("read")
            .expect("some");
        assert_eq!(back, v);
    }

    #[tokio::test]
    async fn rejects_oversize() {
        let bytes = (MAX_FRAME_LEN + 1).to_ne_bytes();
        let mut r = bytes.as_slice();
        assert!(matches!(
            read_frame(&mut r).await,
            Err(FrameError::TooLarge(_))
        ));
    }
}
