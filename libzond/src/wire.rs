use anyhow::{Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub async fn read<T: DeserializeOwned>(
    reader: &mut (impl AsyncBufRead + Unpin),
    limit: usize,
) -> Result<Option<T>> {
    let mut frame = Zeroizing::new(Vec::new());
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            bail!("incomplete protocol frame");
        }
        let end = available.iter().position(|b| *b == b'\n');
        let take = end.map_or(available.len(), |i| i + 1);
        if frame.len() + take > limit {
            bail!("protocol frame exceeds {limit} bytes");
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take);
        if end.is_some() {
            return Ok(Some(
                serde_json::from_slice(&frame)
                    .map_err(|_| anyhow::anyhow!("invalid protocol frame"))?,
            ));
        }
    }
}

pub async fn write<T: Serialize>(writer: &mut (impl AsyncWrite + Unpin), value: &T) -> Result<()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(value)?);
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
