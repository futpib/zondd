//! Stable bootstrap for the single supported command schema. Credentials use
//! their own protocol and do not participate in this handshake.

use crate::{ClientInfo, Envelope, Event, MAX_REQUEST_BYTES, VERSION, wire};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncWrite};

/// Bump for incompatible command or response schemas, including rule records.
pub const PROTOCOL: u32 = 2;
pub const CLIENT_INFO: &str = "client-info";
pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const UPGRADE: &str =
    "update zondctl and zondd, then restart zondd.service on the receiving host";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Extensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<ClientInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub handshake: u32,
    pub protocols: Vec<u32>,
    pub capabilities: Vec<String>,
}

impl Default for Hello {
    fn default() -> Self {
        Self {
            handshake: VERSION,
            protocols: vec![PROTOCOL],
            capabilities: vec![CLIENT_INFO.into()],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub handshake: u32,
    pub protocol: Option<u32>,
    pub capabilities: Vec<String>,
    pub peer: ClientInfo,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Negotiated {
    pub capabilities: Vec<String>,
}

impl Negotiated {
    pub fn select(hello: &Hello) -> Self {
        Self {
            capabilities: [CLIENT_INFO]
                .into_iter()
                .filter(|cap| hello.capabilities.iter().any(|value| value == cap))
                .map(String::from)
                .collect(),
        }
    }

    pub fn client_info(&self) -> bool {
        self.capabilities.iter().any(|cap| cap == CLIENT_INFO)
    }

    pub fn validate<T>(&self, envelope: &Envelope<T>) -> Result<()> {
        ensure!(envelope.version == VERSION, "unsupported envelope version");
        if let Some(extensions) = &envelope.extensions {
            ensure!(
                self.client_info() || (extensions.client.is_none() && extensions.via.is_none()),
                "client-info capability was not negotiated"
            );
        }
        Ok(())
    }
}

// Only the header is inspected to reject an unnegotiated request. Its command
// and authority fields are never decoded or dispatched.
#[derive(Deserialize)]
struct Unnegotiated {
    version: u32,
    id: u64,
    #[serde(rename = "body")]
    _body: IgnoredAny,
}

pub async fn reply(
    writer: &mut (impl AsyncWrite + Unpin),
    peer: &str,
    result: Result<&Negotiated, &str>,
) -> Result<()> {
    let (protocol, capabilities, error) = match result {
        Ok(selected) => (Some(PROTOCOL), selected.capabilities.clone(), None),
        Err(message) => (None, vec![], Some(message.into())),
    };
    wire::write(
        writer,
        &Welcome {
            handshake: VERSION,
            protocol,
            capabilities,
            peer: ClientInfo::current(peer),
            error,
        },
    )
    .await
}

pub async fn read_hello(
    reader: &mut (impl AsyncBufRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    peer: &str,
) -> Result<Option<Hello>> {
    let frame = tokio::time::timeout(TIMEOUT, wire::read_frame(reader, MAX_REQUEST_BYTES))
        .await
        .context("protocol handshake timeout")??
        .context("no protocol handshake")?;
    // Parse directly from the zeroizing frame. An untagged enum would first
    // allocate an unprotected copy of every string in an old credential request.
    match serde_json::from_slice::<Hello>(&frame) {
        Err(_) => {
            let header: Unnegotiated = serde_json::from_slice(&frame)
                .map_err(|_| anyhow::anyhow!("invalid protocol frame"))?;
            let mut response = Envelope::new(
                header.id,
                Event::Error {
                    message: format!("protocol negotiation required; {UPGRADE}"),
                },
            );
            response.version = header.version;
            wire::write(writer, &response).await?;
            Ok(None)
        }
        Ok(hello) => {
            if hello.handshake != VERSION || !hello.protocols.contains(&PROTOCOL) {
                reply(writer, peer, Err(&format!("incompatible command protocol; this peer requires protocol {PROTOCOL}; {UPGRADE}"))).await?;
                return Ok(None);
            }
            Ok(Some(hello))
        }
    }
}

pub async fn accept(
    reader: &mut (impl AsyncBufRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    peer: &str,
) -> Result<Option<Negotiated>> {
    let Some(hello) = read_hello(reader, writer, peer).await? else {
        return Ok(None);
    };
    let selected = Negotiated::select(&hello);
    reply(writer, peer, Ok(&selected)).await?;
    Ok(Some(selected))
}

pub async fn negotiate(
    reader: &mut (impl AsyncBufRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    hello: &Hello,
    peer: &str,
) -> Result<Negotiated> {
    let exchange = async {
        wire::write(writer, hello).await?;
        let welcome: Welcome = wire::read(reader, MAX_REQUEST_BYTES)
            .await?
            .context("peer closed before handshake response")?;
        if let Some(error) = welcome.error {
            anyhow::bail!("{error}");
        }
        ensure!(
            welcome.handshake == VERSION && welcome.protocol == Some(PROTOCOL),
            "incompatible handshake response"
        );
        ensure!(
            welcome
                .capabilities
                .iter()
                .all(|cap| hello.capabilities.contains(cap)),
            "peer selected an unoffered capability"
        );
        Ok(Negotiated {
            capabilities: welcome.capabilities,
        })
    };
    let result = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .context("protocol handshake timeout")
        .and_then(|result| result);
    result.with_context(|| format!("protocol negotiation with {peer} failed; {UPGRADE}"))
}
