//! The subscriber client.

use std::sync::Arc;

use tokio::net::ToSocketAddrs;

use crate::{
    error::{Error, Result},
    events::{Duplicate, Entry, RawShred, SlotEnd, SlotStart},
    protocol::{
        CODEC_BIT_ZSTD, Codec, ErrorMessage, FRAME_HEADER_LEN, FilterAck, FilterMask, FrameHeader,
        FrameKind,
        Capabilities, Challenge, Dictionary, Hello, HelloAck, Lag, PROTOCOL_VERSION, Prove,
        StreamMask, dictionary_id,
        read_frame_header, write_frame,
    },
    handshake::{KeyRef, Transcript, fresh_nonce},
    transaction::Transaction,
    transport::{ServerVerification, Transport},
};

/// The TLS name to present when the caller did not choose one.
///
/// The host as written, unless it is a bare IP address. A certificate cannot usefully be issued for
/// an address the way it can for a name, and a node's generated certificate names `localhost`, so
/// that is what an address is dialled as — the fingerprint is what actually establishes identity in
/// that case, and it does not depend on the name.
fn default_server_name(spec: &str, resolved: std::net::SocketAddr) -> String {
    let host = spec.rsplit_once(':').map_or(spec, |(host, _)| host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.parse::<std::net::IpAddr>().is_ok() || host.is_empty() {
        let _ = resolved;
        return "localhost".to_string();
    }
    host.to_string()
}

/// How to connect.
#[derive(Clone, Debug)]
pub struct Config {
    /// Which transport to use. QUIC by default; see [`Transport`].
    pub transport: Transport,
    /// How to verify the server's certificate over QUIC. Ignored over TCP.
    pub verification: ServerVerification,
    /// Name to present for TLS, when it differs from the host being dialled.
    ///
    /// Needed when connecting to a bare address whose certificate names something else — which is
    /// the case for a node's generated certificate, valid for `localhost`. Pinning does not check
    /// the name, but the name still has to be one TLS will carry.
    pub server_name: Option<String>,
    /// The key issued to this subscriber, and the only credential there is.
    ///
    /// The greeting names it by `SHA-256(domain ‖ secret)` and never carries the secret itself, so
    /// the server finds a key by that reference rather than by any name. There is no separate key
    /// id to supply: this build used to take one, ignore it, and let a subscriber believe a wrong
    /// value would be caught somewhere.
    pub secret: Vec<u8>,
    /// Streams to subscribe to.
    ///
    /// The server grants the intersection of this and what the key permits, so asking for more
    /// than the key allows is not an error — check [`Client::granted`] for what was given.
    pub streams: StreamMask,
    /// A compression dictionary to offer, when you have one in hand.
    ///
    /// Almost never needed. The node hands over whichever dictionary it is using during the
    /// handshake, so leaving this `None` gets the full ratio on the first connection and every one
    /// after it. Set it only to seed a client that already has the bytes and wants to skip even
    /// that first transfer.
    ///
    /// A dictionary roughly triples the compression ratio on transaction frames, which are small
    /// and highly repetitive. One that does not match the node's is not an error: the node simply
    /// sends its own, and this one is superseded for the life of the connection.
    pub dictionary: Option<Arc<Vec<u8>>>,
    /// Where dictionaries received from a node are kept between runs.
    ///
    /// `Some` by default, at the platform's cache directory, so the megabyte a node sends is paid
    /// once ever rather than once per connection. `None` keeps it in memory for the session and
    /// fetches it again next time — correct for a read-only deployment, and no worse than plain
    /// zstd in any case.
    ///
    /// See [`crate::dictcache`] for the location and how to redirect it.
    pub dictionary_cache: Option<crate::dictcache::DictionaryCache>,
    /// How long to wait for the handshake.
    pub connect_timeout: std::time::Duration,
    /// Largest message to accept, compressed or not.
    ///
    /// Bounds both the frame read off the socket and what a compressed one is expanded into, so
    /// lowering it actually bounds what a node can make this process allocate. A compressed body is
    /// smaller than what it becomes, so nothing legitimate is lost by checking it in both places.
    /// Handshake frames are bounded separately, by what each of them can be.
    pub max_message_bytes: usize,
    /// A filter document installed before the stream starts, if any.
    ///
    /// Set through [`Config::filters`] or [`Config::filter`] rather than directly.
    pub filter: Option<String>,
}

impl Config {
    /// A configuration for `secret`, subscribing to every published stream over QUIC.
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            transport: Transport::Quic,
            // The node authenticates itself with your key during the handshake, bound to the
            // certificate the session presented, so that certificate carries no trust and checking
            // it against a store proves nothing further. Verifying by default would instead refuse
            // the self-signed certificate a node generates, and break every client the moment an
            // operator rotated it. See `handshake`.
            verification: ServerVerification::Unchecked,
            server_name: None,
            secret: secret.into(),
            streams: StreamMask::ALL,
            dictionary: None,
            dictionary_cache: crate::dictcache::DictionaryCache::default_location(),
            connect_timeout: std::time::Duration::from_secs(10),
            max_message_bytes: 16 << 20,
            filter: None,
        }
    }

    /// Keeps received dictionaries in `dir` instead of the default location.
    #[must_use]
    pub fn dictionary_cache(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.dictionary_cache = Some(crate::dictcache::DictionaryCache::new(dir));
        self
    }

    /// Keeps no dictionary on disk.
    ///
    /// The dictionary still arrives and this session still streams at the full ratio; it is simply
    /// fetched again on the next connection. Correct for a read-only filesystem, or anywhere you
    /// would rather this crate did not write.
    #[must_use]
    pub fn without_dictionary_cache(mut self) -> Self {
        self.dictionary_cache = None;
        self
    }

    /// Uses TCP instead of QUIC.
    ///
    /// Reasonable for a colocated subscriber, or one behind a network that blocks UDP. Over a WAN
    /// it costs you head-of-line blocking on every lost packet.
    #[must_use]
    pub fn tcp(mut self) -> Self {
        self.transport = Transport::Tcp;
        self
    }

    /// Pins the server's certificate to this SHA-256 fingerprint.
    ///
    /// Belt and braces, and not needed against a manka-shreds node: the handshake already binds the
    /// server's proof to the certificate the session presented, so a substituted one is caught
    /// without anything being pinned. This brings back the cost pinning was invented for — the
    /// value has to be reissued every time the node's certificate is rotated. The node prints it
    /// at startup.
    #[must_use]
    pub fn pinned(mut self, fingerprint: impl Into<String>) -> Self {
        self.verification = ServerVerification::Pinned(fingerprint.into());
        self
    }

    /// Sets how the server's certificate is verified.
    #[must_use]
    pub fn verification(mut self, verification: ServerVerification) -> Self {
        self.verification = verification;
        self
    }

    /// Sets the TLS server name, when it differs from the host being dialled.
    #[must_use]
    pub fn server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Subscribes to `streams` instead of everything.
    #[must_use]
    pub fn streams(mut self, streams: StreamMask) -> Self {
        self.streams = streams;
        self
    }

    /// Uses `dictionary`, if the server holds the same one.
    #[must_use]
    pub fn dictionary(mut self, dictionary: Arc<Vec<u8>>) -> Self {
        self.dictionary = Some(dictionary);
        self
    }

    /// Installs `filters` in the greeting, so the stream is narrowed before it starts.
    ///
    /// [`Client::set_filters`] leaves a window — a round trip at least — during which the
    /// connection is unfiltered and everything subscribed to arrives. On a busy node that window is
    /// thousands of transactions nobody asked for, and it is billed. Naming the filters here closes
    /// it: the server installs them before the first frame is sent.
    ///
    /// A filter that does not compile, or that exceeds the key's budgets, refuses the connection
    /// rather than falling back to an unfiltered stream.
    #[must_use]
    pub fn filters(mut self, filters: &[NamedFilter<'_>]) -> Self {
        self.filter = Some(filters_json(filters));
        self
    }

    /// Installs a single unnamed filter in the greeting.
    #[must_use]
    pub fn filter(self, spec_json: &str) -> Self {
        self.filters(&[NamedFilter {
            name: "",
            spec_json,
        }])
    }
}

/// Encodes a named filter set as the document the server expects.
fn filters_json(filters: &[NamedFilter<'_>]) -> String {
    let mut json = String::from("{\"filters\":[");
    for (index, filter) in filters.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        json.push_str("{\"name\":");
        escape_json(filter.name, &mut json);
        json.push_str(",\"spec\":");
        json.push_str(filter.spec_json);
        json.push('}');
    }
    json.push_str("]}");
    json
}

/// Something the server sent.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event<'a> {
    /// A decoded transaction, and which of this connection's named filters it matched.
    Transaction {
        /// The transaction.
        tx: Transaction<'a>,
        /// Which named filters it matched. Empty when the connection named none.
        ///
        /// A transaction matching several filters arrives once, with every match recorded, rather
        /// than once per filter.
        matched: FilterMask,
    },
    /// A proof-of-history entry.
    Entry(Entry<'a>),
    /// The first shred of a slot arrived.
    SlotStart(SlotStart<'a>),
    /// A slot finished.
    SlotEnd(SlotEnd),
    /// A leader equivocated.
    Duplicate(Duplicate<'a>),
    /// A shred republished exactly as it arrived. Needs the `raw_shreds` stream.
    ///
    /// Delivered before the node verified or decoded anything, so nothing on it is claimed to be
    /// leader-signed — see [`RawShred`].
    RawShred(RawShred<'a>),
    /// Frames this connection missed.
    Lag(Lag),
    /// The server's verdict on a submitted filter.
    FilterAck(FilterAck),
    /// A liveness probe, already answered.
    Ping,
    /// The answer to a probe this client sent.
    Pong,
    /// A frame kind this build does not know.
    ///
    /// Carried rather than dropped so a newer server does not break an older subscriber.
    Other {
        /// The kind byte as it arrived.
        kind: u8,
        /// The frame's payload.
        payload: &'a [u8],
    },
}

/// A live subscription.
///
/// # Compression is not optional
///
/// This client offers only zstd. A manka-shreds node streams several hundred megabits of transaction data
/// per second uncompressed, and a dictionary-compressed stream is roughly a third of that. Letting
/// a subscriber quietly negotiate its way to an uncompressed stream costs the operator bandwidth
/// they did not agree to, so a node can be configured to refuse it — and this client refuses it
/// too, rather than connecting and silently costing more than it should.
pub struct Client {
    stream: crate::transport::Wire,
    ack: HelloAck,
    /// Prepared once: the expensive part of using a dictionary is digesting it, not referencing it.
    dictionary: Option<zstd::dict::DecoderDictionary<'static>>,
    dictionary_active: bool,
    dictionary_was_sent: bool,
    max_message_bytes: usize,
    /// Bytes read from the socket that do not yet form a whole frame.
    pending: Vec<u8>,
    /// The current frame's payload, decompressed.
    frame: Vec<u8>,
    expected_seq: u64,
    gaps: u64,
    wire_bytes: u64,
    decoded_bytes: u64,
}

impl Client {
    /// Connects, authenticates and negotiates compression.
    ///
    /// Uses QUIC unless the configuration says otherwise. `addr` may be anything resolvable —
    /// `"node.example.com:9100"` or a [`std::net::SocketAddr`]; over QUIC the host part is
    /// presented for TLS unless [`Config::server_name`] overrides it.
    pub async fn connect(addr: impl ToSocketAddrs + ToString, config: Config) -> Result<Self> {
        let spec = addr.to_string();
        let resolved = tokio::net::lookup_host(addr)
            .await?
            .next()
            .ok_or_else(|| Error::Handshake(format!("{spec} resolved to no address")))?;
        let server_name = config
            .server_name
            .clone()
            .unwrap_or_else(|| default_server_name(&spec, resolved));

        let transport = config.transport;
        let verification = config.verification.clone();
        let open = async move {
            match transport {
                Transport::Quic => {
                    crate::transport::connect_quic(resolved, &server_name, &verification).await
                }
                Transport::Tcp => crate::transport::connect_tcp(resolved).await,
            }
        };
        let mut stream = tokio::time::timeout(config.connect_timeout, open)
            .await
            .map_err(|_| Error::Handshake("connecting timed out".to_string()))??;

        // Whatever certificate this session completed against, or nothing over TCP.
        let binding = stream.channel_binding();

        // What this client already holds: an explicitly configured dictionary, or failing that
        // whichever one the cache used most recently. Offering it is what lets the node skip
        // sending a megabyte this side already has.
        let held: Option<Arc<Vec<u8>>> = config.dictionary.clone().or_else(|| {
            config
                .dictionary_cache
                .as_ref()
                .and_then(|cache| cache.newest())
                .map(|(_, bytes)| Arc::new(bytes))
        });
        let offered_id = held
            .as_ref()
            .map_or(0, |dictionary| dictionary_id(dictionary));
        // Your key never leaves this process. It names itself by a one-way reference, and
        // possession is proved below over nonces bound to this TLS session.
        let key_ref = KeyRef::of(&config.secret);
        let client_nonce = fresh_nonce();

        let mut body = Vec::new();
        Hello {
            streams: config.streams,
            // Only zstd: see the note on this type.
            codecs: CODEC_BIT_ZSTD,
            key_ref,
            client_nonce,
            // Asking for the dictionary is what makes the ratio automatic. A node only sends one
            // to a client that said it would take it, so a client that cannot is never handed a
            // megabyte it would discard.
            capabilities: Capabilities(Capabilities::ACCEPTS_DICTIONARY),
            dictionary_id: offered_id,
            filter: config.filter.clone(),
        }
        .write(&mut body);
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
        write_frame(&mut frame, FrameKind::Hello, 0, &body);
        stream.write_all(&frame).await?;

        let mut pending = Vec::new();
        let (header, payload_range) =
            tokio::time::timeout(config.connect_timeout, read_frame(&mut stream, &mut pending, crate::protocol::MAX_HANDSHAKE_BYTES))
                .await
                .map_err(|_| Error::Handshake("timed out waiting for the reply".to_string()))??;

        // The node answers with its nonce and its proof. That proof is checked *before* one of your
        // own is sent, so a peer that does not hold your key is abandoned having learned nothing.
        let challenge = {
            let payload = &pending[payload_range.clone()];
            match header.kind {
                FrameKind::Challenge => Challenge::read(payload)?,
                FrameKind::Error => {
                    let error = ErrorMessage::read(payload)?;
                    return Err(Error::Server {
                        code: error.code,
                        detail: error.detail,
                    });
                }
                other => {
                    return Err(Error::Handshake(format!(
                        "expected Challenge, got {other:?}"
                    )));
                }
            }
        };
        pending.drain(..payload_range.end);

        let transcript = Transcript {
            key_ref,
            client_nonce,
            server_nonce: challenge.server_nonce,
            binding,
        };
        if !transcript.verify_server(&config.secret, &challenge.proof) {
            return Err(Error::Handshake(
                "the server did not prove it holds this key; the connection is not to the node it \
                 claims to be, or is being relayed"
                    .to_string(),
            ));
        }

        let mut body = Vec::with_capacity(Prove::LEN);
        Prove {
            proof: transcript.client_proof(&config.secret),
        }
        .write(&mut body);
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
        write_frame(&mut frame, FrameKind::Prove, 0, &body);
        stream.write_all(&frame).await?;

        let (header, payload_range) =
            tokio::time::timeout(config.connect_timeout, read_frame(&mut stream, &mut pending, crate::protocol::MAX_HANDSHAKE_BYTES))
                .await
                .map_err(|_| Error::Handshake("timed out waiting for the reply".to_string()))??;
        let payload = &pending[payload_range.clone()];

        match header.kind {
            FrameKind::HelloAck => {}
            FrameKind::Error => {
                let error = ErrorMessage::read(payload)?;
                return Err(Error::Server {
                    code: error.code,
                    detail: error.detail,
                });
            }
            other => {
                return Err(Error::Handshake(format!("expected HelloAck, got {other:?}")));
            }
        }

        let ack = HelloAck::read(payload)?;
        if ack.protocol_version != PROTOCOL_VERSION {
            return Err(Error::Version {
                server: ack.protocol_version,
                client: PROTOCOL_VERSION,
            });
        }
        if ack.codec != Codec::Zstd {
            return Err(Error::CompressionRequired(ack.codec));
        }

        // Anything past the reply already belongs to the stream, so it is kept rather than dropped.
        pending.drain(..payload_range.end);

        // What this side holds is kept only if the server said it is actually using it, so a
        // mismatch cannot lead this client to decompress against the wrong one.
        let mut bytes: Option<Arc<Vec<u8>>> =
            held.filter(|_| ack.dictionary_id != 0 && ack.dictionary_id == offered_id);

        // The node named a dictionary this side does not hold, so it is sending it — once, before
        // the first data frame. Reading it here rather than in the event loop is what makes "the
        // dictionary does not change during a run" true by construction: by the time this function
        // returns, the one this connection uses is settled.
        let mut dictionary_was_sent = false;
        if bytes.is_none() && ack.dictionary_id != 0 {
            let (header, payload_range) = tokio::time::timeout(
                config.connect_timeout,
                read_frame(
                    &mut stream,
                    &mut pending,
                    Dictionary::HEADER_LEN + crate::protocol::MAX_DICTIONARY_BYTES,
                ),
            )
            .await
            .map_err(|_| {
                Error::Handshake(
                    "the server announced a dictionary and did not send it".to_string(),
                )
            })??;
            let payload = &pending[payload_range.clone()];

            match header.kind {
                FrameKind::Dictionary => {
                    let offered = Dictionary::read(payload)?;
                    // Checked against what the acknowledgement named. Accepting bytes that do not
                    // match would leave this side decompressing against something other than what
                    // the node compresses with, and every frame after it unreadable for a reason
                    // nothing on the wire would explain.
                    let actual = dictionary_id(&offered.bytes);
                    if offered.id != ack.dictionary_id || actual != ack.dictionary_id {
                        return Err(Error::Handshake(format!(
                            "the server sent a dictionary that is not the one it announced: \
                             acknowledged {:#010x}, frame said {:#010x}, bytes hash to \
                             {actual:#010x}",
                            ack.dictionary_id, offered.id
                        )));
                    }
                    let end = payload_range.end;
                    if let Some(cache) = &config.dictionary_cache {
                        cache.store(offered.id, &offered.bytes);
                    }
                    bytes = Some(Arc::new(offered.bytes));
                    dictionary_was_sent = true;
                    // Anything past it already belongs to the stream.
                    pending.drain(..end);
                }
                FrameKind::Error => {
                    let error = ErrorMessage::read(payload)?;
                    return Err(Error::Server {
                        code: error.code,
                        detail: error.detail,
                    });
                }
                other => {
                    return Err(Error::Handshake(format!(
                        "the server announced dictionary {:#010x} and then sent {other:?}",
                        ack.dictionary_id
                    )));
                }
            }
        }

        let dictionary_active = bytes.is_some();
        let dictionary = bytes
            .as_ref()
            .map(|bytes| zstd::dict::DecoderDictionary::copy(bytes));

        Ok(Self {
            stream,
            ack,
            dictionary,
            dictionary_active,
            dictionary_was_sent,
            max_message_bytes: config.max_message_bytes,
            pending,
            frame: Vec::new(),
            expected_seq: 0,
            gaps: 0,
            wire_bytes: 0,
            decoded_bytes: 0,
        })
    }

    /// Streams the server actually granted.
    #[inline]
    pub const fn granted(&self) -> StreamMask {
        self.ack.granted
    }

    /// This connection's server-assigned id, which the operator's logs are keyed by.
    #[inline]
    pub const fn session_id(&self) -> u64 {
        self.ack.session_id
    }

    /// How often the server pings an idle connection.
    #[inline]
    pub const fn keepalive_ms(&self) -> u16 {
        self.ack.keepalive_ms
    }

    /// Whether a compression dictionary is in use on this connection.
    ///
    /// False only when the node has none at all. There is nothing to configure for it to be true:
    /// a node using a dictionary hands it over during the handshake.
    #[inline]
    pub const fn dictionary_active(&self) -> bool {
        self.dictionary_active
    }

    /// Whether the dictionary arrived over the wire rather than out of the cache.
    ///
    /// Expected once — the first time this subscriber ever connects to a given node, and again
    /// after the operator changes the node's dictionary. True on *every* connection means the cache
    /// is not being written: the directory is read-only, or absent, or the process has no home. The
    /// connection is unaffected and streams at the full ratio; it is simply paying about a megabyte
    /// each time it reconnects.
    ///
    /// This crate carries no logging dependency, so this is how that fact is reported. See
    /// [`crate::dictcache`] for where the cache lives and how to move it.
    #[inline]
    pub const fn dictionary_was_sent(&self) -> bool {
        self.dictionary_was_sent
    }

    /// Compressed bytes received.
    #[inline]
    pub const fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }

    /// Bytes after decompression. Against [`Self::wire_bytes`], this is the achieved ratio.
    #[inline]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }

    /// Frames dropped because this client could not keep up.
    #[inline]
    pub const fn gaps(&self) -> u64 {
        self.gaps
    }

    /// Replaces the server-side filter.
    ///
    /// Returns once the request is written, not once it is in force: the server applies it
    /// asynchronously and confirms with [`Event::FilterAck`]. Frames already in flight still arrive
    /// under the previous filter, so a consumer that needs certainty should wait for the ack.
    pub async fn set_filter(&mut self, spec_json: &str) -> Result<()> {
        self.set_filters(&[NamedFilter {
            name: "",
            spec_json,
        }])
        .await
    }

    /// Replaces this connection's filters with a named set, up to sixteen.
    ///
    /// Every transaction reports which of them it matched — see [`Transaction::matched`] — so one
    /// connection can carry several interests and still tell them apart on arrival. The set is
    /// accepted or refused together, so a connection never ends up holding part of what was asked
    /// for.
    pub async fn set_filters(&mut self, filters: &[NamedFilter<'_>]) -> Result<()> {
        let json = filters_json(filters);
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + json.len());
        write_frame(&mut frame, FrameKind::SetFilter, 0, json.as_bytes());
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Sends a liveness probe. The server answers with [`Event::Pong`].
    pub async fn ping(&mut self) -> Result<()> {
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN);
        write_frame(&mut frame, FrameKind::Ping, 0, &[]);
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Waits for the next event.
    ///
    /// The returned event borrows this client's frame buffer, so it must be dropped — or what is
    /// needed from it copied out — before the next call.
    pub async fn next_event(&mut self) -> Result<Event<'_>> {
        let (header, range) =
            read_frame(&mut self.stream, &mut self.pending, self.max_message_bytes).await?;
        self.wire_bytes += (FRAME_HEADER_LEN + header.len) as u64;

        self.frame.clear();
        if header.compressed {
            match header.codec {
                Codec::Zstd => {
                    let input = &self.pending[range.clone()];
                    let decoded = match self.dictionary.as_ref() {
                        // `with_prepared_dictionary` references an already-digested dictionary, so
                        // this is not re-loading it per frame.
                        Some(prepared) => {
                            zstd::bulk::Decompressor::with_prepared_dictionary(prepared)
                                .and_then(|mut d| d.decompress(input, self.max_message_bytes))
                        }
                        None => zstd::bulk::decompress(input, self.max_message_bytes),
                    }
                    .map_err(|err| Error::Decompress(err.to_string()))?;
                    self.frame = decoded;
                }
                other => {
                    self.pending.drain(..range.end);
                    return Err(Error::CompressionRequired(other));
                }
            }
        } else {
            self.frame.extend_from_slice(&self.pending[range.clone()]);
        }
        self.pending.drain(..range.end);
        self.decoded_bytes += self.frame.len() as u64;

        // A sequence gap means the server dropped frames for this connection. It is reported by the
        // lag frame too, but counting here catches a gap even if that frame is itself lost.
        if self.expected_seq != 0 && header.seq > self.expected_seq {
            self.gaps += header.seq - self.expected_seq;
        }
        self.expected_seq = header.seq.wrapping_add(1);

        // Answered here so a consumer that is slow to poll is not disconnected for being idle.
        if header.kind == FrameKind::Ping {
            self.ping_reply().await?;
            return Ok(Event::Ping);
        }
        if header.kind == FrameKind::Error {
            let error = ErrorMessage::read(&self.frame)?;
            return Err(Error::Server {
                code: error.code,
                detail: error.detail,
            });
        }
        if header.kind == FrameKind::Lag {
            let lag = Lag::read(&self.frame)?;
            self.gaps += lag.dropped;
            self.expected_seq = lag.resume_seq;
            return Ok(Event::Lag(lag));
        }

        let body: &[u8] = &self.frame;
        Ok(match header.kind {
            FrameKind::Transaction => Event::Transaction {
                tx: Transaction::read(body)?,
                matched: header.matched,
            },
            FrameKind::Entry => Event::Entry(Entry::read(body)?),
            FrameKind::SlotStart => Event::SlotStart(SlotStart::read(body)?),
            FrameKind::SlotEnd => Event::SlotEnd(SlotEnd::read(body)?),
            FrameKind::Duplicate => Event::Duplicate(Duplicate::read(body)?),
            FrameKind::RawShred => Event::RawShred(RawShred::read(body)?),
            FrameKind::FilterAck => Event::FilterAck(FilterAck::read(body)?),
            FrameKind::Pong => Event::Pong,
            // The dictionary is settled during the handshake and does not change while a
            // connection runs. One arriving here is refused rather than skipped: a server that
            // meant it would be compressing the next frame with something this side is not
            // decoding with, and every message after it would fail for a reason nothing in the
            // error would explain. Better to name the cause than to let it surface as corruption
            // several frames later.
            FrameKind::Dictionary => {
                return Err(Error::Handshake(
                    "the server sent a dictionary mid-stream; the dictionary is fixed for the \
                     life of a connection"
                        .to_string(),
                ));
            }
            _ => Event::Other {
                kind: header.raw_kind,
                payload: body,
            },
        })
    }

    /// Hand-written because the prepared dictionary is opaque and its bytes are not worth printing.
    fn debug_fields(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("session_id", &self.ack.session_id)
            .field("granted", &self.ack.granted)
            .field("dictionary_active", &self.dictionary_active)
            .field("wire_bytes", &self.wire_bytes)
            .field("decoded_bytes", &self.decoded_bytes)
            .field("gaps", &self.gaps)
            .finish()
    }

    async fn ping_reply(&mut self) -> Result<()> {
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN);
        write_frame(&mut frame, FrameKind::Pong, 0, &[]);
        self.stream.write_all(&frame).await?;
        Ok(())
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.debug_fields(f)
    }
}

/// Reads one whole frame into `pending`, returning its header and where its payload sits.
///
/// The payload is left in `pending` rather than copied out; the caller drains it once it is done.
///
/// `limit` is what the frame being waited for can legitimately be, checked before anything is
/// reserved for it. The length belongs to the server, so without it the server decides how much
/// this side allocates.
async fn read_frame(
    stream: &mut crate::transport::Wire,
    pending: &mut Vec<u8>,
    limit: usize,
) -> Result<(FrameHeader, std::ops::Range<usize>)> {
    loop {
        if pending.len() >= FRAME_HEADER_LEN {
            let header = read_frame_header(pending)?;
            if header.len > limit {
                return Err(Error::Handshake(format!(
                    "the server sent a {:?} frame of {} bytes, and this connection accepts at most \
                     {limit}",
                    header.kind, header.len
                )));
            }
            let end = FRAME_HEADER_LEN + header.len;
            if pending.len() >= end {
                return Ok((header, FRAME_HEADER_LEN..end));
            }
            pending.reserve(end - pending.len());
        }
        let read = stream.read_buf(pending).await?;
        if read == 0 {
            return Err(Error::Closed);
        }
    }
}

/// One filter, with the name the subscriber chose for it.
///
/// The spec is passed as JSON rather than as a typed tree: this crate deliberately carries no
/// serialization dependency, and a filter is written once at startup where a string literal is as
/// readable as a builder would be.
#[derive(Clone, Copy, Debug)]
pub struct NamedFilter<'a> {
    /// What you call it. Comes back in a refusal so you know which one was at fault.
    pub name: &'a str,
    /// The filter itself, as JSON.
    pub spec_json: &'a str,
}

/// Writes `value` into `out` as a quoted JSON string.
///
/// This crate carries no serialization dependency, so the one string it has to encode is encoded
/// here. Escaping only the quote and the backslash is the tempting version and is wrong: every
/// character below `0x20` is forbidden raw in a JSON string, so a name containing a newline or a
/// tab produces JSON no parser accepts — and the server then refuses the whole submission as a
/// malformed *filter*, pointing at the filter language rather than at the name.
fn escape_json(value: &str, out: &mut String) {
    use std::fmt::Write;

    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control < ' ' => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod json_escaping {
    use super::escape_json;

    #[test]
    fn a_name_with_control_characters_stays_valid_json() {
        let escaped = |value: &str| {
            let mut out = String::new();
            escape_json(value, &mut out);
            out
        };

        assert_eq!(escaped("plain"), "\"plain\"");
        assert_eq!(escaped("say \"hi\"\\ok"), "\"say \\\"hi\\\"\\\\ok\"");

        // The case the naive version produced invalid JSON for.
        let control = format!("two{}lines{}apart", '\n', '\t');
        assert_eq!(escaped(&control), "\"two\\nlines\\tapart\"");

        // A control character with no short form takes the \u escape.
        assert_eq!(escaped(&format!("bell{}", '\u{7}')), "\"bell\\u0007\"");

        // Non-ASCII needs no escaping in JSON and must survive intact.
        assert_eq!(escaped("naïve ✓"), "\"naïve ✓\"");
    }
}
