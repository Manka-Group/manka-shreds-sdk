//! Everything that can go wrong.

use crate::protocol::ErrorCode;

/// A convenience alias for this crate's results.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong connecting to or reading from a manka-shreds node.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The socket failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The server refused the connection, or closed it.
    #[error("server error {code:?}: {detail}")]
    Server {
        /// Why.
        code: ErrorCode,
        /// The server's explanation.
        detail: String,
    },

    /// A message ended before it should have.
    #[error("{what} needs {need} bytes, have {have}")]
    Truncated {
        /// Which message.
        what: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },

    /// A frame declared a payload larger than the protocol allows.
    #[error("frame declares {len} payload bytes, which exceeds the limit")]
    FrameTooLarge {
        /// The declared length.
        len: usize,
    },

    /// A table entry pointed outside its own byte region.
    #[error("{what} {index} points outside its byte region")]
    BadOffset {
        /// Which table.
        what: &'static str,
        /// Which entry.
        index: usize,
    },

    /// The server speaks a different protocol version.
    #[error("server speaks protocol version {server}, this client speaks {client}")]
    Version {
        /// What the server offered.
        server: u16,
        /// What this client speaks.
        client: u16,
    },

    /// The handshake did not complete.
    #[error("handshake failed: {0}")]
    Handshake(String),

    /// The server negotiated a codec this client never offered, or none at all.
    ///
    /// This client offers only zstd, so an uncompressed stream means the server has zstd disabled.
    /// Continuing would silently cost the operator several times the bandwidth they configured for.
    #[error("server negotiated {0:?}, but this client requires zstd")]
    CompressionRequired(crate::protocol::Codec),

    /// Decompression failed.
    #[error("decompressing a frame failed: {0}")]
    Decompress(String),

    /// The server closed the connection.
    #[error("the server closed the connection")]
    Closed,
}
