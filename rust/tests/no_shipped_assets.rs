//! What this build must not start carrying again.
//!
//! An archive used to ship two things beside the source: a node endpoint and a copy of the node's
//! compression dictionary. Both are gone — the address is an argument now, and the node hands its
//! dictionary over during the handshake — and neither should come back by accident.
//!
//! A dictionary file reappearing would be read by nothing, since there is no `include_bytes!` left
//! to read it. It would simply sit there being reissued in every archive, a megabyte at a time,
//! looking like it mattered.

/// No dictionary is shipped beside this crate.
#[test]
fn no_dictionary_is_shipped_beside_this_crate() {
    let stray = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("dictionary.bin");
    assert!(
        !stray.exists(),
        "{} is back; the node sends its dictionary during the handshake and nothing reads this file",
        stray.display()
    );
}

/// No endpoint is baked into the source.
///
/// One archive has to serve every node. A constant here would be one more thing to reissue when an
/// operator moves a node, and one more way for a subscriber to be pointed at something that has
/// gone away — which fails looking like a credential problem rather than an address problem.
#[test]
fn no_endpoint_is_baked_into_the_source() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(
        !src.join("defaults.rs").exists(),
        "src/defaults.rs is back; the address is an argument to connect(), not a build-time constant"
    );
}
