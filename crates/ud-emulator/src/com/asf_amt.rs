//! Round 59 — minimal ASF Header → `WAVEFORMATEX` extractor.
//!
//! Round 58 demonstrated that the `msadds32.ax` audio splitter
//! rejects synthetic `AM_MEDIA_TYPE`s whose `WAVEFORMATEX` carries
//! all-zero codec-specific extradata.  `IPin::QueryAccept` returns
//! `E_FAIL` because the splitter validates those bytes against
//! expected WMA1/WMA2 header constants.  This round extracts the
//! real bytes from an ASF/WMA file so the round-60 `ReceiveConnection`
//! retry has a chance of succeeding.
//!
//! ## What this module does, and what it does NOT do
//!
//! * It DOES locate the ASF *Header Object* (top-level GUID
//!   `{75B22630-668E-11CF-A6D9-00AA0062CE6C}`) at the start of the
//!   ASF byte stream, walk every sub-object inside it, and isolate
//!   the *Stream Properties Object*
//!   (`{B7DC0791-A9B7-11CF-8EE6-00C00C205365}`) whose Stream Type
//!   field equals `ASF_Audio_Media`
//!   (`{F8699E40-5B4D-11CF-A8FD-00805F5C442B}`).
//! * Inside that audio Stream Properties Object, it locates the
//!   *Type-Specific Data* field, which for an audio stream IS the
//!   `WAVEFORMATEX` struct followed by `cbSize` bytes of
//!   codec-specific extradata.
//! * It does NOT implement a full ASF demuxer — there is no
//!   handling of header-extension sub-objects, multiple-payload
//!   data packets, padding bytes, ECC bytes, or DRM.  Future
//!   rounds may grow a real demuxer (`asf::Demuxer`) in this
//!   crate or factor it out into a dedicated `oxideav-asf` crate.
//!
//! ## Reference material (clean-room only)
//!
//! * Microsoft Advanced Systems Format (ASF) Specification,
//!   revision 01.20.05 (public; no NDA).  §3 enumerates
//!   top-level objects; §3.2 covers File Properties Object and
//!   §3.3 covers Stream Properties Object including the
//!   per-stream-type Type-Specific Data layout.
//! * Microsoft Multimedia Registry (`mmreg.h`) for the public
//!   `WAVEFORMATEX` layout and `wFormatTag` constants
//!   `WAVE_FORMAT_MSAUDIO1` (`0x0160`) and
//!   `WAVE_FORMAT_WMAUDIO2` (`0x0161`).
//! * The audio-stream type GUID `ASF_Audio_Media` is documented
//!   in the ASF spec §11.1.
//!
//! No Wine / ReactOS / MinGW / Microsoft DShow / ffmpeg WMA source
//! consulted — the parser was written from the ASF spec only.
//! ffmpeg is used as an opaque black-box fixture generator (it
//! writes the bytes we read); we do not read any line of its
//! source.

use super::Guid;

/// ASF *Header Object* GUID (`{75B22630-668E-11CF-A6D9-00AA0062CE6C}`).
///
/// Always the first 16 bytes of a well-formed ASF file.  Source:
/// ASF spec §11.1.
pub const ASF_HEADER_OBJECT: Guid = Guid::new(
    0x75B2_2630,
    0x668E,
    0x11CF,
    [0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C],
);

/// ASF *Stream Properties Object* GUID
/// (`{B7DC0791-A9B7-11CF-8EE6-00C00C205365}`).  ASF spec §3.3.
pub const ASF_STREAM_PROPERTIES_OBJECT: Guid = Guid::new(
    0xB7DC_0791,
    0xA9B7,
    0x11CF,
    [0x8E, 0xE6, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65],
);

/// ASF *Audio Media* stream-type GUID
/// (`{F8699E40-5B4D-11CF-A8FD-00805F5C442B}`).  Identifies the
/// Stream Properties Object's Type-Specific Data field as
/// `WAVEFORMATEX` + codec-specific extradata.  ASF spec §11.1.
pub const ASF_AUDIO_MEDIA: Guid = Guid::new(
    0xF869_9E40,
    0x5B4D,
    0x11CF,
    [0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B],
);

/// Errors the ASF parser can surface.  Each variant pinpoints the
/// exact ASF-spec rule that the input violated, so a test failure
/// reads as a single-line spec citation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsfParseError {
    /// File is shorter than the 30-byte ASF Header Object
    /// preamble (16 GUID + 8 size + 4 NumHeaderObjects + 2
    /// reserved).
    TruncatedHeader,
    /// The first 16 bytes are not the ASF Header Object GUID.
    /// Caller passed a non-ASF byte stream.
    NotAnAsfFile,
    /// The Header Object's declared size field is smaller than
    /// the 30-byte preamble, or exceeds the input buffer.
    InvalidHeaderObjectSize { declared: u64, buffer: usize },
    /// One of the sub-objects inside the Header Object declares
    /// a size smaller than its 24-byte preamble (GUID + size),
    /// which is unrepresentable.
    InvalidSubObjectSize { declared: u64 },
    /// A sub-object spans past the end of the Header Object's
    /// declared size.
    SubObjectOverflowsHeader { needed: u64, remaining: u64 },
    /// Walked the entire Header Object without finding any
    /// Stream Properties Object whose Stream Type GUID equals
    /// `ASF_AUDIO_MEDIA`.
    NoAudioStream,
    /// The Stream Properties Object for an audio stream is
    /// shorter than the 78-byte preamble it requires (24 +
    /// Stream Type GUID + Error Correction Type GUID + Time
    /// Offset + Type-Specific Data Length + Error Correction
    /// Data Length + Flags + Reserved).
    StreamPropertiesTooShort { len: u64 },
    /// The Type-Specific Data length in the Stream Properties
    /// Object is shorter than the 18-byte `WAVEFORMATEX`
    /// preamble.
    TypeSpecificDataTooShort { len: u32 },
    /// `WAVEFORMATEX::cbSize` declares more extradata bytes than
    /// the Type-Specific Data field actually provides.
    WaveFormatExtraOverflow { cb_size: u16, available: u32 },
}

impl core::fmt::Display for AsfParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AsfParseError::TruncatedHeader => {
                f.write_str("ASF input is shorter than the 30-byte Header Object preamble")
            }
            AsfParseError::NotAnAsfFile => {
                f.write_str("ASF input does not start with the Header Object GUID")
            }
            AsfParseError::InvalidHeaderObjectSize { declared, buffer } => {
                write!(
                    f,
                    "ASF Header Object declares size {declared} but buffer is {buffer} bytes"
                )
            }
            AsfParseError::InvalidSubObjectSize { declared } => {
                write!(f, "ASF sub-object declares size {declared} < 24 (preamble)")
            }
            AsfParseError::SubObjectOverflowsHeader { needed, remaining } => {
                write!(
                    f,
                    "ASF sub-object needs {needed} bytes but only {remaining} remain in header"
                )
            }
            AsfParseError::NoAudioStream => f.write_str(
                "ASF Header Object contains no Stream Properties Object of type ASF_Audio_Media",
            ),
            AsfParseError::StreamPropertiesTooShort { len } => {
                write!(f, "ASF Stream Properties Object too short: {len} bytes")
            }
            AsfParseError::TypeSpecificDataTooShort { len } => {
                write!(
                    f,
                    "Audio Type-Specific Data is {len} bytes; WAVEFORMATEX preamble needs 18"
                )
            }
            AsfParseError::WaveFormatExtraOverflow { cb_size, available } => {
                write!(
                    f,
                    "WAVEFORMATEX::cbSize={cb_size} but only {available} extradata bytes available"
                )
            }
        }
    }
}

impl std::error::Error for AsfParseError {}

/// Decoded `WAVEFORMATEX` (`mmreg.h` layout) + the codec-specific
/// extradata block that follows it on the wire.  This is the
/// blueprint a downstream `stage_audio_am_media_type` consumes to
/// populate the `AM_MEDIA_TYPE` it hands the splitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmtBlueprint {
    /// `wFormatTag` — `0x0160` (WMA1), `0x0161` (WMA2), etc.
    pub format_tag: u16,
    /// `nChannels`.
    pub n_channels: u16,
    /// `nSamplesPerSec`.
    pub n_samples_per_sec: u32,
    /// `nAvgBytesPerSec`.
    pub n_avg_bytes_per_sec: u32,
    /// `nBlockAlign`.
    pub n_block_align: u16,
    /// `wBitsPerSample`.
    pub w_bits_per_sample: u16,
    /// Codec-specific extradata.  `len()` equals
    /// `WAVEFORMATEX::cbSize` from the wire.  For WMA1 this is
    /// typically 4 bytes; for WMA2 it is 10 bytes.
    pub extradata: Vec<u8>,
}

impl AmtBlueprint {
    /// Total `cbFormat` value to store in the `AM_MEDIA_TYPE`
    /// header.  `18` is the `WAVEFORMATEX` base + the extradata
    /// length.
    pub fn wfx_total_len(&self) -> u32 {
        18 + self.extradata.len() as u32
    }

    /// Build an AMT blueprint shaped so `msadds32.ax`'s WMA
    /// splitter's `CompleteConnect` (`inner.vtable[12]` at RVA
    /// `0x2057` in the wmpcdcs8-2001 build) accepts it.  Round 60
    /// reverse-engineered that callee:
    ///
    /// ```text
    /// CompleteConnect(pConnector):
    ///   pConnector->ConnectionMediaType(&amt);
    ///   pbFormat = amt.pbFormat;
    ///   switch (wFormatTag at [pbFormat]) {
    ///     case 0x0160 (WMA1):
    ///       if (cbSize < 0x29) goto fail;
    ///       if (memcmp(pbFormat + 0x16, "1A0F78F0-EC8A-11d2-BBBE-006008320064\0", 0x25) != 0)
    ///         goto fail;
    ///     case 0x0161 (WMA2):
    ///       if (cbSize < 0x2F) goto fail;
    ///       if (memcmp(pbFormat + 0x1C, "1A0F78F0-EC8A-11d2-BBBE-006008320064\0", 0x25) != 0)
    ///         goto fail;
    ///     default: return E_UNEXPECTED;
    ///   }
    /// ```
    ///
    /// The "magic CLSID" is the codec's expected
    /// `WindowsMediaAudioDecoder` registration GUID.  It is the
    /// SAME 37-byte ASCII string for both WMA1 and WMA2; only
    /// the in-extradata offset differs (4 for WMA1, 10 for WMA2)
    /// because the extradata preamble itself differs in size.
    ///
    /// On success the WAVEFORMATEX has:
    ///   - `wFormatTag = tag` (must be 0x0160 or 0x0161)
    ///   - `cbSize = 0x29` (WMA1) or `0x2F` (WMA2)
    ///   - `extradata = <preamble> ++ "1A0F78F0-EC8A-11d2-BBBE-006008320064\0"`
    ///
    /// The preamble bytes (4 for WMA1, 10 for WMA2) are zeroed
    /// here — the validator does not constrain them; the codec's
    /// internal decoder reads them as `SamplesPerBlock` /
    /// `EncodeOptions`, but [`AmtBlueprint::wma_criteria_passing`]
    /// is for the AMT-acceptance gate only.  Callers driving real
    /// decode should populate the preamble with values matching
    /// the bitstream's actual codec parameters.
    pub fn wma_criteria_passing(
        format_tag: u16,
        n_channels: u16,
        n_samples_per_sec: u32,
        n_avg_bytes_per_sec: u32,
        n_block_align: u16,
    ) -> Self {
        const MAGIC_CLSID: &[u8; 37] = b"1A0F78F0-EC8A-11d2-BBBE-006008320064\0";
        let preamble_len = match format_tag {
            0x0160 => 4,
            0x0161 => 10,
            _ => 10, // best-effort default; non-WMA tag will fail anyway
        };
        let mut extradata = vec![0u8; preamble_len];
        extradata.extend_from_slice(MAGIC_CLSID);
        AmtBlueprint {
            format_tag,
            n_channels,
            n_samples_per_sec,
            n_avg_bytes_per_sec,
            n_block_align,
            w_bits_per_sample: 16,
            extradata,
        }
    }

    /// Round-68 successor of [`Self::wma_criteria_passing`].  Same
    /// 37-byte magic CLSID suffix the splitter's `CompleteConnect`
    /// validator demands, but the codec-private-data preamble is
    /// populated with the bytes a real ffmpeg-produced WMA fixture
    /// emits, instead of all-zero.
    ///
    /// ## Why this matters
    ///
    /// The round-60 `wma_criteria_passing` constructor satisfies the
    /// `inner.vtable[12]` `CompleteConnect` validator (RVA `0x2057`)
    /// but uses an all-zero codec-private-data preamble.  Round 64
    /// (see `docs/codec/msadds32-receive-e-unexpected.md`) pinned the
    /// `Receive` `E_UNEXPECTED` bail-out at RVA `0x172f` to the
    /// inner-decode-no-output guard: the codec accepts our WMA2
    /// frame, the inner decode at RVA `0xc887` returns `eax = 0`,
    /// but the "samples produced" out-pointer stays NULL and two
    /// consecutive zero-output iterations make the outer loop bail.
    ///
    /// The round-64 hand-off ranked four candidates; rounds 64+65
    /// falsified candidates (1) JoinFilterGraph and (3) ASF Payload
    /// Parsing strip.  Candidate (2) — codec-private-data missing
    /// at the WAVEFORMATEX tail — is what this constructor probes.
    ///
    /// ## Empirical preamble bytes (per ffmpeg-emitted fixtures)
    ///
    /// Sourced from the round-59 `tests/fixtures/audio/wma{1,2}…wma`
    /// blobs ffmpeg generated at codec-bringup time:
    ///
    /// | tag    | preamble (hex)                  | meaning (per public Windows Media Audio spec) |
    /// |--------|---------------------------------|----------------------------------------------|
    /// | 0x0160 | `00 00 01 00`                   | sample-rate-class (?) = `0x0001_0000`        |
    /// | 0x0161 | `00 00 00 00 01 00 00 00 00 00` | encoder version flags (?) = `0x0000_0001`    |
    ///
    /// Both layouts preserve the 37-byte CLSID suffix the validator
    /// demands.  WMA1 emits cbSize = 41 (4 + 37), WMA2 emits
    /// cbSize = 47 (10 + 37).
    ///
    /// ## Reference material (clean-room only)
    ///
    /// * `mmreg.h` — `WAVEFORMATEX` layout (public Microsoft).
    /// * Microsoft Windows Media Audio public spec — codec-private
    ///   block field meanings (sample-rate-class, encoder version).
    /// * Raw bytes of ffmpeg-generated WMA1/WMA2 fixtures stored at
    ///   `tests/fixtures/audio/`.
    ///
    /// No Wine / ReactOS / MinGW / Microsoft codec source consulted.
    pub fn wma_with_ffmpeg_extradata_prefix(
        format_tag: u16,
        n_channels: u16,
        n_samples_per_sec: u32,
        n_avg_bytes_per_sec: u32,
        n_block_align: u16,
    ) -> Self {
        const MAGIC_CLSID: &[u8; 37] = b"1A0F78F0-EC8A-11d2-BBBE-006008320064\0";
        let preamble: &[u8] = match format_tag {
            0x0160 => &[0x00, 0x00, 0x01, 0x00],
            0x0161 => &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
            _ => &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
        };
        let mut extradata = Vec::with_capacity(preamble.len() + MAGIC_CLSID.len());
        extradata.extend_from_slice(preamble);
        extradata.extend_from_slice(MAGIC_CLSID);
        AmtBlueprint {
            format_tag,
            n_channels,
            n_samples_per_sec,
            n_avg_bytes_per_sec,
            n_block_align,
            w_bits_per_sample: 16,
            extradata,
        }
    }
}

/// Walk the ASF byte stream `bytes`, find the audio Stream
/// Properties Object, and decode its `WAVEFORMATEX` +
/// `cbSize`-bytes-of-extradata trailer into an [`AmtBlueprint`].
///
/// Failures pinpoint the exact ASF-spec rule the input violated;
/// see [`AsfParseError`].
pub fn extract_wma_amt_from_asf(bytes: &[u8]) -> Result<AmtBlueprint, AsfParseError> {
    if bytes.len() < 30 {
        return Err(AsfParseError::TruncatedHeader);
    }
    let leading_guid = read_guid(bytes, 0).ok_or(AsfParseError::TruncatedHeader)?;
    if leading_guid != ASF_HEADER_OBJECT {
        return Err(AsfParseError::NotAnAsfFile);
    }
    let header_obj_size = read_u64_le(bytes, 16).ok_or(AsfParseError::TruncatedHeader)?;
    if header_obj_size < 30 || header_obj_size > bytes.len() as u64 {
        return Err(AsfParseError::InvalidHeaderObjectSize {
            declared: header_obj_size,
            buffer: bytes.len(),
        });
    }
    // Walk sub-objects starting at byte 30, ending at byte
    // header_obj_size.
    let mut cursor: u64 = 30;
    let end = header_obj_size;
    while cursor + 24 <= end {
        let off = cursor as usize;
        let sub_guid = read_guid(bytes, off).ok_or(AsfParseError::TruncatedHeader)?;
        let sub_size = read_u64_le(bytes, off + 16).ok_or(AsfParseError::TruncatedHeader)?;
        if sub_size < 24 {
            return Err(AsfParseError::InvalidSubObjectSize { declared: sub_size });
        }
        if cursor + sub_size > end {
            return Err(AsfParseError::SubObjectOverflowsHeader {
                needed: sub_size,
                remaining: end - cursor,
            });
        }
        if sub_guid == ASF_STREAM_PROPERTIES_OBJECT {
            // Stream Properties Object layout (ASF §3.3):
            //   [+0  16] Object ID GUID
            //   [+16  8] Object Size
            //   [+24 16] Stream Type GUID  (e.g. ASF_AUDIO_MEDIA)
            //   [+40 16] Error Correction Type GUID
            //   [+56  8] Time Offset
            //   [+64  4] Type-Specific Data Length
            //   [+68  4] Error Correction Data Length
            //   [+72  2] Flags
            //   [+74  4] Reserved
            //   [+78  N] Type-Specific Data
            //   [+78+N M] Error Correction Data
            if sub_size < 78 {
                return Err(AsfParseError::StreamPropertiesTooShort { len: sub_size });
            }
            let stream_type = read_guid(bytes, off + 24).ok_or(AsfParseError::TruncatedHeader)?;
            if stream_type == ASF_AUDIO_MEDIA {
                let tsd_len = read_u32_le(bytes, off + 64).ok_or(AsfParseError::TruncatedHeader)?;
                if (tsd_len as u64) + 78 > sub_size {
                    return Err(AsfParseError::StreamPropertiesTooShort { len: sub_size });
                }
                if tsd_len < 18 {
                    return Err(AsfParseError::TypeSpecificDataTooShort { len: tsd_len });
                }
                let wfx_off = off + 78;
                let format_tag =
                    read_u16_le(bytes, wfx_off).ok_or(AsfParseError::TruncatedHeader)?;
                let n_channels =
                    read_u16_le(bytes, wfx_off + 2).ok_or(AsfParseError::TruncatedHeader)?;
                let n_samples_per_sec =
                    read_u32_le(bytes, wfx_off + 4).ok_or(AsfParseError::TruncatedHeader)?;
                let n_avg_bytes_per_sec =
                    read_u32_le(bytes, wfx_off + 8).ok_or(AsfParseError::TruncatedHeader)?;
                let n_block_align =
                    read_u16_le(bytes, wfx_off + 12).ok_or(AsfParseError::TruncatedHeader)?;
                let w_bits_per_sample =
                    read_u16_le(bytes, wfx_off + 14).ok_or(AsfParseError::TruncatedHeader)?;
                let cb_size =
                    read_u16_le(bytes, wfx_off + 16).ok_or(AsfParseError::TruncatedHeader)?;
                let available_extra = tsd_len.saturating_sub(18);
                if cb_size as u32 > available_extra {
                    return Err(AsfParseError::WaveFormatExtraOverflow {
                        cb_size,
                        available: available_extra,
                    });
                }
                let extra_start = wfx_off + 18;
                let extra_end = extra_start + cb_size as usize;
                let extradata = bytes[extra_start..extra_end].to_vec();
                return Ok(AmtBlueprint {
                    format_tag,
                    n_channels,
                    n_samples_per_sec,
                    n_avg_bytes_per_sec,
                    n_block_align,
                    w_bits_per_sample,
                    extradata,
                });
            }
        }
        cursor += sub_size;
    }
    Err(AsfParseError::NoAudioStream)
}

/// Locate the first audio *Data Packet* payload in an ASF byte
/// stream.  Returns a borrowed slice covering one full data
/// packet, including its packet header — callers can do a minimal
/// extraction of the encoded audio frames inside.
///
/// The Data Object's GUID is
/// `{75B22636-668E-11CF-A6D9-00AA0062CE6C}` (ASF spec §3.7).  Its
/// preamble:
///   [+0  16] Object ID
///   [+16  8] Object Size
///   [+24 16] File ID
///   [+40  8] Total Data Packets
///   [+48  2] Reserved
///   [+50 ..] N data packets, each `Min Packet Size` bytes
/// On well-formed ASF/WMA files written by ffmpeg the packet size
/// is constant; we ignore variable-size streaming files for the
/// round-59 scope.  Caller can read the File Properties Object's
/// `Min Data Packet Size` ahead of time to size the slice
/// precisely; for round-59 we just take the first 4 KiB after the
/// Data Object preamble, which always covers a full first packet
/// for the small fixtures we ship.
pub fn locate_first_data_packet(bytes: &[u8]) -> Option<&[u8]> {
    const ASF_DATA_OBJECT: Guid = Guid::new(
        0x75B2_2636,
        0x668E,
        0x11CF,
        [0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C],
    );
    let header_obj_size = read_u64_le(bytes, 16)? as usize;
    if header_obj_size + 24 > bytes.len() {
        return None;
    }
    let off = header_obj_size;
    let g = read_guid(bytes, off)?;
    if g != ASF_DATA_OBJECT {
        return None;
    }
    let data_obj_size = read_u64_le(bytes, off + 16)? as usize;
    if off + data_obj_size > bytes.len() {
        return None;
    }
    // Data Object preamble is 50 bytes; first packet starts at
    // `off + 50`.
    let first = off + 50;
    if first >= bytes.len() {
        return None;
    }
    Some(&bytes[first..(off + data_obj_size).min(bytes.len())])
}

// ---- byte-level helpers ----------------------------------------------

fn read_guid(bytes: &[u8], at: usize) -> Option<Guid> {
    if at + 16 > bytes.len() {
        return None;
    }
    Guid::read_le(&bytes[at..at + 16])
}

fn read_u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    if at + 2 > bytes.len() {
        return None;
    }
    Some(u16::from_le_bytes([bytes[at], bytes[at + 1]]))
}

fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    if at + 4 > bytes.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
    ]))
}

fn read_u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    if at + 8 > bytes.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny synthetic ASF byte stream: Header Object containing
    /// one Stream Properties Object describing a synthetic WMA1
    /// audio stream with 4 bytes of extradata.  Built by hand so
    /// the parser tests are independent of the ffmpeg fixture.
    fn synthetic_wma1_asf() -> Vec<u8> {
        let mut out = Vec::new();
        // Header Object GUID + size placeholder + NumHeaderObjects + reserved.
        out.extend_from_slice(&ASF_HEADER_OBJECT.write_le());
        let size_off = out.len();
        out.extend_from_slice(&0u64.to_le_bytes()); // placeholder for size
        out.extend_from_slice(&1u32.to_le_bytes()); // NumHeaderObjects = 1
        out.push(0x01); // Reserved1
        out.push(0x02); // Reserved2
                        // --- Stream Properties Object ---
        let spo_start = out.len();
        out.extend_from_slice(&ASF_STREAM_PROPERTIES_OBJECT.write_le()); // GUID
        let spo_size_off = out.len();
        out.extend_from_slice(&0u64.to_le_bytes()); // size placeholder
        out.extend_from_slice(&ASF_AUDIO_MEDIA.write_le()); // Stream Type
        out.extend_from_slice(&[0u8; 16]); // ECC type GUID (irrelevant)
        out.extend_from_slice(&0u64.to_le_bytes()); // Time Offset
        out.extend_from_slice(&22u32.to_le_bytes()); // Type-Specific Data Length: WFX(18)+4
        out.extend_from_slice(&0u32.to_le_bytes()); // ECC Data Length
        out.extend_from_slice(&0u16.to_le_bytes()); // Flags
        out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
                                                    // WAVEFORMATEX (18 bytes) + 4-byte extra:
        out.extend_from_slice(&0x0160u16.to_le_bytes()); // WMA1
        out.extend_from_slice(&1u16.to_le_bytes()); // 1 channel
        out.extend_from_slice(&44_100u32.to_le_bytes()); // 44.1 kHz
        out.extend_from_slice(&4_000u32.to_le_bytes()); // 32 kbit/s
        out.extend_from_slice(&185u16.to_le_bytes()); // block align
        out.extend_from_slice(&16u16.to_le_bytes()); // bits-per-sample
        out.extend_from_slice(&4u16.to_le_bytes()); // cbSize=4
        out.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // extradata
        let spo_size = (out.len() - spo_start) as u64;
        out[spo_size_off..spo_size_off + 8].copy_from_slice(&spo_size.to_le_bytes());
        // patch header object size
        let total = out.len() as u64;
        out[size_off..size_off + 8].copy_from_slice(&total.to_le_bytes());
        out
    }

    #[test]
    fn wma_with_ffmpeg_extradata_prefix_wma1_layout() {
        let bp = AmtBlueprint::wma_with_ffmpeg_extradata_prefix(0x0160, 1, 44_100, 4_000, 185);
        assert_eq!(bp.format_tag, 0x0160);
        assert_eq!(bp.extradata.len(), 4 + 37);
        // Preamble: ffmpeg-emitted bytes
        assert_eq!(&bp.extradata[0..4], &[0x00, 0x00, 0x01, 0x00]);
        // CLSID suffix: magic the splitter validator demands
        assert_eq!(
            &bp.extradata[4..],
            b"1A0F78F0-EC8A-11d2-BBBE-006008320064\0"
        );
        // cbSize gate: the round-60 validator requires >= 0x29 (41).
        assert!(bp.extradata.len() >= 0x29);
        assert_eq!(bp.wfx_total_len(), 18 + 41);
    }

    #[test]
    fn wma_with_ffmpeg_extradata_prefix_wma2_layout() {
        let bp = AmtBlueprint::wma_with_ffmpeg_extradata_prefix(0x0161, 1, 44_100, 4_000, 185);
        assert_eq!(bp.format_tag, 0x0161);
        assert_eq!(bp.extradata.len(), 10 + 37);
        // Preamble: ffmpeg-emitted bytes — only offset 4 non-zero.
        assert_eq!(
            &bp.extradata[0..10],
            &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        // CLSID suffix: magic the splitter validator demands
        assert_eq!(
            &bp.extradata[10..],
            b"1A0F78F0-EC8A-11d2-BBBE-006008320064\0"
        );
        // cbSize gate: the round-60 validator requires >= 0x2F (47).
        assert!(bp.extradata.len() >= 0x2F);
        assert_eq!(bp.wfx_total_len(), 18 + 47);
    }

    #[test]
    fn extract_from_synthetic_wma1_blob() {
        let blob = synthetic_wma1_asf();
        let bp = extract_wma_amt_from_asf(&blob).unwrap();
        assert_eq!(bp.format_tag, 0x0160);
        assert_eq!(bp.n_channels, 1);
        assert_eq!(bp.n_samples_per_sec, 44_100);
        assert_eq!(bp.n_avg_bytes_per_sec, 4_000);
        assert_eq!(bp.n_block_align, 185);
        assert_eq!(bp.w_bits_per_sample, 16);
        assert_eq!(bp.extradata, vec![0x00, 0x00, 0x01, 0x00]);
        assert_eq!(bp.wfx_total_len(), 22);
    }

    #[test]
    fn truncated_buffer_rejected() {
        let err = extract_wma_amt_from_asf(&[0u8; 10]).unwrap_err();
        assert_eq!(err, AsfParseError::TruncatedHeader);
    }

    #[test]
    fn non_asf_file_rejected() {
        // 30 bytes that do not start with the Header Object GUID.
        let mut bad = vec![0xAAu8; 30];
        bad[16..24].copy_from_slice(&30u64.to_le_bytes());
        let err = extract_wma_amt_from_asf(&bad).unwrap_err();
        assert_eq!(err, AsfParseError::NotAnAsfFile);
    }

    #[test]
    fn header_object_guids_round_trip_via_braced_form() {
        assert_eq!(
            ASF_HEADER_OBJECT.to_braced_string(),
            "{75B22630-668E-11CF-A6D9-00AA0062CE6C}"
        );
        assert_eq!(
            ASF_STREAM_PROPERTIES_OBJECT.to_braced_string(),
            "{B7DC0791-A9B7-11CF-8EE6-00C00C205365}"
        );
        assert_eq!(
            ASF_AUDIO_MEDIA.to_braced_string(),
            "{F8699E40-5B4D-11CF-A8FD-00805F5C442B}"
        );
    }

    #[test]
    fn header_with_no_audio_stream_rejected() {
        // Header object with zero sub-objects.
        let mut blob = Vec::new();
        blob.extend_from_slice(&ASF_HEADER_OBJECT.write_le());
        blob.extend_from_slice(&30u64.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.push(0);
        blob.push(0);
        let err = extract_wma_amt_from_asf(&blob).unwrap_err();
        assert_eq!(err, AsfParseError::NoAudioStream);
    }
}
