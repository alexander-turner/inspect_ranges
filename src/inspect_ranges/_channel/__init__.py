"""Range channel: protocol v3, codec, channel client, and conformance mocks.

The wire contract is specified in `design/inspect-ranges/range-channel.md` and the phase plan in `design/inspect-ranges/channel-v1.md`. Everything arriving over the channel is untrusted input: replies are strict-schema validated and byte caps are enforced reader-side.
"""

from .codec import (
    BulkMismatch,
    BulkOverrun,
    ChannelClosed,
    DecodeError,
    EncodeError,
    FrameTooLarge,
    FrameType,
    InvalidMessage,
    MessageStreamReader,
    ProtocolViolation,
    TraceEvent,
    TruncatedFrame,
    decode_frames,
    encode_message,
)
from .protocol import PROTOCOL_VERSION, Budget, Message

__all__ = [
    "Budget",
    "BulkMismatch",
    "BulkOverrun",
    "ChannelClosed",
    "DecodeError",
    "EncodeError",
    "FrameTooLarge",
    "FrameType",
    "InvalidMessage",
    "Message",
    "MessageStreamReader",
    "PROTOCOL_VERSION",
    "ProtocolViolation",
    "TraceEvent",
    "TruncatedFrame",
    "decode_frames",
    "encode_message",
]
