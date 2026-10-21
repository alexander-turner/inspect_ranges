"""Sample-metadata keys shared across layers that must not import each other.

`challenge_dataset` (the challenges layer) writes these into Inspect sample metadata; the provider reads them at `sample_init`. A shared zero-dependency home keeps the dataset import graph free of the provider/sandbox stack and vice versa.
"""

PROBE_SEGMENTS_METADATA_KEY = "inspect_ranges:probe_segments"
"""Comma-joined networks whose probe endpoints the sample's challenge needs (from its `active-prober` goals); the provider threads them into render-time plan options, so a challenge's observer needs become plan options without the compiler ever seeing challenges."""

RANGE_SPEC_METADATA_KEY = "inspect_ranges:range_spec"
"""The sample's range definition as YAML text (the file's verbatim text for a path, a serialization for a typed spec), written by `challenge_dataset` when it was given a `range_spec`; `range_apparatus` reads it so after-the-fact scans need no explicit spec."""
