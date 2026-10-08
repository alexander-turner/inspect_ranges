// Package main implements vsockd v3, the in-guest control daemon.
//
// This file is the wire codec: protocol v3 framing and message schemas,
// byte-compatible with the Python reference (src/inspect_ranges/_channel/
// protocol.py, codec.py) and pinned by the shared vectors in
// tests/wire_vectors/v3.json. Canonical JSON: sorted keys, compact
// separators, raw UTF-8 (no HTML escaping), null optionals omitted on
// encode and REJECTED on decode; v is required; duplicate keys rejected;
// unknown fields, cross-kind fields, and missing per-kind required fields
// are rejected by the per-kind field table, mirroring the Python schema
// (implementation note for the C# port: copy the table, not the struct).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
)

const (
	ProtocolVersion   = 3
	MaxFramePayload   = 32 * 1024
	MaxBulkDeclarable = 1 << 30
	MaxWireInt        = int64(1) << 53
	DefaultBulkCap    = 16 * 1024 * 1024
	DefaultUntimedMs  = 14_400_000
)

const (
	FrameControl byte = 0x43
	FrameData    byte = 0x44
	FrameEnd     byte = 0x45
)

var (
	requestIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	errnoRe     = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,15}$`)
	sha256Re    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// DecodeError is the typed failure for every malformed input; the daemon
// hardens its decode path even though its peer is the trusted host.
type DecodeError struct{ Reason string }

func (e *DecodeError) Error() string { return "decode: " + e.Reason }

func decodeErrf(format string, args ...any) error {
	return &DecodeError{Reason: fmt.Sprintf(format, args...)}
}

// Message is one protocol v3 message of any kind. Optional fields are
// pointers so encode can omit them (never emit null) and decode can
// distinguish absent from zero.
type Message struct {
	V    int    `json:"v"`
	ID   string `json:"id"`
	Kind string `json:"kind"`

	DataSize *int64 `json:"data_size,omitempty"`

	// exec / read_file / write_file / forward
	Cmd      []string          `json:"cmd,omitempty"`
	Cwd      *string           `json:"cwd,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	User     *string           `json:"user,omitempty"`
	Budget   *Budget           `json:"budget,omitempty"`
	Path     string            `json:"path,omitempty"`
	MaxBytes *int64            `json:"max_bytes,omitempty"`
	Host     string            `json:"host,omitempty"`
	Port     *int64            `json:"port,omitempty"`

	// poll / ack / pending / forward_ok
	TargetID  string `json:"target_id,omitempty"`
	ElapsedMs *int64 `json:"elapsed_ms,omitempty"`
	Handle    string `json:"handle,omitempty"`

	// diag
	MaxEntries *int64      `json:"max_entries,omitempty"`
	Entries    []DiagEntry `json:"entries,omitempty"`

	// pong
	Daemon   string `json:"daemon,omitempty"`
	Protocol *int64 `json:"protocol,omitempty"`

	// exec_result / file_data
	Rc              *int64 `json:"rc,omitempty"`
	StdoutSize      *int64 `json:"stdout_size,omitempty"`
	StderrSize      *int64 `json:"stderr_size,omitempty"`
	StdoutTruncated *bool  `json:"stdout_truncated,omitempty"`
	StderrTruncated *bool  `json:"stderr_truncated,omitempty"`
	Size            *int64 `json:"size,omitempty"`
	Truncated       *bool  `json:"truncated,omitempty"`

	// error
	Errno   string  `json:"errno,omitempty"`
	Message string  `json:"message,omitempty"`
	Layer   *string `json:"layer,omitempty"`

	// host plane
	BundleDigest string            `json:"bundle_digest,omitempty"`
	Grants       []string          `json:"grants,omitempty"`
	Stage        string            `json:"stage,omitempty"`
	Detail       *string           `json:"detail,omitempty"`
	Guests       map[string]string `json:"guests,omitempty"`
	UptimeMs     *int64            `json:"uptime_ms,omitempty"`
}

// Budget mirrors protocol.Budget; nil pointers encode as absent.
type Budget struct {
	CommandMs      *int64 `json:"command_ms,omitempty"`
	ChannelMs      *int64 `json:"channel_ms,omitempty"`
	UntimedBoundMs *int64 `json:"untimed_bound_ms,omitempty"`
}

// DiagEntry mirrors protocol.DiagEntry.
type DiagEntry struct {
	TsMs      int64   `json:"ts_ms"`
	Level     string  `json:"level"`
	Event     string  `json:"event"`
	RequestID *string `json:"request_id,omitempty"`
	Detail    string  `json:"detail"`
}

func i64(v int64) *int64    { return &v }
func strp(v string) *string { return &v }
func boolp(v bool) *bool    { return &v }

// ---------------------------------------------------------------------------
// canonical JSON
// ---------------------------------------------------------------------------

// canonicalJSON encodes a value as sorted-key compact UTF-8 JSON. Maps sort
// natively under encoding/json; HTML escaping is disabled to match Python's
// ensure_ascii=False output.
func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// controlMap converts a Message to the map that canonical encoding needs:
// only set fields, defaults materialized (the wire always carries defaults
// the Python encoder emits, e.g. budget sub-fields that are set).
func (m *Message) controlMap() (map[string]any, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	// struct marshal omits empty strings for required fields like detail "";
	// re-add the always-present fields the Python encoder emits
	switch m.Kind {
	case "stage":
		if _, ok := out["detail"]; !ok {
			out["detail"] = ""
		}
		if _, ok := out["guests"]; !ok {
			out["guests"] = map[string]any{}
		}
	case "heartbeat":
		if _, ok := out["guests"]; !ok {
			out["guests"] = map[string]any{}
		}
	case "exec":
		if _, ok := out["env"]; !ok {
			out["env"] = map[string]any{}
		}
		if _, ok := out["budget"]; !ok {
			out["budget"] = map[string]any{"untimed_bound_ms": DefaultUntimedMs}
		}
	case "read_file", "write_file", "forward":
		if _, ok := out["budget"]; !ok {
			out["budget"] = map[string]any{"untimed_bound_ms": DefaultUntimedMs}
		}
	case "exec_result":
		if _, ok := out["stdout_truncated"]; !ok {
			out["stdout_truncated"] = false
		}
		if _, ok := out["stderr_truncated"]; !ok {
			out["stderr_truncated"] = false
		}
	case "file_data":
		if _, ok := out["truncated"]; !ok {
			out["truncated"] = false
		}
	case "realize":
		if _, ok := out["grants"]; !ok {
			out["grants"] = []any{}
		}
	case "pong":
		if _, ok := out["protocol"]; !ok {
			out["protocol"] = ProtocolVersion
		}
	case "diag":
		if _, ok := out["max_entries"]; !ok {
			out["max_entries"] = 100
		}
	case "diag_result":
		if _, ok := out["entries"]; !ok {
			out["entries"] = []any{}
		}
	}
	if budget, ok := out["budget"].(map[string]any); ok {
		if _, set := budget["untimed_bound_ms"]; !set {
			budget["untimed_bound_ms"] = DefaultUntimedMs
		}
	}
	return out, nil
}

// EncodeMessage renders a message (and optional bulk) into wire frames.
func EncodeMessage(m *Message, bulk []byte) ([]byte, error) {
	if m.DataSize == nil && bulk != nil {
		return nil, fmt.Errorf("%s: bulk supplied but data_size is nil", m.Kind)
	}
	if m.DataSize != nil && int64(len(bulk)) != *m.DataSize {
		return nil, fmt.Errorf("%s: data_size=%d but bulk is %d bytes", m.Kind, *m.DataSize, len(bulk))
	}
	control, err := m.controlMap()
	if err != nil {
		return nil, err
	}
	payload, err := canonicalJSON(control)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxFramePayload {
		return nil, fmt.Errorf("%s: control payload %d exceeds frame cap", m.Kind, len(payload))
	}
	var out bytes.Buffer
	writeFrame(&out, FrameControl, payload)
	if m.DataSize != nil {
		for offset := 0; offset < len(bulk); offset += MaxFramePayload {
			end := offset + MaxFramePayload
			if end > len(bulk) {
				end = len(bulk)
			}
			writeFrame(&out, FrameData, bulk[offset:end])
		}
		digest := sha256.Sum256(bulk)
		endPayload, err := canonicalJSON(map[string]any{
			"sha256": hex.EncodeToString(digest[:]),
			"size":   *m.DataSize,
		})
		if err != nil {
			return nil, err
		}
		writeFrame(&out, FrameEnd, endPayload)
	}
	return out.Bytes(), nil
}

func writeFrame(out *bytes.Buffer, frameType byte, payload []byte) {
	var header [5]byte
	binary.BigEndian.PutUint32(header[:4], uint32(len(payload)))
	header[4] = frameType
	out.Write(header[:])
	out.Write(payload)
}

// ---------------------------------------------------------------------------
// decode
// ---------------------------------------------------------------------------

// FrameReader reads frames from an untrusted byte stream, checking the
// length field against the cap before buffering the payload.
type FrameReader struct{ r io.Reader }

func NewFrameReader(r io.Reader) *FrameReader { return &FrameReader{r: r} }

func (fr *FrameReader) Read() (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(fr.r, header[:]); err != nil {
		if err == io.EOF {
			return 0, nil, io.EOF
		}
		return 0, nil, decodeErrf("truncated frame header: %v", err)
	}
	length := binary.BigEndian.Uint32(header[:4])
	if length > MaxFramePayload {
		return 0, nil, decodeErrf("frame declares %d bytes (cap %d)", length, MaxFramePayload)
	}
	frameType := header[4]
	if frameType != FrameControl && frameType != FrameData && frameType != FrameEnd {
		return 0, nil, decodeErrf("unknown frame type 0x%02x", frameType)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return 0, nil, decodeErrf("truncated frame payload: %v", err)
	}
	return frameType, payload, nil
}

// ReadMessage reads one full message (control + optional bulk) from the
// stream, enforcing the reader-side bulk cap and the END digest.
func ReadMessage(fr *FrameReader, bulkCap int64) (*Message, []byte, error) {
	frameType, payload, err := fr.Read()
	if err != nil {
		return nil, nil, err
	}
	if frameType != FrameControl {
		return nil, nil, decodeErrf("expected CONTROL frame, got 0x%02x", frameType)
	}
	message, err := ParseControl(payload)
	if err != nil {
		return nil, nil, err
	}
	if message.DataSize == nil {
		return message, nil, nil
	}
	declared := *message.DataSize
	var bulk bytes.Buffer
	for {
		frameType, payload, err = fr.Read()
		if err != nil {
			if err == io.EOF {
				return nil, nil, decodeErrf("stream ended mid-bulk")
			}
			return nil, nil, err
		}
		switch frameType {
		case FrameData:
			if int64(bulk.Len()+len(payload)) > bulkCap {
				return nil, nil, decodeErrf("bulk exceeds reader cap %d", bulkCap)
			}
			if int64(bulk.Len()+len(payload)) > declared {
				return nil, nil, decodeErrf("bulk exceeds declared data_size %d", declared)
			}
			bulk.Write(payload)
		case FrameEnd:
			endSha, endSize, err := parseEnd(payload)
			if err != nil {
				return nil, nil, err
			}
			if endSize != int64(bulk.Len()) || int64(bulk.Len()) != declared {
				return nil, nil, decodeErrf("bulk size mismatch declared=%d received=%d end=%d", declared, bulk.Len(), endSize)
			}
			digest := sha256.Sum256(bulk.Bytes())
			if hex.EncodeToString(digest[:]) != endSha {
				return nil, nil, decodeErrf("bulk sha256 mismatch")
			}
			return message, bulk.Bytes(), nil
		default:
			return nil, nil, decodeErrf("CONTROL frame inside bulk transfer")
		}
	}
}

// ParseControl parses and strictly validates a control payload.
func ParseControl(payload []byte) (*Message, error) {
	if err := scanStrict(payload); err != nil {
		return nil, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil, decodeErrf("control payload is not a JSON object: %v", err)
	}
	var version int64
	if raw, ok := probe["v"]; !ok {
		return nil, decodeErrf("control payload must carry v=%d, got absent", ProtocolVersion)
	} else if err := json.Unmarshal(raw, &version); err != nil || version != ProtocolVersion {
		return nil, decodeErrf("control payload must carry v=%d", ProtocolVersion)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var message Message
	if err := decoder.Decode(&message); err != nil {
		return nil, decodeErrf("schema violation: %v", err)
	}
	keys := make(map[string]bool, len(probe))
	for key := range probe {
		keys[key] = true
	}
	if err := validateFields(message.Kind, keys); err != nil {
		return nil, err
	}
	if err := message.validate(); err != nil {
		return nil, err
	}
	return &message, nil
}

// kindSpec mirrors the Python per-kind schema: which fields a kind requires
// and which it may carry; everything else is a cross-kind violation.
type kindSpec struct {
	required []string
	optional []string
}

var kindFields = map[string]kindSpec{
	"ping":        {},
	"pong":        {required: []string{"daemon"}, optional: []string{"protocol"}},
	"exec":        {required: []string{"cmd"}, optional: []string{"cwd", "env", "user", "budget"}},
	"read_file":   {required: []string{"path"}, optional: []string{"max_bytes", "budget"}},
	"write_file":  {required: []string{"path"}, optional: []string{"budget"}},
	"forward":     {required: []string{"host", "port"}, optional: []string{"budget"}},
	"poll":        {required: []string{"target_id"}},
	"ack":         {required: []string{"target_id"}},
	"diag":        {optional: []string{"max_entries"}},
	"exec_result": {required: []string{"rc", "stdout_size", "stderr_size"}, optional: []string{"stdout_truncated", "stderr_truncated"}},
	"file_data":   {required: []string{"size"}, optional: []string{"truncated"}},
	"ok":          {},
	"pending":     {required: []string{"target_id", "elapsed_ms"}},
	"forward_ok":  {required: []string{"handle"}},
	"diag_result": {optional: []string{"entries"}},
	"error":       {required: []string{"errno", "message"}, optional: []string{"layer"}},
	"realize":     {required: []string{"bundle_digest"}, optional: []string{"grants"}},
	"teardown":    {},
	"stage":       {required: []string{"stage"}, optional: []string{"detail", "guests"}},
	"heartbeat":   {required: []string{"uptime_ms"}, optional: []string{"guests"}},
}

func validateFields(kind string, keys map[string]bool) error {
	spec, ok := kindFields[kind]
	if !ok {
		return decodeErrf("unknown kind %q", kind)
	}
	allowed := map[string]bool{"v": true, "id": true, "kind": true}
	if bulkKinds[kind] {
		allowed["data_size"] = true
	}
	for _, name := range spec.required {
		allowed[name] = true
		if !keys[name] {
			return decodeErrf("%s: missing required field %q", kind, name)
		}
	}
	for _, name := range spec.optional {
		allowed[name] = true
	}
	for key := range keys {
		if !allowed[key] {
			return decodeErrf("%s: field %q does not belong to this kind", kind, key)
		}
	}
	return nil
}

// scanStrict walks the raw JSON once, rejecting duplicate keys and explicit
// nulls anywhere (an honest encoder emits neither).
func scanStrict(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return decodeErrf("not JSON: %v", err)
		}
		switch tok := token.(type) {
		case json.Delim:
			switch tok {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					keyToken, err := decoder.Token()
					if err != nil {
						return decodeErrf("not JSON: %v", err)
					}
					key, ok := keyToken.(string)
					if !ok {
						return decodeErrf("non-string object key")
					}
					if seen[key] {
						return decodeErrf("duplicate JSON key %q", key)
					}
					seen[key] = true
					if err := walk(); err != nil {
						return err
					}
				}
				if _, err := decoder.Token(); err != nil {
					return decodeErrf("not JSON: %v", err)
				}
			case '[':
				for decoder.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				if _, err := decoder.Token(); err != nil {
					return decodeErrf("not JSON: %v", err)
				}
			}
		case nil:
			return decodeErrf("explicit null in control payload")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if decoder.More() {
		return decodeErrf("trailing data after JSON document")
	}
	return nil
}

func parseEnd(payload []byte) (string, int64, error) {
	if err := scanStrict(payload); err != nil {
		return "", 0, err
	}
	var end struct {
		Sha256 *string `json:"sha256"`
		Size   *int64  `json:"size"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&end); err != nil || end.Sha256 == nil || end.Size == nil {
		return "", 0, decodeErrf("END payload must be exactly {sha256, size}")
	}
	if !sha256Re.MatchString(*end.Sha256) || *end.Size < 0 || *end.Size > MaxBulkDeclarable {
		return "", 0, decodeErrf("END payload out of bounds")
	}
	return *end.Sha256, *end.Size, nil
}

// ---------------------------------------------------------------------------
// validation (mirrors the pydantic schema rules the vectors pin)
// ---------------------------------------------------------------------------

var bulkKinds = map[string]bool{
	"exec": true, "write_file": true, "exec_result": true, "file_data": true,
}

var allKinds = map[string]bool{
	"ping": true, "exec": true, "read_file": true, "write_file": true,
	"forward": true, "poll": true, "ack": true, "diag": true,
	"pong": true, "exec_result": true, "file_data": true, "ok": true,
	"pending": true, "forward_ok": true, "diag_result": true, "error": true,
	"realize": true, "teardown": true, "stage": true, "heartbeat": true,
}

func (m *Message) validate() error {
	if !allKinds[m.Kind] {
		return decodeErrf("unknown kind %q", m.Kind)
	}
	if !requestIDRe.MatchString(m.ID) {
		return decodeErrf("%s: bad request id", m.Kind)
	}
	if m.DataSize != nil {
		if !bulkKinds[m.Kind] {
			return decodeErrf("%s: data_size on a bulk-less kind", m.Kind)
		}
		if *m.DataSize < 0 || *m.DataSize > MaxBulkDeclarable {
			return decodeErrf("%s: data_size out of bounds", m.Kind)
		}
	}
	for _, bounded := range []*int64{m.ElapsedMs, m.UptimeMs, m.MaxBytes, m.Size, m.StdoutSize, m.StderrSize} {
		if bounded != nil && (*bounded < 0 || *bounded > MaxWireInt) {
			return decodeErrf("%s: integer field out of bounds", m.Kind)
		}
	}
	if m.Budget != nil {
		if err := m.Budget.validate(); err != nil {
			return decodeErrf("%s: %v", m.Kind, err)
		}
	}
	switch m.Kind {
	case "exec":
		if len(m.Cmd) == 0 {
			return decodeErrf("exec: empty cmd")
		}
	case "read_file", "write_file":
		if m.Path == "" {
			return decodeErrf("%s: empty path", m.Kind)
		}
		if m.Kind == "write_file" && m.DataSize == nil {
			return decodeErrf("write_file requires data_size")
		}
	case "diag":
		if m.MaxEntries != nil && (*m.MaxEntries < 1 || *m.MaxEntries > 1000) {
			return decodeErrf("diag: max_entries out of bounds")
		}
	case "poll", "ack", "pending":
		if !requestIDRe.MatchString(m.TargetID) {
			return decodeErrf("%s: bad target id", m.Kind)
		}
	case "exec_result":
		if m.Rc == nil || m.StdoutSize == nil || m.StderrSize == nil {
			return decodeErrf("exec_result: missing fields")
		}
		if *m.Rc < -(int64(1)<<31) || *m.Rc > (int64(1)<<31)-1 {
			return decodeErrf("exec_result: rc outside int32")
		}
		declared := int64(0)
		if m.DataSize != nil {
			declared = *m.DataSize
		}
		if *m.StdoutSize+*m.StderrSize != declared {
			return decodeErrf("exec_result: sizes do not match data_size")
		}
	case "file_data":
		if m.Size == nil {
			return decodeErrf("file_data: missing size")
		}
		declared := int64(0)
		if m.DataSize != nil {
			declared = *m.DataSize
		}
		if *m.Size != declared {
			return decodeErrf("file_data: size does not match data_size")
		}
	case "error":
		if !errnoRe.MatchString(m.Errno) {
			return decodeErrf("error: bad errno shape")
		}
		if (m.Errno == "ETIME" || m.Errno == "ETIMEDOUT") && m.Layer == nil {
			return decodeErrf("error: budget errors must name their layer")
		}
	case "forward":
		if m.Port == nil || *m.Port < 1 || *m.Port > 65535 {
			return decodeErrf("forward: bad port")
		}
	case "realize":
		if !sha256Re.MatchString(m.BundleDigest) {
			return decodeErrf("realize: bad bundle digest")
		}
	}
	return nil
}

func (b *Budget) validate() error {
	for _, bounded := range []*int64{b.CommandMs, b.ChannelMs, b.UntimedBoundMs} {
		if bounded != nil && (*bounded < 1 || *bounded > MaxWireInt) {
			return fmt.Errorf("budget field out of bounds")
		}
	}
	outer := int64(DefaultUntimedMs)
	if b.UntimedBoundMs != nil {
		outer = *b.UntimedBoundMs
	}
	if b.CommandMs != nil && *b.CommandMs > outer {
		return fmt.Errorf("untimed_bound_ms must cover command_ms")
	}
	return nil
}

// sortedKeys is used by diag formatting; kept here beside the codec.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
