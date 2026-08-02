package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

var (
	ErrKindInvalid       = errors.New("audit: record kind is invalid")
	ErrSequenceInvalid   = errors.New("audit: sequence and previous root are inconsistent")
	ErrRecordRootMissing = errors.New("audit: record root is required")
	ErrOccurredAtMissing = errors.New("audit: occurrence time is required")
	ErrEntryNotCanonical = errors.New("audit: chain entry is not canonical")
	ErrLedgerEmpty       = errors.New("audit: ledger is empty")
	ErrLedgerConflict    = errors.New("audit: ledger head changed")
)

type RecordKind uint8

const (
	RecordEvaluation RecordKind = iota + 1
	RecordEstimator
	RecordResponsibilityHandover
	RecordEvidenceBundle
)

func (kind RecordKind) IsValid() bool {
	return kind >= RecordEvaluation && kind <= RecordEvidenceBundle
}

type Entry struct {
	Sequence     uint64
	Kind         RecordKind
	PreviousRoot [32]byte
	RecordRoot   [32]byte
	OccurredAt   time.Time
	Root         [32]byte
}

const chainDomain = "cargoos:audit-chain:v1"

func NewEntry(
	sequence uint64,
	kind RecordKind,
	previousRoot [32]byte,
	recordRoot [32]byte,
	occurredAt time.Time,
) (Entry, error) {
	if !kind.IsValid() {
		return Entry{}, ErrKindInvalid
	}
	if sequence == 0 || (sequence == 1) != (previousRoot == ([32]byte{})) {
		return Entry{}, ErrSequenceInvalid
	}
	if recordRoot == ([32]byte{}) {
		return Entry{}, ErrRecordRootMissing
	}
	if occurredAt.IsZero() {
		return Entry{}, ErrOccurredAtMissing
	}
	entry := Entry{
		Sequence: sequence, Kind: kind, PreviousRoot: previousRoot,
		RecordRoot: recordRoot, OccurredAt: occurredAt.UTC().Truncate(time.Microsecond),
	}
	entry.Root = calculateRoot(entry)
	return entry, nil
}

func (entry Entry) Validate() error {
	normalized, err := NewEntry(
		entry.Sequence, entry.Kind, entry.PreviousRoot, entry.RecordRoot, entry.OccurredAt,
	)
	if err != nil {
		return err
	}
	if normalized != entry {
		return ErrEntryNotCanonical
	}
	return nil
}

func calculateRoot(entry Entry) [32]byte {
	var preimage [len(chainDomain) + 1 + 8 + 32 + 32 + 8]byte
	offset := copy(preimage[:], chainDomain)
	preimage[offset] = byte(entry.Kind)
	offset++
	binary.BigEndian.PutUint64(preimage[offset:offset+8], entry.Sequence)
	offset += 8
	copy(preimage[offset:offset+32], entry.PreviousRoot[:])
	offset += 32
	copy(preimage[offset:offset+32], entry.RecordRoot[:])
	offset += 32
	binary.BigEndian.PutUint64(preimage[offset:offset+8], uint64(entry.OccurredAt.UnixMicro()))
	return sha256.Sum256(preimage[:])
}
