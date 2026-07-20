package evidence

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func validInput() Input {
	observed := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	confidence := 0.98
	return Input{
		EvidenceID:        uuid.New(),
		SessionID:         uuid.New(),
		SourceID:          "scale-17",
		SourceType:        "WEIGHT_SENSOR",
		EvidenceType:      TypeWeight,
		ObservedAt:        observed,
		ReceivedAt:        observed.Add(200 * time.Millisecond),
		Payload:           json.RawMessage(`{"unit":"kg","value":25.00}`),
		Confidence:        &confidence,
		Provenance:        map[string]string{"gateway": "dock-3"},
		SchemaVersion:     "evidence.v1",
		RuntimeVersion:    "cargoos-pds.dev",
		AcquisitionMethod: "MQTT",
	}
}

func TestNewObjectCanonicalizesAndVerifiesPayload(t *testing.T) {
	input := validInput()
	input.Payload = json.RawMessage(`{ "value": 25.00, "unit": "kg" }`)
	object, err := NewObject(input)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := object.Snapshot()
	if string(snapshot.Payload) != `{"unit":"kg","value":25.00}` {
		t.Fatalf("unexpected canonical payload: %s", snapshot.Payload)
	}
	if err = object.VerifyIntegrity(); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotIsDefensiveCopy(t *testing.T) {
	object, err := NewObject(validInput())
	if err != nil {
		t.Fatal(err)
	}
	first := object.Snapshot()
	first.Payload[0] = '['
	*first.Confidence = 0
	first.Provenance["gateway"] = "changed"
	second := object.Snapshot()
	if second.Payload[0] != '{' || *second.Confidence != 0.98 || second.Provenance["gateway"] != "dock-3" {
		t.Fatalf("snapshot mutation leaked into object: %#v", second)
	}
}

func TestRehydrateRejectsPayloadTampering(t *testing.T) {
	object, err := NewObject(validInput())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := object.Snapshot()
	snapshot.Payload = json.RawMessage(`{"unit":"kg","value":26}`)
	if _, err = Rehydrate(snapshot); !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("expected integrity mismatch, got %v", err)
	}
}

func TestRehydrateRejectsNonCanonicalPayload(t *testing.T) {
	object, err := NewObject(validInput())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := object.Snapshot()
	snapshot.Payload = json.RawMessage(`{ "unit": "kg", "value": 25.00 }`)
	snapshot.Integrity.PayloadDigest = digest(snapshot.Payload)
	if _, err = Rehydrate(snapshot); !errors.Is(err, ErrNonCanonicalPayload) {
		t.Fatalf("expected non-canonical payload error, got %v", err)
	}
}

func TestCustomEvidenceTypeIsAllowed(t *testing.T) {
	input := validInput()
	input.EvidenceType = Type("TEMPERATURE_PROFILE")
	if _, err := NewObject(input); err != nil {
		t.Fatal(err)
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Input)
		want error
	}{
		{name: "evidence ID", edit: func(i *Input) { i.EvidenceID = uuid.Nil }, want: ErrEvidenceIDRequired},
		{name: "session ID", edit: func(i *Input) { i.SessionID = uuid.Nil }, want: ErrSessionIDRequired},
		{name: "source", edit: func(i *Input) { i.SourceID = " " }, want: ErrSourceIDRequired},
		{name: "type", edit: func(i *Input) { i.EvidenceType = Type("invalid type") }, want: ErrInvalidEvidenceType},
		{name: "time order", edit: func(i *Input) { i.ReceivedAt = i.ObservedAt.Add(-time.Second) }, want: ErrInvalidTimestampOrder},
		{name: "payload", edit: func(i *Input) { i.Payload = json.RawMessage(`{`) }, want: ErrInvalidPayload},
		{name: "confidence", edit: func(i *Input) { value := 1.1; i.Confidence = &value }, want: ErrInvalidConfidence},
		{name: "schema", edit: func(i *Input) { i.SchemaVersion = "" }, want: ErrSchemaVersionRequired},
		{name: "runtime", edit: func(i *Input) { i.RuntimeVersion = "" }, want: ErrRuntimeVersionRequired},
		{name: "acquisition", edit: func(i *Input) { i.AcquisitionMethod = "" }, want: ErrAcquisitionRequired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validInput()
			test.edit(&input)
			if _, err := NewObject(input); !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}
