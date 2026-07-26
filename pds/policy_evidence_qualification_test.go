package pds

import (
	"context"
	"errors"
	"testing"

	"cargoos/evidence"
	"cargoos/policy"
)

type recordingQualificationCompiler struct {
	policy evidence.QualificationPolicy
	err    error
}

func (c recordingQualificationCompiler) CompileQualificationPolicy(
	context.Context,
	*policy.Version,
) (evidence.QualificationPolicy, error) {
	return c.policy, c.err
}

func TestPolicyEvidenceQualificationServiceRequiresDependencies(t *testing.T) {
	evidenceService, err := evidence.NewService(
		evidence.NewMemoryRepository(),
		evidence.ServiceConfig{SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	versionReader := &recordingVersionReader{}
	compiler := recordingQualificationCompiler{}
	tests := []struct {
		name        string
		evaluations *Service
		evidence    *evidence.Service
		reader      policy.VersionReader
		compiler    PolicyQualificationCompiler
		target      error
	}{
		{"evaluation service", nil, evidenceService, versionReader, compiler, ErrEvaluationServiceRequired},
		{"evidence service", NewService(nil), nil, versionReader, compiler, ErrEvidenceQualificationRequired},
		{"version reader", NewService(nil), evidenceService, nil, compiler, ErrPolicyVersionReaderRequired},
		{"compiler", NewService(nil), evidenceService, versionReader, nil, ErrQualificationCompilerRequired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewPolicyEvidenceQualificationService(
				test.evaluations,
				test.evidence,
				test.reader,
				test.compiler,
			)
			if !errors.Is(err, test.target) {
				t.Fatalf("got %v, want %v", err, test.target)
			}
			if service != nil {
				t.Fatal("constructor returned a service with a missing dependency")
			}
		})
	}
}
