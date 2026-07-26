package pds

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/policy"
)

var (
	ErrQualificationCompilerRequired     = errors.New("pds: policy qualification compiler is required")
	ErrEvidenceQualificationRequired     = errors.New("pds: evidence qualification service is required")
	ErrPolicyQualificationBindingInvalid = errors.New("pds: policy qualification binding is invalid")
)

type PolicyQualificationCompiler interface {
	CompileQualificationPolicy(context.Context, *policy.Version) (evidence.QualificationPolicy, error)
}

// PolicyEvidenceQualificationService derives qualification exclusively from
// the exact immutable Policy Version already bound to an Evaluation.
type PolicyEvidenceQualificationService struct {
	evaluations *Service
	evidence    *evidence.Service
	reader      policy.VersionReader
	compiler    PolicyQualificationCompiler
}

func NewPolicyEvidenceQualificationService(
	evaluations *Service,
	evidenceService *evidence.Service,
	reader policy.VersionReader,
	compiler PolicyQualificationCompiler,
) (*PolicyEvidenceQualificationService, error) {
	if evaluations == nil {
		return nil, ErrEvaluationServiceRequired
	}
	if evidenceService == nil {
		return nil, ErrEvidenceQualificationRequired
	}
	if reader == nil {
		return nil, ErrPolicyVersionReaderRequired
	}
	if compiler == nil {
		return nil, ErrQualificationCompilerRequired
	}
	return &PolicyEvidenceQualificationService{
		evaluations: evaluations,
		evidence:    evidenceService,
		reader:      reader,
		compiler:    compiler,
	}, nil
}

func (s *PolicyEvidenceQualificationService) QualifyAndBind(
	ctx context.Context,
	evaluationID uuid.UUID,
) (evaluation.EvaluationSnapshot, error) {
	if s == nil || s.evaluations == nil {
		return evaluation.EvaluationSnapshot{}, ErrEvaluationServiceRequired
	}
	if s.evidence == nil {
		return evaluation.EvaluationSnapshot{}, ErrEvidenceQualificationRequired
	}
	if s.reader == nil {
		return evaluation.EvaluationSnapshot{}, ErrPolicyVersionReaderRequired
	}
	if s.compiler == nil {
		return evaluation.EvaluationSnapshot{}, ErrQualificationCompilerRequired
	}
	evaluationSnapshot, err := s.evaluations.Snapshot(ctx, evaluationID)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if evaluationSnapshot.EvidenceBinding != nil {
		return evaluationSnapshot, nil
	}
	binding := evaluationSnapshot.PolicyBinding
	if binding == nil {
		return evaluation.EvaluationSnapshot{}, ErrPolicyBindingMissing
	}
	version, err := s.reader.FindVersion(
		ctx,
		binding.PolicyID,
		binding.Version,
		binding.Hash,
	)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	if version == nil {
		return evaluation.EvaluationSnapshot{}, policy.ErrPolicyNotFound
	}
	snapshot := version.Snapshot()
	if snapshot.PolicyID != binding.PolicyID ||
		snapshot.Version != binding.Version ||
		snapshot.Hash != binding.Hash {
		return evaluation.EvaluationSnapshot{}, ErrPolicyQualificationBindingInvalid
	}
	qualificationPolicy, err := s.compiler.CompileQualificationPolicy(ctx, version)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	qualifier, err := evidence.NewQualifier(qualificationPolicy)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	result, err := s.evidence.QualifySession(ctx, evaluationSnapshot.SessionID, qualifier)
	if err != nil {
		return evaluation.EvaluationSnapshot{}, err
	}
	bound, err := s.evaluations.BindEvidenceQualification(ctx, evaluationID, result)
	if err == nil {
		return bound, nil
	}
	if errors.Is(err, evaluation.ErrEvidenceAlreadyBound) ||
		errors.Is(err, ErrConcurrentModification) {
		latest, findErr := s.evaluations.Snapshot(ctx, evaluationID)
		if findErr == nil && latest.EvidenceBinding != nil {
			return latest, nil
		}
	}
	return evaluation.EvaluationSnapshot{}, err
}
