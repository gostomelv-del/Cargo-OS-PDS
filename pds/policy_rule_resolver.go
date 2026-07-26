package pds

import (
	"context"
	"errors"
	"strings"

	"cargoos/policy"
)

var (
	ErrPolicyVersionReaderRequired = errors.New("pds: policy version reader is required")
	ErrPolicyRuleCompilerRequired  = errors.New("pds: policy rule compiler is required")
	ErrPolicyRuleReferenceInvalid  = errors.New("pds: policy rule reference is invalid")
)

// PolicyRuleCompiler compiles one required rule from an already verified,
// immutable policy version. Implementations must not load another policy.
type PolicyRuleCompiler interface {
	CompileRule(context.Context, *policy.Version, string) (RuleOperator, error)
}

// PolicyDocumentRuleResolver bridges an Evaluation's exact Policy Binding to a
// compiler without allowing active-policy re-resolution or document
// substitution.
type PolicyDocumentRuleResolver struct {
	reader   policy.VersionReader
	compiler PolicyRuleCompiler
}

func NewPolicyDocumentRuleResolver(
	reader policy.VersionReader,
	compiler PolicyRuleCompiler,
) (*PolicyDocumentRuleResolver, error) {
	if reader == nil {
		return nil, ErrPolicyVersionReaderRequired
	}
	if compiler == nil {
		return nil, ErrPolicyRuleCompilerRequired
	}
	return &PolicyDocumentRuleResolver{reader: reader, compiler: compiler}, nil
}

func (r *PolicyDocumentRuleResolver) ResolveRuleOperator(
	ctx context.Context,
	reference PolicyRuleReference,
) (RuleOperator, error) {
	if r == nil || r.reader == nil {
		return nil, ErrPolicyVersionReaderRequired
	}
	if r.compiler == nil {
		return nil, ErrPolicyRuleCompilerRequired
	}
	reference.PolicyID = strings.TrimSpace(reference.PolicyID)
	reference.PolicyVersion = strings.TrimSpace(reference.PolicyVersion)
	reference.PolicyHash = strings.TrimSpace(reference.PolicyHash)
	reference.RuleID = strings.TrimSpace(reference.RuleID)
	if reference.PolicyID == "" || reference.PolicyVersion == "" ||
		reference.PolicyHash == "" || reference.RuleID == "" {
		return nil, ErrPolicyRuleReferenceInvalid
	}
	version, err := r.reader.FindVersion(
		ctx,
		reference.PolicyID,
		reference.PolicyVersion,
		reference.PolicyHash,
	)
	if err != nil {
		return nil, err
	}
	if version == nil {
		return nil, policy.ErrPolicyNotFound
	}
	snapshot := version.Snapshot()
	if snapshot.PolicyID != reference.PolicyID ||
		snapshot.Version != reference.PolicyVersion ||
		snapshot.Hash != reference.PolicyHash {
		return nil, ErrPolicyRuleReferenceInvalid
	}
	operator, err := r.compiler.CompileRule(ctx, version, reference.RuleID)
	if err != nil {
		return nil, err
	}
	if operator == nil || strings.TrimSpace(operator.RuleID()) != reference.RuleID {
		return nil, ErrResolvedRuleMismatch
	}
	return operator, nil
}

var _ RuleOperatorResolver = (*PolicyDocumentRuleResolver)(nil)
