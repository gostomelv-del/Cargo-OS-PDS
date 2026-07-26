package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	postgresstore "cargoos/persistence/postgres"
	"cargoos/policy"
	"cargoos/ruleoperator"
)

const maxAdmissionRequestBytes = 1 << 20

var (
	errDatabaseURLRequired = errors.New("PDS_DATABASE_URL is required")
	errAdmissionInputUsage = errors.New("usage: pds-policy-admit [request.json|-]")
	errAdmissionTooLarge   = errors.New("policy admission request exceeds 1 MiB")
	errInvalidAdmission    = errors.New("invalid policy admission request")
)

type admissionRequest struct {
	Policy      policy.Snapshot       `json:"policy"`
	Signature   policy.Signature      `json:"signature"`
	Approval    policy.ApprovalRecord `json:"approval"`
	VerifiedAt  time.Time             `json:"verified_at"`
	ActivatedAt time.Time             `json:"activated_at"`
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	databaseURL := os.Getenv("PDS_DATABASE_URL")
	if databaseURL == "" {
		return errDatabaseURLRequired
	}
	reader, closeInput, err := admissionInput(os.Args[1:], os.Stdin)
	if err != nil {
		return err
	}
	defer closeInput()
	request, err := decodeAdmissionRequest(reader)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = db.PingContext(ctx); err != nil {
		return err
	}
	store, err := postgresstore.NewStore(db)
	if err != nil {
		return err
	}
	activated, err := admit(ctx, request, store, store)
	if err != nil {
		return err
	}
	snapshot := activated.VerifiedVersion().Version().Snapshot()
	log.Printf("admitted policy %s version %s (%s)", snapshot.PolicyID, snapshot.Version, snapshot.Hash)
	return nil
}

func admissionInput(args []string, stdin io.Reader) (io.Reader, func(), error) {
	switch len(args) {
	case 0:
		return stdin, func() {}, nil
	case 1:
		if args[0] == "-" {
			return stdin, func() {}, nil
		}
		file, err := os.Open(args[0])
		if err != nil {
			return nil, func() {}, err
		}
		return file, func() { _ = file.Close() }, nil
	default:
		return nil, func() {}, errAdmissionInputUsage
	}
}

func decodeAdmissionRequest(reader io.Reader) (admissionRequest, error) {
	if reader == nil {
		return admissionRequest{}, errInvalidAdmission
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxAdmissionRequestBytes+1))
	if err != nil {
		return admissionRequest{}, err
	}
	if len(payload) > maxAdmissionRequestBytes {
		return admissionRequest{}, errAdmissionTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var request admissionRequest
	if err = decoder.Decode(&request); err != nil {
		return admissionRequest{}, fmt.Errorf("%w: %v", errInvalidAdmission, err)
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return admissionRequest{}, errInvalidAdmission
	}
	if _, err = policy.Rehydrate(request.Policy); err != nil {
		return admissionRequest{}, fmt.Errorf("%w: %v", errInvalidAdmission, err)
	}
	return request, nil
}

func admit(
	ctx context.Context,
	request admissionRequest,
	trustStore policy.TrustStore,
	registry policy.ActivatedVersionRegistry,
) (*policy.ActivatedVersion, error) {
	version, err := policy.Rehydrate(request.Policy)
	if err != nil {
		return nil, err
	}
	verifier, err := policy.NewVerifier(trustStore)
	if err != nil {
		return nil, err
	}
	service, err := policy.NewAdmissionService(
		verifier,
		ruleoperator.PolicyDocumentCompiler{},
		registry,
	)
	if err != nil {
		return nil, err
	}
	return service.Admit(
		ctx,
		version,
		request.Signature,
		request.Approval,
		request.VerifiedAt,
		request.ActivatedAt,
	)
}
