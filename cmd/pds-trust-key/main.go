package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	postgresstore "cargoos/persistence/postgres"
	"cargoos/policy"
)

const maxTrustRequestBytes = 1 << 20

var (
	errDatabaseURLRequired = errors.New("PDS_DATABASE_URL is required")
	errTrustInputUsage     = errors.New("usage: pds-trust-key [request.json|-]")
	errTrustInputTooLarge  = errors.New("trust key request exceeds 1 MiB")
	errInvalidTrustRequest = errors.New("invalid trust key request")
)

type trustAction string

const (
	actionRegister trustAction = "register"
	actionRevoke   trustAction = "revoke"
)

type trustRequest struct {
	Action     trustAction `json:"action"`
	SignerID   string      `json:"signer_id"`
	KeyID      string      `json:"key_id"`
	Algorithm  string      `json:"algorithm,omitempty"`
	PublicKey  []byte      `json:"public_key,omitempty"`
	ValidFrom  time.Time   `json:"valid_from,omitempty"`
	ValidUntil *time.Time  `json:"valid_until,omitempty"`
	RevokedAt  time.Time   `json:"revoked_at,omitempty"`
}

type trustStore interface {
	AddVerificationKey(context.Context, policy.VerificationKey) error
	RevokeVerificationKey(context.Context, string, string, time.Time) error
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
	reader, closeInput, err := trustInput(os.Args[1:], os.Stdin)
	if err != nil {
		return err
	}
	defer closeInput()
	request, err := decodeTrustRequest(reader)
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
	if err = executeTrustRequest(ctx, store, request); err != nil {
		return err
	}
	log.Printf("%s trust key %s/%s", request.Action, request.SignerID, request.KeyID)
	return nil
}

func trustInput(args []string, stdin io.Reader) (io.Reader, func(), error) {
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
		return nil, func() {}, errTrustInputUsage
	}
}

func decodeTrustRequest(reader io.Reader) (trustRequest, error) {
	if reader == nil {
		return trustRequest{}, errInvalidTrustRequest
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxTrustRequestBytes+1))
	if err != nil {
		return trustRequest{}, err
	}
	if len(payload) > maxTrustRequestBytes {
		return trustRequest{}, errTrustInputTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var request trustRequest
	if err = decoder.Decode(&request); err != nil {
		return trustRequest{}, fmt.Errorf("%w: %v", errInvalidTrustRequest, err)
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return trustRequest{}, errInvalidTrustRequest
	}
	request.Action = trustAction(strings.ToLower(strings.TrimSpace(string(request.Action))))
	request.SignerID = strings.TrimSpace(request.SignerID)
	request.KeyID = strings.TrimSpace(request.KeyID)
	request.Algorithm = strings.TrimSpace(request.Algorithm)
	if err = validateTrustRequest(request); err != nil {
		return trustRequest{}, err
	}
	return request, nil
}

func validateTrustRequest(request trustRequest) error {
	if request.SignerID == "" || request.KeyID == "" {
		return errInvalidTrustRequest
	}
	switch request.Action {
	case actionRegister:
		if request.Algorithm != policy.AlgorithmEd25519 ||
			len(request.PublicKey) != ed25519.PublicKeySize ||
			request.ValidFrom.IsZero() ||
			!request.RevokedAt.IsZero() ||
			(request.ValidUntil != nil && !request.ValidUntil.After(request.ValidFrom)) {
			return errInvalidTrustRequest
		}
	case actionRevoke:
		if request.Algorithm != "" ||
			len(request.PublicKey) != 0 ||
			!request.ValidFrom.IsZero() ||
			request.ValidUntil != nil ||
			request.RevokedAt.IsZero() {
			return errInvalidTrustRequest
		}
	default:
		return errInvalidTrustRequest
	}
	return nil
}

func executeTrustRequest(ctx context.Context, store trustStore, request trustRequest) error {
	if store == nil {
		return errors.New("trust store is required")
	}
	switch request.Action {
	case actionRegister:
		return store.AddVerificationKey(ctx, policy.VerificationKey{
			SignerID: request.SignerID, KeyID: request.KeyID,
			Algorithm: request.Algorithm, PublicKey: append([]byte(nil), request.PublicKey...),
			ValidFrom: request.ValidFrom.UTC(), ValidUntil: utcTime(request.ValidUntil),
		})
	case actionRevoke:
		return store.RevokeVerificationKey(
			ctx, request.SignerID, request.KeyID, request.RevokedAt.UTC(),
		)
	default:
		return errInvalidTrustRequest
	}
}

func utcTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}
