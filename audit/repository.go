package audit

import "context"

type Repository interface {
	AppendAuditEntry(context.Context, Entry) error
	FindAuditHead(context.Context) (Entry, error)
}
