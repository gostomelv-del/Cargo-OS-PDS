module cargoos

go 1.22

require (
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.2
)

replace github.com/google/uuid => ./third_party/google_uuid
