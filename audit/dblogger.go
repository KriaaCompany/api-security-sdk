package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// DBLogger writes audit events to a SQL database table using database/sql.
// It is compatible with any database driver (PostgreSQL, MySQL, SQLite, etc.).
//
// # Default schema
//
// Run this migration before using DBLogger with the default column layout.
// For PostgreSQL use JSONB for meta; for MySQL/SQLite use TEXT.
//
//	CREATE TABLE audit_logs (
//	    id         BIGSERIAL PRIMARY KEY,            -- BIGINT AUTO_INCREMENT for MySQL
//	    event_id   TEXT,
//	    type       TEXT        NOT NULL,
//	    timestamp  TIMESTAMPTZ NOT NULL,             -- DATETIME for MySQL, TEXT for SQLite
//	    subject    TEXT,
//	    resource   TEXT,
//	    action     TEXT,
//	    result     TEXT,
//	    ip         TEXT,
//	    user_agent TEXT,
//	    request_id TEXT,
//	    meta       JSONB                             -- TEXT for MySQL/SQLite
//	);
//
//	CREATE INDEX audit_logs_type_idx      ON audit_logs(type);
//	CREATE INDEX audit_logs_subject_idx   ON audit_logs(subject);
//	CREATE INDEX audit_logs_timestamp_idx ON audit_logs(timestamp);
//
// # Custom schema
//
// If your database has a different audit table layout, supply your own INSERT
// statement and a mapper via WithCustomSchema — no migration needed.
//
// # Usage
//
//	db, _ := sql.Open("pgx", os.Getenv("DATABASE_URL"))
//	logger := audit.NewDBLogger(db)
//
//	// Alongside the JSON logger:
//	combined := audit.NewMultiLogger(audit.NewJSONLogger(os.Stdout), logger)
type DBLogger struct {
	db    *sql.DB
	table string
	// insertSQL is pre-built at construction time.
	insertSQL    string
	mapper       EventMapper // nil when using the default schema
	customSchema bool        // true when WithCustomSchema was applied
}

// DBLoggerOption configures a DBLogger.
type DBLoggerOption func(*DBLogger)

// WithTableName sets the target table name. Default: "audit_logs".
// This option is ignored when WithCustomSchema is set, because the table name
// is embedded in the caller's INSERT statement.
func WithTableName(name string) DBLoggerOption {
	return func(l *DBLogger) {
		if l.customSchema {
			return // caller's SQL owns the table name; ignore
		}
		l.table = name
		l.insertSQL = buildInsertSQL(name)
	}
}

// EventMapper converts an audit.Event into the positional SQL parameters for
// the caller's custom INSERT statement. The returned slice must have exactly as
// many elements as there are placeholders in the INSERT statement.
type EventMapper func(e Event) []any

// WithCustomSchema replaces the default INSERT statement and column mapping
// with the caller's own. Use this when your database has a different
// audit_logs schema than the SDK's default.
//
// insertSQL must be a complete INSERT statement with positional placeholders
// ($1, $2, … for PostgreSQL; ?, ?, … for MySQL/SQLite).
// mapper must return a slice whose length matches the number of placeholders.
//
// When WithCustomSchema is set, WithTableName is ignored because the table
// name is embedded in the caller-supplied SQL.
//
// Example (PostgreSQL, project-specific schema):
//
//	const insertSQL = `INSERT INTO audit_logs
//	    (id, user_id, action, entity_type, entity_id, changes, ip_address, user_agent)
//	    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
//
//	mapper := func(e audit.Event) []any {
//	    return []any{
//	        e.ID,
//	        e.Subject,            // user_id
//	        e.Action,
//	        e.Resource,           // entity_type
//	        e.Meta["entity_id"],  // entity_id
//	        metaToJSON(e.Meta),   // changes
//	        e.IP,
//	        e.UserAgent,
//	    }
//	}
//
//	logger := audit.NewDBLogger(db, audit.WithCustomSchema(insertSQL, mapper))
func WithCustomSchema(insertSQL string, mapper EventMapper) DBLoggerOption {
	return func(l *DBLogger) {
		l.insertSQL = insertSQL
		l.mapper = mapper
		l.customSchema = true
	}
}

// NewDBLogger creates a DBLogger that writes to db.
// The database connection must already be open and the schema must exist.
func NewDBLogger(db *sql.DB, opts ...DBLoggerOption) *DBLogger {
	l := &DBLogger{db: db, table: "audit_logs"}
	l.insertSQL = buildInsertSQL(l.table)
	for _, o := range opts {
		o(l)
	}
	return l
}

// Log inserts the event into the database. It honours the context deadline/
// cancellation so a slow database does not block the request indefinitely.
//
// When WithCustomSchema was used, Log delegates entirely to the caller's
// INSERT statement and EventMapper. Otherwise the default 11-column schema
// is used.
func (l *DBLogger) Log(ctx context.Context, e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	// Custom schema path — caller owns the SQL and parameter mapping.
	if l.mapper != nil {
		args := l.mapper(e)
		_, err := l.db.ExecContext(ctx, l.insertSQL, args...)
		if err != nil {
			return fmt.Errorf("audit: db insert failed: %w", err)
		}
		return nil
	}

	// Default schema path.
	var metaJSON []byte
	if len(e.Meta) > 0 {
		var err error
		metaJSON, err = json.Marshal(e.Meta)
		if err != nil {
			metaJSON = []byte("{}")
		}
	}

	_, err := l.db.ExecContext(ctx, l.insertSQL,
		nullString(e.ID),
		string(e.Type),
		e.Timestamp.UTC(),
		nullString(e.Subject),
		nullString(e.Resource),
		nullString(e.Action),
		nullString(string(e.Result)),
		nullString(e.IP),
		nullString(e.UserAgent),
		nullString(e.RequestID),
		nullBytes(metaJSON),
	)
	if err != nil {
		return fmt.Errorf("audit: db insert failed: %w", err)
	}
	return nil
}

// Ping checks that the database is reachable and the audit_logs table exists.
// Call this at startup to fail fast on misconfiguration.
// Note: Ping uses the configured table name; it is not available when
// WithCustomSchema is set (the table name is embedded in the caller's SQL).
func (l *DBLogger) Ping(ctx context.Context) error {
	if err := l.db.PingContext(ctx); err != nil {
		return fmt.Errorf("audit: database unreachable: %w", err)
	}
	row := l.db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT 1 FROM %s LIMIT 1", l.table))
	var dummy int
	if err := row.Scan(&dummy); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("audit: table %q not accessible: %w", l.table, err)
	}
	return nil
}

// Recent returns up to limit events from the table in reverse-chronological
// order. Optionally filter by subject (pass "" to return all subjects).
// Useful for building an admin audit trail view.
func (l *DBLogger) Recent(ctx context.Context, subject string, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		rows *sql.Rows
		err  error
	)
	if subject != "" {
		rows, err = l.db.QueryContext(ctx,
			fmt.Sprintf(`SELECT event_id, type, timestamp, subject, resource, action,
			result, ip, user_agent, request_id, meta
			FROM %s WHERE subject = $1 ORDER BY timestamp DESC LIMIT $2`, l.table),
			subject, limit)
	} else {
		rows, err = l.db.QueryContext(ctx,
			fmt.Sprintf(`SELECT event_id, type, timestamp, subject, resource, action,
			result, ip, user_agent, request_id, meta
			FROM %s ORDER BY timestamp DESC LIMIT $1`, l.table),
			limit)
	}
	if err != nil {
		return nil, fmt.Errorf("audit: query failed: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var (
			e        Event
			eventID  sql.NullString
			subject  sql.NullString
			resource sql.NullString
			action   sql.NullString
			result   sql.NullString
			ip       sql.NullString
			ua       sql.NullString
			reqID    sql.NullString
			metaJSON sql.NullString
		)
		if err := rows.Scan(
			&eventID, &e.Type, &e.Timestamp,
			&subject, &resource, &action, &result,
			&ip, &ua, &reqID, &metaJSON,
		); err != nil {
			return nil, fmt.Errorf("audit: scan failed: %w", err)
		}
		e.ID = eventID.String
		e.Subject = subject.String
		e.Resource = resource.String
		e.Action = action.String
		e.Result = Result(result.String)
		e.IP = ip.String
		e.UserAgent = ua.String
		e.RequestID = reqID.String
		if metaJSON.Valid && metaJSON.String != "" {
			_ = json.Unmarshal([]byte(metaJSON.String), &e.Meta)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func buildInsertSQL(table string) string {
	return fmt.Sprintf(`INSERT INTO %s
		(event_id, type, timestamp, subject, resource, action,
		 result, ip, user_agent, request_id, meta)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, table)
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func nullBytes(b []byte) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}
