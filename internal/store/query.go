package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

var queryTables = words("fleets clusters snapshots components component_properties dependencies component_catalog component_catalog_observations component_inventory cluster_metadata app_settings latest_snapshots inventory_history latest_inventory runs run_results")
var queryFunctions = words("count count_star sum avg min max median quantile_cont quantile_disc stddev stddev_pop variance var_pop first last any_value arg_min arg_max bool_and bool_or string_agg list array_agg array_length len length lower upper trim ltrim rtrim concat concat_ws substring substr replace split_part string_split starts_with ends_with contains regexp_matches regexp_full_match regexp_extract regexp_replace coalesce nullif ifnull if greatest least abs round ceil ceiling floor sqrt power date_trunc date_part date_diff date_sub date_add extract strftime epoch now current_timestamp current_date current_localtimestamp row_number rank dense_rank lag lead first_value last_value ntile percent_rank cume_dist range generate_series unnest")

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, v := range strings.Fields(s) {
		m[v] = true
	}
	return m
}

// Query validates DuckDB's parsed SELECT AST, not a textual SELECT prefix.
// Only known pure functions and application-owned tables may be referenced.
func (s *Store) Query(ctx context.Context, query string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if len(query) > 65536 {
		return Result{}, fmt.Errorf("query exceeds 64 KiB")
	}
	var encoded any
	if err := s.DB.QueryRowContext(ctx, "SELECT json_serialize_sql(CAST(? AS VARCHAR))", query).Scan(&encoded); err != nil {
		return Result{}, err
	}
	var serialized string
	switch v := encoded.(type) {
	case string:
		serialized = v
	case []byte:
		serialized = string(v)
	case map[string]any:
		b, err := json.Marshal(v)
		if err != nil {
			return Result{}, err
		}
		serialized = string(b)
	default:
		return Result{}, fmt.Errorf("unexpected DuckDB SQL parser result %T", encoded)
	}
	var ast map[string]any
	if err := json.Unmarshal([]byte(serialized), &ast); err != nil {
		return Result{}, err
	}
	if failed, _ := ast["error"].(bool); failed {
		return Result{}, fmt.Errorf("only valid SELECT queries are supported: %v", ast["error_message"])
	}
	stmts, ok := ast["statements"].([]any)
	if !ok || len(stmts) != 1 {
		return Result{}, fmt.Errorf("exactly one SELECT query is required")
	}
	ctes := map[string]bool{}
	collectCTEs(ast, ctes)
	if err := validateAST(ast, ctes); err != nil {
		return Result{}, err
	}
	return s.Read(ctx, query)
}

func collectCTEs(v any, ctes map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		if m, ok := x["cte_map"].(map[string]any); ok {
			if entries, ok := m["map"].([]any); ok {
				for _, entry := range entries {
					if e, ok := entry.(map[string]any); ok {
						if key, ok := e["key"].(string); ok {
							ctes[strings.ToLower(key)] = true
						}
					}
				}
			}
		}
		for _, v := range x {
			collectCTEs(v, ctes)
		}
	case []any:
		for _, v := range x {
			collectCTEs(v, ctes)
		}
	}
}

func validateAST(v any, ctes map[string]bool) error {
	switch x := v.(type) {
	case map[string]any:
		if fn, ok := x["function_name"].(string); ok && !queryFunctions[strings.ToLower(fn)] {
			return fmt.Errorf("function %q is not available in read-only queries", fn)
		}
		if table, ok := x["table_name"].(string); ok && table != "" && !queryTables[strings.ToLower(table)] && !ctes[strings.ToLower(table)] {
			return fmt.Errorf("table %q is not available in read-only queries", table)
		}
		for _, key := range []string{"schema_name", "catalog_name"} {
			if name, ok := x[key].(string); ok && name != "" && name != "main" {
				return fmt.Errorf("qualified external references are not supported")
			}
		}
		for _, v := range x {
			if err := validateAST(v, ctes); err != nil {
				return err
			}
		}
	case []any:
		for _, v := range x {
			if err := validateAST(v, ctes); err != nil {
				return err
			}
		}
	}
	return nil
}
