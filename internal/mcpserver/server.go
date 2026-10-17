package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type queryInput struct {
	SQL string `json:"sql"`
}
type listInput struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

func Run(ctx context.Context, base string) error {
	base = strings.TrimRight(base, "/")
	client := &http.Client{Timeout: 35 * time.Second}
	server := mcp.NewServer(&mcp.Implementation{Name: "kbomination", Version: "0.1.0"}, nil)
	request := func(ctx context.Context, path string, body any) (json.RawMessage, error) {
		var data io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			data = strings.NewReader(string(b))
		}
		method := http.MethodGet
		if body != nil {
			method = http.MethodPost
		}
		req, err := http.NewRequestWithContext(ctx, method, base+"/api/v1/"+path, data)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("kbomination API: %s", strings.TrimSpace(string(raw)))
		}
		return json.RawMessage(raw), nil
	}
	addList := func(name, description, path string) {
		mcp.AddTool(server, &mcp.Tool{Name: name, Description: description}, func(ctx context.Context, _ *mcp.CallToolRequest, in listInput) (*mcp.CallToolResult, json.RawMessage, error) {
			q := ""
			if in.Limit > 0 {
				q = fmt.Sprintf("?limit=%d&offset=%d", min(in.Limit, 1000), max(0, in.Offset))
			}
			v, e := request(ctx, path+q, nil)
			return nil, v, e
		})
	}
	addList("list_clusters", "List clusters in the local fleet.", "clusters")
	addList("list_components", "List package identities and their versions and cluster membership.", "catalog")
	addList("list_snapshots", "List collection snapshots.", "snapshots")
	addList("list_runs", "List recent collection runs.", "runs")
	mcp.AddTool(server, &mcp.Tool{Name: "read_only_sql", Description: "Run one restricted read-only SELECT query against the inventory views."}, func(ctx context.Context, _ *mcp.CallToolRequest, in queryInput) (*mcp.CallToolResult, json.RawMessage, error) {
		v, e := request(ctx, "query", map[string]string{"sql": in.SQL})
		return nil, v, e
	})
	mcp.AddTool(server, &mcp.Tool{Name: "query_schema", Description: "List tables and columns available for read-only SQL."}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, json.RawMessage, error) {
		v, e := request(ctx, "schema", nil)
		return nil, v, e
	})
	return server.Run(ctx, &mcp.StdioTransport{})
}
