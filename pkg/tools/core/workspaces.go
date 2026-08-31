/*
Copyright 2026 The kcp Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package core

import (
	"context"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/kcp-dev/contrib-mcp-virtual-workspace/pkg/tools"
)

var workspaceLogicalClusterGVR = schema.GroupVersionResource{
	Group:    "core.kcp.io",
	Version:  "v1alpha1",
	Resource: "logicalclusters",
}

// WorkspaceInfo represents a single workspace in the list_kcp_workspaces output.
type WorkspaceInfo struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	Name     string `json:"name,omitempty"`
}

// ListWorkspacesInput is the input schema for list_kcp_workspaces (empty).
type ListWorkspacesInput struct{}

// ListWorkspacesOutput is the output schema for list_kcp_workspaces.
type ListWorkspacesOutput struct {
	Workspaces []WorkspaceInfo `json:"workspaces"`
}

func registerListWorkspaces(server *mcp.Server, scope tools.Scope) {
	mcp.AddTool(server, &mcp.Tool{
		Annotations: tools.ReadOnly("List workspaces"),
		Name:        "list_kcp_workspaces",
		Description: "List kcp workspaces the authenticated user has access to. Returns workspace IDs (logical cluster names), API endpoints, and human-readable workspace names where the caller may read them.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListWorkspacesInput) (*mcp.CallToolResult, ListWorkspacesOutput, error) {
		clusters := scope.Clusters()
		workspaces := make([]WorkspaceInfo, len(clusters))
		var wg sync.WaitGroup
		for i, c := range clusters {
			workspaces[i] = WorkspaceInfo{ID: c.ClusterName, Endpoint: c.Endpoint}
			wg.Add(1)
			go func() {
				defer wg.Done()
				workspaces[i].Name = workspaceName(ctx, scope, c.ClusterName)
			}()
		}
		wg.Wait()
		return nil, ListWorkspacesOutput{Workspaces: workspaces}, nil
	})
}

func workspaceName(ctx context.Context, scope tools.Scope, workspace string) string {
	_, dyn, err := scope.ClientFor(workspace)
	if err != nil || dyn == nil {
		return ""
	}
	lc, err := dyn.Resource(workspaceLogicalClusterGVR).Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return ""
	}
	path := lc.GetAnnotations()["kcp.io/path"]
	if i := strings.LastIndex(path, ":"); i >= 0 {
		return path[i+1:]
	}
	return path
}
