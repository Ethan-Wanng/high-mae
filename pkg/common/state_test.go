package common

import (
	"testing"

	"wing/protocol"
)

func TestAllNodesAccessorsReturnSnapshots(t *testing.T) {
	oldNodes := GetAllNodes()
	t.Cleanup(func() { SetAllNodes(oldNodes) })

	SetAllNodes([]protocol.Node{{Name: "one"}, {Name: "two"}})

	snapshot := GetAllNodes()
	snapshot[0].Name = "mutated"

	next := GetAllNodes()
	if next[0].Name != "one" {
		t.Fatalf("GetAllNodes() returned mutable global slice, got first node %q", next[0].Name)
	}
}

func TestUpdateAllNodeReturnsUpdatedSnapshot(t *testing.T) {
	oldNodes := GetAllNodes()
	t.Cleanup(func() { SetAllNodes(oldNodes) })

	SetAllNodes([]protocol.Node{{Name: "one"}})
	nodes, ok := UpdateAllNode(0, func(node *protocol.Node) {
		node.Group = "group-a"
	})
	if !ok {
		t.Fatal("UpdateAllNode() ok = false, want true")
	}
	if len(nodes) != 1 || nodes[0].Group != "group-a" {
		t.Fatalf("UpdateAllNode() snapshot = %+v, want updated node", nodes)
	}

	nodes[0].Group = "mutated"
	next := GetAllNodes()
	if next[0].Group != "group-a" {
		t.Fatalf("UpdateAllNode() returned mutable global slice, got group %q", next[0].Group)
	}
}
