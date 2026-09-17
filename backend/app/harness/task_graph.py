"""Task Graph (architecture §8) - parallel vs dependent execution.

Nodes carry tool_name + args. Edges express dependencies; the graph executor
runs independent nodes concurrently and only blocks on deps. Phase 0: node
types are generic (engine tool nodes); Mode 1/2/3 graph shapes arrive with each
engine phase.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger

log = get_logger("aegis.harness.task_graph")


class TaskGraphError(Exception):
    pass


@dataclass
class TaskNode:
    id: str
    tool_name: str
    args: dict[str, Any] = field(default_factory=dict)
    deps: list[str] = field(default_factory=list)
    status: str = "PENDING"  # PENDING | RUNNING | COMPLETED | FAILED
    result: dict[str, Any] | None = None
    error: str | None = None


@dataclass(frozen=True)
class TaskGraphRunResult:
    nodes: dict[str, TaskNode]
    all_succeeded: bool


class TaskGraph:
    def __init__(self, nodes: list[TaskNode] | None = None) -> None:
        self.nodes: dict[str, TaskNode] = {n.id: n for n in (nodes or [])}

    def add(self, node: TaskNode) -> None:
        if node.id in self.nodes:
            raise TaskGraphError(f"duplicate node id {node.id!r}")
        for dep in node.deps:
            if dep not in self.nodes and dep != node.id:
                raise TaskGraphError(f"node {node.id!r} references unknown dependency {dep!r}")
        self.nodes[node.id] = node

    def topo_order(self) -> list[str]:
        """Kahn's algorithm; also detects cycles."""
        order: list[str] = []
        visited: set[str] = set()
        temp: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in temp:
                raise TaskGraphError("cycle detected in task graph")
            if node_id in visited:
                return
            temp.add(node_id)
            for dep in self.nodes[node_id].deps:
                visit(dep)
            temp.discard(node_id)
            visited.add(node_id)
            order.append(node_id)

        for nid in self.nodes:
            visit(nid)
        return order

    async def run(self, execute_node) -> TaskGraphRunResult:
        """execute_node(node: TaskNode) -> None (performs the tool call).

        Uses the topo order to materialize dependency levels then runs each
        level concurrently with asyncio.gather.
        """
        levels: list[list[str]] = []
        remaining = set(self.nodes)
        while remaining:
            level = [nid for nid in remaining if set(self.nodes[nid].deps) <= set().union(*levels, set())]
            if not level:
                raise TaskGraphError("task graph has unsatisfiable dependencies")
            levels.append(level)
            remaining -= set(level)

        for level in levels:
            await asyncio.gather(*(self._run_node(nid, execute_node) for nid in level))
        all_ok = all(n.status == "COMPLETED" for n in self.nodes.values())
        return TaskGraphRunResult(nodes=self.nodes, all_succeeded=all_ok)

    async def _run_node(self, node_id: str, execute_node) -> None:
        node = self.nodes[node_id]
        node.status = "RUNNING"
        try:
            await execute_node(node)
            node.status = "COMPLETED"
        except Exception as exc:  # failures are carried per-node, not fatal to graph
            node.status = "FAILED"
            node.error = str(exc)
            log.info("task_graph.node_failed", node=node_id, error=str(exc))

    def snapshot(self) -> dict[str, Any]:
        return {
            "nodes": {nid: {"tool": n.tool_name, "args": n.args, "deps": n.deps, "status": n.status,
                             "error": n.error} for nid, n in self.nodes.items()},
            "status": "COMPLETED" if all(n.status == "COMPLETED" for n in self.nodes.values()) else "RUNNING",
        }