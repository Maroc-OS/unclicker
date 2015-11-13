#!/usr/bin/python

import sys
import struct


DEBUG = 0


class TerminalNode():
    TERMINAL_NODE_TYPE_ALLOW = 0x00
    TERMINAL_NODE_TYPE_DENY = 0x01
    type = None
    flags = None
    parent = None

    def __eq__(self, other):
        return self.type == other.type and self.flags == other.flags

    def __str__(self):
        if self.type == self.TERMINAL_NODE_TYPE_ALLOW:
            return "allow"
        elif self.type == self.TERMINAL_NODE_TYPE_DENY:
            return "deny"
        else:
            return "unknown"

    def is_allow(self):
        return self.type == self.TERMINAL_NODE_TYPE_ALLOW

    def is_deny(self):
        return self.type == self.TERMINAL_NODE_TYPE_DENY


class NonTerminalNode():
    filter_id = None
    filter = None
    argument_id = None
    argument = None
    match_offset = None
    match = None
    unmatch_offset = None
    unmatch = None
    parent = None

    def __eq__(self, other):
        return self.filter_id == other.filter_id and self.argument_id == other.argument_id and self.match_offset == other.match_offset and self.unmatch_offset == other.unmatch_offset

    def __str__(self):
        if self.filter:
            if self.argument:
                return "(%s %s)" % (self.filter, self.argument)
            else:
                return "(%s)" % (self.filter)
        return "(%02x %04x %04x %04x)" % (self.filter_id, self.argument_id, self.match_offset, self.unmatch_offset)

    def is_entitlement_start(self):
        return self.filter_id == 0x1e or self.filter_id == 0xa0

    def is_entitlement(self):
        return self.filter_id == 0x1e or self.filter_id == 0x1f or self.filter_id == 0x20 or self.filter_id == 0xa0

    def is_last_regular_expression(self):
        return self.filter_id == 0x81 and self.argument_id == num_regex-1

    def convert_filter(self, convert_fn, f):
        (self.filter, self.argument) = convert_fn(f, self.filter_id, self.argument_id)


class OperationNode():
    OPERATION_NODE_TYPE_NON_TERMINAL = 0x00
    OPERATION_NODE_TYPE_TERMINAL = 0x01
    offset = None
    raw = []
    type = None
    terminal = None
    non_terminal = None

    def __init__(self, offset):
        self.offset = offset

    def is_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_TERMINAL

    def is_non_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_NON_TERMINAL

    def parse_terminal(self):
        self.terminal = TerminalNode()
        self.terminal.parent = self
        self.terminal.type = self.raw[2] & 0x01
        self.terminal.flags = self.raw[2] & 0xfe

    def parse_non_terminal(self):
        self.non_terminal = NonTerminalNode()
        self.non_terminal.parent = self
        self.non_terminal.filter_id = self.raw[1]
        self.non_terminal.argument_id = self.raw[2] + (self.raw[3] << 8)
        self.non_terminal.match_offset = self.raw[4] + (self.raw[5] << 8)
        self.non_terminal.unmatch_offset = self.raw[6] + (self.raw[7] << 8)

    def parse_raw(self):
        self.type = self.raw[0]
        if self.is_terminal():
            self.parse_terminal()
        elif self.is_non_terminal():
            self.parse_non_terminal()

    def convert_filter(self, convert_fn, f):
        if self.is_non_terminal():
            self.non_terminal.convert_filter(convert_fn, f)

    def str_debug(self):
        ret = "(%02x) " % (self.offset)
        if self.is_terminal():
            ret += "terminal: "
            ret += str(self.terminal)
        if self.is_non_terminal():
            ret += "non-terminal: "
            ret += str(self.non_terminal)
        return ret

    def str_nodebug(self):
        ret = ""
        if self.is_terminal():
            ret += str(self.terminal)
        if self.is_non_terminal():
            ret += str(self.non_terminal)
        return ret

    def __str__(self):
        if DEBUG == 1:
            return self.str_debug()
        else:
            return self.str_nodebug()

    def __eq__(self, other):
        return self.raw == other.raw

    def __hash__(self):
        return self.offset


# Operation nodes processed so far.
processed_nodes = []

# Number of regular expressions.
num_regex = 0


def has_been_processed(node):
    global processed_nodes
    return node in processed_nodes


def build_operation_node(raw, offset):
    node = OperationNode(offset / 8)
    node.raw = raw
    node.parse_raw()
    return node


def build_operation_nodes(f, num_sb_ops):
    f.seek(2)
    end = struct.unpack("<H", f.read(2))[0] * 8
    start = (6 + 2 * num_sb_ops + 15) / 16 * 16
    num_operation_nodes = (end - start) / 8

    f.seek(start)
    operation_nodes = []
    for i in range(num_operation_nodes):
        offset = start + i*8
        f.seek(offset)
        raw = struct.unpack("<8B", f.read(8))
        operation_nodes.append(build_operation_node(raw, offset))
    for idx, node in enumerate(operation_nodes):
        print "%d: %s" % (idx, node)

    # Fill match and unmatch fields for each node in operation_nodes.
    for i in range(len(operation_nodes)):
        if operation_nodes[i].is_non_terminal():
            for j in range(len(operation_nodes)):
                if operation_nodes[i].non_terminal.match_offset == operation_nodes[j].offset:
                    operation_nodes[i].non_terminal.match = operation_nodes[j]
                if operation_nodes[i].non_terminal.unmatch_offset == operation_nodes[j].offset:
                    operation_nodes[i].non_terminal.unmatch = operation_nodes[j]

    return operation_nodes


def find_operation_node_by_offset(operation_nodes, offset):
    for node in operation_nodes:
        if node.offset == offset:
            return node
    return None


def build_operation_node_graph(node):
    if node.is_terminal():
        return None

    # If node is non-terminal and has already been processed, then it's a jump rule to a previous operation.
    if has_been_processed(node):
        return None

    # Create operation node graph.
    g = {}
    nodes_to_process = set()
    nodes_to_process.add((None, node))
    while nodes_to_process:
        (parent_node, current_node) = nodes_to_process.pop()
        if not current_node in g.keys():
            g[current_node] = {"list": set(), "decision": None, "type": set(["normal"]), "reduce": None}
        if not parent_node:
            g[current_node]["type"].add("start")
        # If match is terminal, end path.
        if current_node.non_terminal.match.is_terminal():
            g[current_node]["decision"] = str(current_node.non_terminal.match.terminal)
            g[current_node]["type"].add("final")
        else:
            if not has_been_processed(current_node.non_terminal.match):
                g[current_node]["list"].add(current_node.non_terminal.match)
                nodes_to_process.add((current_node, current_node.non_terminal.match))

        # For unmatch, only look for non terminal nodes.
        if current_node.non_terminal.unmatch.is_non_terminal():
            if not has_been_processed(current_node.non_terminal.unmatch):
                if parent_node:
                    g[parent_node]["list"].add(current_node.non_terminal.unmatch)
                nodes_to_process.add((parent_node, current_node.non_terminal.unmatch))

    processed_nodes.append(node)
    #print_operation_node_graph(g)
    g = clean_edges_in_operation_node_graph(g)
    return g


def print_operation_node_graph(g):
    if not g:
        return
    for node_iter in g.keys():
        sys.stdout.write("0x%x (%s): [ " % (node_iter.offset, g[node_iter]["type"]))
        for edge in g[node_iter]["list"]:
            sys.stdout.write("0x%x " % (edge.offset))
        sys.stdout.write("]\n")


def remove_edge_in_operation_node_graph(g, node_start, node_end):
    if node_end in g[node_start]["list"]:
        g[node_start]["list"].remove(node_end)
    return g


paths = []
current_path = []


def _get_operation_node_graph_paths(g, node):
    global paths, current_path
    current_path.append(node)
    if "final" in g[node]["type"]:
        copy_path = list(current_path)
        paths.append(copy_path)
    else:
        for next_node in g[node]["list"]:
            _get_operation_node_graph_paths(g, next_node)
    current_path.pop()


def get_operation_node_graph_paths(g, start_node):
    global paths, current_path
    paths = []
    current_path = []
    _get_operation_node_graph_paths(g, start_node)
    return paths


def clean_edges_in_operation_node_graph(g):
    """From the initial graph remove edges that are redundant.
    """
    start_nodes = []
    final_nodes = []
    for node_iter in g.keys():
        if "start" in g[node_iter]["type"]:
            start_nodes.append(node_iter)
        if "final" in g[node_iter]["type"]:
            final_nodes.append(node_iter)

    # Remove edges to start nodes.
    for snode in start_nodes:
        for node_iter in g.keys():
            g = remove_edge_in_operation_node_graph(g, node_iter, snode)

    #print_operation_node_graph(g)
    # Traverse graph and built all paths. If end node and start node of
    # two or more pathes are similar, remove vertices.
    for snode in start_nodes:
        paths = get_operation_node_graph_paths(g, snode)
        #print "for start node", snode, "paths are"
        #for p in paths:
        #    sys.stdout.write("[ ")
        #    for n in p:
        #        sys.stdout.write(str(n) + " ")
        #    sys.stdout.write("]\n")
        for i in range(0, len(paths)):
            for j in range(i+1, len(paths)):
                # Step over equal length paths.
                if len(paths[i]) == len(paths[j]):
                    continue
                elif len(paths[i]) < len(paths[j]):
                    p = paths[i]
                    q = paths[j]
                else:
                    p = paths[j]
                    q = paths[i]
                # If similar final nodes, remove edge.
                #print "short path: [",
                #for n in p:
                #    print n,
                #print "]"
                #print "long path: [",
                #for n in q:
                #    print n,
                #print "]"
                if p[len(p)-1] == q[len(q)-1]:
                    for i in range(0, len(p)):
                        if p[len(p)-1-i] == q[len(q)-1-i]:
                            continue
                        else:
                            g = remove_edge_in_operation_node_graph(g, q[len(q)-1-i], q[len(q)-i])
                            break

    return g


replace_occurred = False

class ReducedVertice():
    TYPE_SINGLE = "single"
    TYPE_REQUIRE_ANY = "require-any"
    TYPE_REQUIRE_ALL = "require-all"
    type = TYPE_SINGLE
    value = None
    decision = None

    def __init__(self, type=TYPE_SINGLE, value=None, decision=None):
        self.type = type
        self.value = value
        self.decision = decision

    def set_value(self, value):
        self.value = value

    def set_type(self, type):
        self.type = type

    def _replace_in_list(self, lst, old, new):
        global replace_occurred
        tmp_list = list(lst)
        for i, v in enumerate(tmp_list):
            if isinstance(v.value, list):
                self._replace_in_list(v.value, old, new)
            else:
                if v == old:
                    lst[i] = new
                    replace_occurred = True
                    return

    def replace_in_list(self, old, new):
        if isinstance(self.value, list):
            self._replace_in_list(self.value, old, new)

    def _replace_sublist_in_list(self, lst, old, new):
        global replace_occurred
        all_found = True
        for v in old:
            if v not in lst:
                all_found = False
                break
        if all_found:
            for v in old:
                lst.remove(v)
            lst.append(new)
            replace_occurred = True
            return

        for i, v in enumerate(lst):
            if isinstance(v.value, list):
                self._replace_sublist_in_list(v.value, old, new)
            else:
                return

    def replace_sublist_in_list(self, old, new):
        if isinstance(self.value, list):
            self._replace_sublist_in_list(self.value, old, new)

    def set_decision(self, decision):
        self.decision = decision

    def set_type_single(self):
        self.type = self.TYPE_SINGLE

    def set_type_require_any(self):
        self.type = self.TYPE_REQUIRE_ANY

    def set_type_require_all(self):
        self.type = self.TYPE_REQUIRE_ALL

    def is_type_single(self):
        return self.type == self.TYPE_SINGLE

    def is_type_require_all(self):
        return self.type == self.TYPE_REQUIRE_ALL

    def is_type_require_any(self):
        return self.type == self.TYPE_REQUIRE_ANY

    def recursive_str(self, level):
        result_str = ""
        if self.is_type_single():
            result_str += str(self.value)
        else:
            if level == 1:
                result_str += "\n" + 13*' '
            result_str += "(" + self.type
            level += 1
            for i, v in enumerate(self.value):
                if i == 0:
                    result_str += " " + v.recursive_str(level)
                else:
                    result_str += "\n" + 13*level*' ' + v.recursive_str(level)
            result_str += ")"
        return result_str

    def __str__(self):
        return self.recursive_str(1)


class ReducedEdge():
    start = None
    end = None

    def __init__(self, start=None, end=None):
        self.start = start
        self.end = end

    def __str__(self):
        return str(self.start) + " -> " + str(self.end)


class ReducedGraph():
    vertices = []
    edges = []
    final_vertices = []

    def __init__(self):
        self.vertices = []
        self.edges = []
        self.final_vertices = []

    def add_vertice(self, v):
        self.vertices.append(v)

    def add_edge(self, e):
        self.edges.append(e)

    def add_edge_by_vertices(self, v_start, v_end):
        e = ReducedEdge(v_start, v_end)
        self.edges.append(e)

    def set_final_vertices(self):
        self.final_vertices = []
        for v in self.vertices:
            is_final = True
            for e in self.edges:
                if v == e.start:
                    is_final = False
                    break
            if is_final:
                self.final_vertices.append(v)

    def contains_vertice(self, v):
        return v in self.vertices

    def contains_edge(self, e):
        return e in self.edges

    def contains_edge_by_vertices(self, v_start, v_end):
        for e in self.edges:
            if e.start == v_start and e.end == v_end:
                return True
        return False

    def get_vertice_by_value(self, value):
        for v in self.vertices:
            if v.is_type_single():
                if v.value == value:
                    return v

    def get_edge_by_vertices(self, v_start, v_end):
        for e in self.edges:
            if e.start == v_start and e.end == v_end:
                return e
        return None

    def remove_vertice(self, v):
        edges_copy = list(self.edges)
        for e in edges_copy:
            if e.start == v or e.end == v:
                self.edges.remove(e)
        if v in self.vertices:
            self.vertices.remove(v)

    def remove_edge(self, e):
        if e in self.edges:
            self.edges.remove(e)

    def remove_edge_by_vertices(self, v_start, v_end):
        e = self.get_edge_by_vertices(v_start, v_end)
        if e:
            self.edges.remove(e)

    def replace_vertice_in_edge_start(self, old, new):
        global replace_occurred
        for e in self.edges:
            replace_occurred = False
            if e.start == old:
                e.start = new
                replace_occurred = True
            else:
                if isinstance(e.start.value, list):
                    e.start.replace_in_list(old, new)
                    if replace_occurred:
                        e.start.decision = new.decision

    def replace_vertice_in_edge_end(self, old, new):
        global replace_occurred
        for e in self.edges:
            replace_occurred = False
            if e.end == old:
                e.end = new
                replace_occurred = True
            else:
                if isinstance(e.end.value, list):
                    e.end.replace_in_list(old, new)
                    if replace_occurred:
                        e.end.decision = new.decision

    def replace_vertice_in_single_vertices(self, old, new):
        for v in self.vertices:
            if len(self.get_next_vertices(v)) == 0 and len(self.get_prev_vertices(v)) == 0:
                if isinstance(v.value, list):
                    v.replace_in_list(old, new)

    def replace_vertice_list(self, old, new):
        for v in self.vertices:
            if isinstance(v.value, list):
                v.replace_sublist_in_list(old, new)
            if set(self.get_next_vertices(v)) == set(old):
                for n in old:
                    self.remove_edge_by_vertices(v, n)
                self.add_edge_by_vertices(v, new)
            if set(self.get_prev_vertices(v)) == set(old):
                for n in old:
                    self.remove_edge_by_vertices(n, v)
                self.add_edge_by_vertices(new, v)

    def get_next_vertices(self, v):
        next_vertices = []
        for e in self.edges:
            if e.start == v:
                next_vertices.append(e.end)
        return next_vertices

    def get_prev_vertices(self, v):
        prev_vertices = []
        for e in self.edges:
            if e.end == v:
                prev_vertices.append(e.start)
        return prev_vertices

    def get_start_vertices(self):
        start_vertices = []
        for v in self.vertices:
            if not self.get_prev_vertices(v):
                start_vertices.append(v)
        return start_vertices

    def get_end_vertices(self):
        end_vertices = []
        for v in self.vertices:
            if not self.get_next_vertices(v):
                end_vertices.append(v)
        return end_vertices

    def reduce_next_vertices(self, v):
        next_vertices = self.get_next_vertices(v)
        if len(next_vertices) <= 1:
            return
        new_vertice = ReducedVertice("require-any", next_vertices, next_vertices[0].decision)
        add_to_final = False
        for n in next_vertices:
            self.remove_edge_by_vertices(v, n)
        self.replace_vertice_list(next_vertices, new_vertice)
        for n in next_vertices:
            if n in self.final_vertices:
                self.final_vertices.remove(n)
                add_to_final = True
            # If no more next vertices, remove vertice.
            if not self.get_next_vertices(n):
                self.vertices.remove(n)
        self.add_edge_by_vertices(v, new_vertice)
        self.add_vertice(new_vertice)
        if add_to_final:
            self.final_vertices.append(new_vertice)

    def reduce_prev_vertices(self, v):
        prev_vertices = self.get_prev_vertices(v)
        if len(prev_vertices) <= 1:
            return
        new_vertice = ReducedVertice("require-any", prev_vertices, v.decision)
        for p in prev_vertices:
            self.remove_edge_by_vertices(p, v)
        self.replace_vertice_list(prev_vertices, new_vertice)
        for p in prev_vertices:
            # If no more prev vertices, remove vertice.
            if not self.get_prev_vertices(p):
                self.vertices.remove(p)
        self.add_vertice(new_vertice)
        self.add_edge_by_vertices(new_vertice, v)

    def reduce_vertice_single_prev(self, v):
        global replace_occurred
        prev = self.get_prev_vertices(v)
        if len(prev) != 1:
            return
        p = prev[0]
        nexts = self.get_next_vertices(p)
        if len(nexts) > 1 or nexts[0] != v:
            return
        require_all_vertices = []
        if p.is_type_require_all():
            require_all_vertices.extend(p.value)
        else:
            require_all_vertices.append(p)
        if v.is_type_require_all():
            require_all_vertices.extend(v.value)
        else:
            require_all_vertices.append(v)
        new_vertice = ReducedVertice("require-all", require_all_vertices, v.decision)
        self.remove_edge_by_vertices(p, v)
        replace_occurred = False
        self.replace_vertice_in_edge_start(v, new_vertice)
        self.replace_vertice_in_edge_end(p, new_vertice)
        self.replace_vertice_in_single_vertices(p, new_vertice)
        self.replace_vertice_in_single_vertices(v, new_vertice)
        self.remove_vertice(p)
        self.remove_vertice(v)
        if not replace_occurred:
            self.add_vertice(new_vertice)
        if v in self.final_vertices:
            self.final_vertices.remove(v)
            self.final_vertices.append(new_vertice)

    def reduce_vertice_single_next(self, v):
        global replace_occurred
        next = self.get_next_vertices(v)
        if len(next) != 1:
            return
        n = next[0]
        prevs = self.get_prev_vertices(n)
        if len(prevs) > 1 or prevs[0] != v:
            return
        require_all_vertices = []
        if v.is_type_require_all():
            require_all_vertices.extend(v.value)
        else:
            require_all_vertices.append(v)
        if n.is_type_require_all():
            require_all_vertices.extend(n.value)
        else:
            require_all_vertices.append(n)
        new_vertice = ReducedVertice("require-all", require_all_vertices, n.decision)
        self.remove_edge_by_vertices(v, n)
        replace_occurred = False
        self.replace_vertice_in_edge_start(n, new_vertice)
        self.replace_vertice_in_edge_end(v, new_vertice)
        self.replace_vertice_in_single_vertices(v, new_vertice)
        self.replace_vertice_in_single_vertices(n, new_vertice)
        self.remove_vertice(v)
        self.remove_vertice(n)
        if not replace_occurred:
            self.add_vertice(new_vertice)
        if n in self.final_vertices:
            self.final_vertices.remove(n)
            self.final_vertices.append(new_vertice)

    def reduce_graph(self):
        self.set_final_vertices()

        #print "before everything:\n", self.print_simple()
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            self.reduce_next_vertices(v)
        #print "after next:\n", self.print_simple()
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            self.reduce_prev_vertices(v)
        #print "after next/prev:\n", self.print_simple()

        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            self.reduce_vertice_single_prev(v)
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            self.reduce_vertice_single_next(v)

    def print_simple(self):
        print "==== vertices:"
        for v in self.vertices:
            print "decision:", v.decision, "\t", v
        print "==== final vertices:"
        for v in self.final_vertices:
            print "decision:", v.decision, "\t", v
        print "==== edges:"
        for e in self.edges:
            print "\t", e

    def __str__(self):
        result_str = ""
        for v in self.vertices:
            result_str += "(" + str(v.decision) + " "
            if len(self.get_next_vertices(v)) == 0 and len(self.get_next_vertices(v)) == 0:
                if v in self.final_vertices:
                    result_str += str(v) + "\n"
            result_str += ")\n"
        for e in self.edges:
            result_str += str(e) + "\n"
        result_str += "\n"
        return result_str

    def print_vertices_with_operation(self, operation, out_f):
        allow_vertices = [v for v in self.vertices if v.decision == "allow"]
        deny_vertices = [v for v in self.vertices if v.decision == "deny"]
        if allow_vertices:
            out_f.write("(allow %s " % (operation))
            if len(allow_vertices) > 1:
                for v in allow_vertices:
                    out_f.write("\n" + 8*" " + str(v))
            else:
                out_f.write(str(allow_vertices[0]))
            out_f.write(")\n")
        if deny_vertices:
            out_f.write("(deny %s " % (operation))
            if len(deny_vertices) > 1:
                for v in deny_vertices:
                    out_f.write("\n" + 8*" " + str(v))
            else:
                out_f.write(str(deny_vertices[0]))
            out_f.write(")\n")


def reduce_operation_node_graph(g):
    # Create reduced graph.
    rg = ReducedGraph()
    for node_iter in g.keys():
        rv = ReducedVertice(value=node_iter, decision=g[node_iter]["decision"])
        rg.add_vertice(rv)

    for node_iter in g.keys():
        rv = rg.get_vertice_by_value(node_iter)
        for node_next in g[node_iter]["list"]:
            rn = rg.get_vertice_by_value(node_next)
            rg.add_edge_by_vertices(rv, rn)

    rg.reduce_graph()
    return rg


def main():
    if len(sys.argv) != 3:
        print >> sys.stderr, "Usage: %s binary_sandbox_file operations_file" % (sys.argv[0])
        sys.exit(-1)

    # Read sandbox operations.
    sb_ops = [l.strip() for l in open(sys.argv[2])]
    num_sb_ops = len(sb_ops)
    print "num_sb_ops:", num_sb_ops

    f = open(sys.argv[1], "rb")
    operation_nodes = build_operation_nodes(f, num_sb_ops)

    global num_regex
    f.seek(4)
    num_regex = struct.unpack("<H", f.read(2))[0]
    print "num_regex: %02x" % (num_regex)
    f.seek(6)
    sb_ops_offsets = struct.unpack("<%dH" % (num_sb_ops), f.read(2*num_sb_ops))

    # Extract node for 'default' operation (index 0).
    default_node = find_operation_node_by_offset(operation_nodes, sb_ops_offsets[0])
    print "(%s default)" % (default_node.terminal)

    # For each operation expand operation node.
    #for idx in range(1, len(sb_ops_offsets)):
    for idx in range(10, 11):
        offset = sb_ops_offsets[idx]
        operation = sb_ops[idx]
        node = find_operation_node_by_offset(operation_nodes, offset)
        if not node:
            print "operation %s (index %d) has no operation node" % (operation, idx)
            continue
        #print "expanding operation %s (index %d, offset: %02x)" % (operation, idx, offset)
        g = build_operation_node_graph(node)
        #print "reducing operation %s (index %d, offset: %02x)" % (operation, idx, offset)
        #print_operation_node_graph(g)
        if g:
            rg = reduce_operation_node_graph(g)
            rg.print_vertices_with_operation(operation)
        else:
            if node.terminal:
                if node.terminal.type != default_node.terminal.type:
                    print "(%s %s)" % (node.terminal, operation)


if __name__ == "__main__":
    sys.exit(main())
