#!/usr/bin/env python

"""
iOS/OS X sandbox decompiler

Heavily inspired from Dion Blazakis' previous work
    https://github.com/dionthegod/XNUSandbox/tree/master/sbdis
Excellent information from Stefan Essers' slides and work
    http://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements
    https://github.com/sektioneins/sandbox_toolkit
"""

import sys
import mmap
import struct
import time
import operation_node


def get_re_index_for_pos(re, pos):
    for idx, item in enumerate(re):
        if item["pos"] == pos:
            return idx
    for idx, item in enumerate(re):
        if item["pos"]-1 == pos:
            return idx
    return -1


def create_regex_fsm_nodes(re):
    re_backup = list(re)
    nodes = []
    for idx, item in enumerate(re):
        node = {
                "type": None,
                "next": None,
                "value": None,
                "traversal": "white"
                }
        if item["type"] == "jump_backward":
            node["type"] = "jump_backward"
            node["next"] = [ get_re_index_for_pos(re_backup, item["value"]) ]
            node["value"] = None
        elif item["type"] == "jump_forward":
            node["type"] = "jump_forward"
            node["next"] = [ get_re_index_for_pos(re_backup, item["value"]), idx+1 ]
            node["value"] = None
        elif item["type"] == "end":
            node["type"] = "end"
            node["next"] = [ idx+1 ]
            node["value"] = None
        else:
            node["type"] = item["type"]
            node["next"] = [ idx+1 ]
            node["value"] = item["value"]
        nodes.append(node)
    return nodes


class Node():
    TYPE_JUMP_FORWARD = 1
    TYPE_JUMP_BACKWARD = 2
    TYPE_CHARACTER = 3
    TYPE_END = 4
    FLAG_WHITE = 1
    FLAG_GREY = 2
    FLAG_BLACK = 3
    name = ""
    type = None
    value = None
    flag = "white"

    def __init__(self, name=None, type=None, value=''):
        self.name = name
        self.type = type
        self.value = value
        self.flag = self.FLAG_WHITE

    def set_name(self, name):
        self.name = name

    def set_type_jump_forward(self):
        self.type = self.TYPE_JUMP_FORWARD

    def set_type_jump_backward(self):
        self.type = self.TYPE_JUMP_BACKWARD

    def set_type_character(self):
        self.type = self.TYPE_CHARACTER

    def set_type_end(self):
        self.type = self.TYPE_END

    def is_type_end(self):
        return self.type == self.TYPE_END

    def is_type_jump(self):
        return self.type == self.TYPE_JUMP_BACKWARD or self.type == self.TYPE_JUMP_FORWARD

    def is_type_jump_backward(self):
        return self.type == self.TYPE_JUMP_BACKWARD

    def is_type_jump_forward(self):
        return self.type == self.TYPE_JUMP_FORWARD

    def is_type_character(self):
        return self.type == self.TYPE_CHARACTER

    def set_value(self, value):
        self.value = value

    def set_flag_white(self):
        self.flag = self.FLAG_WHITE

    def set_flag_grey(self):
        self.flag = self.FLAG_GREY

    def set_flag_black(self):
        self.flag = self.FLAG_BLACK

    def __str__(self):
        if self.type == self.TYPE_JUMP_BACKWARD:
            return "(%s: jump backward)" % (self.name)
        elif self.type == self.TYPE_JUMP_FORWARD:
            return "(%s: jump forward)" % (self.name)
        elif self.type == self.TYPE_END:
            return "(%s: end)" % (self.name)
        else:
            return "(%s: %s)" % (self.name, self.value)


class Graph():
    graph_dict = {}
    canon_graph_dict = {}
    node_list = []
    start_node = None
    end_states = []
    start_state = 0
    regex = []
    unified_regex = ""

    def __init__(self):
        self.graph_dict = {}

    def add_node(self, node, next_list=None):
        self.graph_dict[node] = next_list

    def has_node(self, node):
        return node in graph_dict.keys()

    def update_node(self, node, next_list):
        self.graph_dict[node] = next_list

    def add_new_next_to_node(self, node, next):
        self.graph_dict[node].append(next)

    def __str__(self):
        # Get maximum node number.
        max = -1
        for node in self.graph_dict.keys():
            if max < int(node.name):
                max = int(node.name)

        # Create graph list for ordered listing of nodes.
        graph_list = [None] * (max+1)
        for node in self.graph_dict.keys():
            actual_string = str(node) + ":"
            for next_node in self.graph_dict[node]:
                actual_string += " " + str(next_node)
            graph_list[int(node.name)] = actual_string

        # Store node graph in ret_string.
        ret_string = "\n-- Node graph --\n"
        for s in graph_list:
            if s:
                ret_string += s + "\n"

        # Store canonical graph in ret_string.
        ret_string += "\n-- Canonical graph --\n"
        for state in self.canon_graph_dict.keys():
            if state == self.start_state:
                ret_string += "> "
            elif state in self.end_states:
                ret_string += "# "
            else:
                ret_string += "  "
            ret_string += "%d: %s\n" % (state, self.canon_graph_dict[state])
        ret_string += "\n"
        return ret_string

    def get_node_for_idx(self, idx):
        if idx >= len(self.node_list):
            return None
        return self.node_list[idx]

    def fill_from_regex_list(self, regex_list):
        # First create list of nodes. No pointers/links at this point.
        # Create a node for each item.
        self.node_list = []
        for idx, item in enumerate(regex_list):
            node = Node(name="%s" % (idx))
            if item["type"] == "jump_backward":
                node.set_type_jump_backward()
            elif item["type"] == "jump_forward":
                node.set_type_jump_forward()
            elif item["type"] == "end":
                node.set_type_end()
            else:
                node.set_type_character()
                node.set_value(item["value"])
            self.node_list.append(node)

        self.graph_dict = {}
        for idx, node in enumerate(self.node_list):
            # If node is end node ignore.
            if node.is_type_end():
                 self.graph_dict[node] = []
            elif node.is_type_character():
                next = self.get_node_for_idx(idx+1)
                if next:
                    self.graph_dict[node] = [ next ]
                else:
                    self.graph_dict[node] = []
            # Node is jump node.
            elif node.is_type_jump_backward():
                next_idx = get_re_index_for_pos(regex_list, regex_list[idx]["value"])
                next = self.get_node_for_idx(next_idx)
                if next:
                    self.graph_dict[node] = [next]
                else:
                    self.graph_dict[node] = []
            elif node.is_type_jump_forward():
                next_idx1 = idx+1
                next_idx2 = get_re_index_for_pos(regex_list, regex_list[idx]["value"])
                next1 = self.get_node_for_idx(next_idx1)
                next2 = self.get_node_for_idx(next_idx2)
                self.graph_dict[node] = []
                if next1:
                    self.graph_dict[node].append(next1)
                if next2:
                    self.graph_dict[node].append(next2)

    def get_character_nodes(self, node):
        node_list = []
        for next in self.graph_dict[node]:
            if next.is_type_character() or next.is_type_end():
                node_list.append(next)
            else:
                node_list = list(set(node_list).union(self.get_character_nodes(next)))
        return node_list

    def find_node_type_jump(self, current_node, node, backup_dict):
        if not current_node.is_type_jump():
            return False
        if current_node == node:
            return True
        if not self.graph_dict[current_node]:
            return False
        for next_node in backup_dict[current_node]:
            if self.find_node_type_jump(next_node, node, backup_dict):
                return True
        return False

    def reduce(self):
        star_node = None
        for node in self.graph_dict.keys():
            if node.is_type_character():
                self.graph_dict[node] = self.get_character_nodes(node)
            if node.name == "0":
                start_node = node
        old_dict = dict(self.graph_dict)
        backup_dict = dict(self.graph_dict)
        for node in old_dict.keys():
            if node.is_type_jump():
                if self.find_node_type_jump(start_node, node, backup_dict):
                    continue
                del self.graph_dict[node]

    def get_edges(self, node):
        edges = []
        is_end_state = False
        for next in self.graph_dict[node]:
            if next.is_type_end():
                is_end_state = True
            else:
                edges.append((next.value, int(next.name)))
        return is_end_state, edges

    def convert_to_canonical(self):
        self.end_states = []
        for node in self.graph_dict.keys():
            if node.is_type_end():
                continue
            state_idx = int(node.name)
            is_end_state, self.canon_graph_dict[state_idx] = self.get_edges(node)
            if is_end_state == True:
                self.end_states.append(state_idx)
        for node in self.graph_dict.keys():
            if node.name == "0":
                self.start_state = -1
                self.canon_graph_dict[-1] = [ (node.value, 0) ]
        print self.canon_graph_dict
        print "end_states:", self.end_states
        print "start_state:", self.start_state

    def need_use_plus(self, initial_string, string_to_add):
        if not string_to_add.endswith("*"):
            return False

        if string_to_add.startswith("(") and string_to_add[-2:-1] == ")":
            actual_part = string_to_add[1:-2]
        else:
            actual_part = string_to_add[:-1]
        if initial_string.endswith(actual_part):
            return True
        if initial_string.endswith(string_to_add):
            return True

        return False

    def unify_two_strings(self, s1, s2):
        # Find largest common starting substring.
        lcss = ""
        for i in range(1, len(s1)+1):
            if s2.find(s1[:i], 0, i) != -1:
                lcss = s1[:i]
        if lcss:
            s1 = s1[len(lcss):]
            s2 = s2[len(lcss):]
        # Find largest common ending substring.
        lces = ""
        for i in range(1, len(s1)+1):
            if s2.find(s1[-i:], len(s2)-i, len(s2)) != -1:
                lces = s1[-i:]
        if lces:
            s1 = s1[:len(s1)-len(lces)]
            s2 = s2[:len(s2)-len(lces)]

        if not s1 and not s2:
            return lcss + lces

        if s1 and s2:
            return lcss + "(" + s1 + "|" + s2 + ")" + lces

        # Make s1 the empty string.
        if not s2:
            aux = s1
            s1 = s2
            s2 = aux

        if s2[-1] == '+':
            s2 = s2[:-1] + '*'
        else:
            if len(s2) > 1:
                s2 = "(" + s2 + ")?"
            else:
                s2 = s2 + '?'

        return lcss + s2 + lces

    def unify_strings(self, string_list):
        unified = ""
        if not string_list:
            return None
        if len(string_list) == 1:
            return string_list[0]
        # We now know we have multiple strings. Merge two at a time.
        current = string_list[0]
        for s in string_list[1:]:
            current = self.unify_two_strings(current, s)
        return current

    def remove_state(self, state_to_remove):
        itself_string = ""
        for (next_string, next_state) in self.canon_graph_dict[state_to_remove]:
            if next_state == state_to_remove:
                if len(next_string) > 1:
                    itself_string = "(%s)*" % next_string
                else:
                    itself_string = "%s*" % next_string

        # Create list of to_strings indexed by to_states.
        to_strings = {}
        for to_state in self.canon_graph_dict.keys():
            to_strings[to_state] = []
            if to_state == state_to_remove:
                continue
            for (iter_to_string, iter_to_state) in self.canon_graph_dict[state_to_remove]:
                if iter_to_state == to_state:
                    to_strings[to_state].append(iter_to_string)

        # Unify multiple strings leading to the same to_state.
        unified_to_string = {}
        for to_state in to_strings.keys():
            unified_to_string[to_state] = self.unify_strings(to_strings[to_state])

        # Go through all graph edges.
        for from_state in self.canon_graph_dict.keys():
            # Pass current state to remove.
            if from_state == state_to_remove:
                continue
            items_to_remove_list = []
            for (next_string, next_state) in self.canon_graph_dict[from_state]:
                # Only if edge points to state_to_remove.
                if next_state != state_to_remove:
                    continue
                # Plan edge to remove. Create new edge bypassing state_to_remove.
                items_to_remove_list.append((next_string, next_state))
                for to_state in self.canon_graph_dict.keys():
                    if len(to_strings[to_state]) == 0:
                        continue
                    to_string = unified_to_string[to_state]
                #for (to_string, to_state) in self.canon_graph_dict[state_to_remove]:
                #    # If state points to itself, do not add edge.
                #    if to_state == state_to_remove:
                #        continue
                    # Add new edge, consider if state points to itself.
                    if self.need_use_plus(next_string, itself_string):
                        self.canon_graph_dict[from_state].append((next_string + "+" + to_string, to_state))
                        continue
                    self.canon_graph_dict[from_state].append((next_string + itself_string + to_string, to_state))
            for (next_string, next_state) in items_to_remove_list:
                self.canon_graph_dict[from_state].remove((next_string, next_state))

        del self.canon_graph_dict[state_to_remove]

    def simplify(self):
        tmp_dict = dict(self.canon_graph_dict)
        for state in tmp_dict.keys():
            if state != self.start_state and state not in self.end_states:
                self.remove_state(state)

    def combine_start_end_nodes(self):
        working_strings = self.canon_graph_dict[self.start_state]
        final_strings = []
        string_added = True
        while string_added == True:
            string_added = False
            initial_strings = working_strings
            working_strings = []
            for (start_string, start_next_state) in initial_strings:
                if not start_next_state in self.end_states:
                    continue
                if self.canon_graph_dict[start_next_state]:
                    for (next_string, next_state) in self.canon_graph_dict[start_next_state]:
                        if next_state == start_next_state:
                            next_string = "(%s)*" % next_string
                            if self.need_use_plus(start_string, next_string):
                                final_strings.append((start_string + "+", None))
                            else:
                                final_strings.append((start_string + next_string, None))
                        else:
                            final_strings.append((start_string + next_string, None))
                            working_strings.append((start_string + next_string, next_state))
                else:
                    final_strings.append((start_string, None))
                string_added = True
        self.regex = [x[0] for x in final_strings]
        self.unified_regex = self.unify_strings(self.regex)


def print_regex_fsm_nodes(nodes):
    for idx, node in enumerate(nodes):
        if node["type"] == "jump_backward":
            print "%d: jump backward to: %d" % (idx, node["next"][0])
        elif node["type"] == "jump_forward":
            print "%d: jump forward to: %d, %d" % (idx, node["next"][0], node["next"][1])
        elif node["type"] == "end":
            print "%d: end" % idx
        else:
            print "%d: %s" % (idx, node["value"])


def process_node(nodes, node, idx):
    if node["type"] == "jump_backward":
        next = process_node(nodes, nodes[node["next"][0]], node["next"][0])
        if next == None:
            pass
    elif node["type"] == "jump_forward":
        next0 = process_node(nodes, nodes[node["next"][0]], node["next"][0])
        next1 = process_node(nodes, nodes[node["next"][1]], node["next"][1])
        if next == None:
            pass
    elif node["type"] == "end":
        return None
    else:
        return node["value"]


def parse_regex(re):
    regex_list = []

    print "    re.type: 0x%x" % ((re[0] >> 24) + (re[1] >> 16) + (re[2] >> 8) + re[3])
    print "    re.length: 0x%x" % (re[4] + (re[5] >> 8))

    i = 6
    while i < len(re):
        # Actual character.
        if re[i] == 0x02:
            value = chr(re[i+1])
            if value == ".":
                value = "\\."
            regex_list.append({
                "pos": i-6,
                "type": "character",
                "value": value}
                )
            i = i+1
        # Beginning of line.
        elif re[i] == 0x19:
            regex_list.append({
                "pos": i-6,
                "type": "character",
                "value": "^"}
                )
        # End of line.
        elif re[i] == 0x29:
            regex_list.append({
                "pos": i-6,
                "type": "character",
                "value": "$"}
                )
        # Any character.
        elif re[i] == 0x09:
            regex_list.append({
                "pos": i-6,
                "type": "character",
                "value": "."}
                )
        # Jump forward.
        elif re[i] == 0x2f:
            jump_to = re[i+1] + (re[i+2] << 8)
            regex_list.append({
                "pos": i-6,
                "type": "jump_forward",
                "value": jump_to}
                )
            i = i+2
        # Jump backward.
        elif re[i] & 0xf == 0xa:
            jump_to = re[i+1] + (re[i+2] << 8)
            regex_list.append({
                "pos": i-6,
                "type": "jump_backward",
                "value": jump_to}
                )
            print "(0xa) i: %d (0x%x), re[i, i+1, i+2]: 0x%x, 0x%x, 0x%x" % (i, i, re[i], re[i+1], re[i+2])
            print "value: 0x%x" % jump_to
            i = i+2
        # Character class.
        elif re[i] & 0xf == 0xb:
            num = (re[i] >> 4)
            i = i+1
            print "i: %d, num: %d" % (i, num)
            values = []
            value = "["
            for j in range(0, num):
                values.append(re[i+2*j])
                values.append(re[i+2*j+1])
            first = values[0]
            last = values[2*num-1]
            # In case of exlucdes.
            if (first > last):
                node_type = "class_exclude"
                value += "^"
                for j in range(len(values)-1, 0, -1):
                    values[j] = values[j-1]
                values[0] = last
                for j in range(0, len(values)):
                    if j % 2 == 0:
                        values[j] = values[j]+1
                    else:
                        values[j] = values[j]-1
            else:
                node_type = "class"
            for j in range(0, len(values), 2):
                if values[j] < values[j+1]:
                    value += "%s-%s" % (chr(values[j]), chr(values[j+1]))
                else:
                    value += "%s" % (chr(values[j]))
            value += "]"
            regex_list.append({
                "pos": i-6,
                "type": node_type,
                "value": value
                })
            print "values: [", ", ".join([hex(j) for j in values]), "]"
            i += 2*num-1
        elif re[i] & 0xf == 0x5:
            regex_list.append({
                "pos": i-6,
                "type": "end",
                "value": 0
                })
            i = i+1
        else:
            print "##########unknown", hex(re[i])
        i = i+1
    nodes = create_regex_fsm_nodes(regex_list)
    print_regex_fsm_nodes(nodes)
    g = Graph()
    g.fill_from_regex_list(regex_list)
    g.reduce()
    g.convert_to_canonical()
    g.simplify()
    g.combine_start_end_nodes()
    #print g
    return [ g.unified_regex ]


def get_filter_arg_string_by_offset(f, offset):
    f.seek(offset * 8)
    len = struct.unpack("<I", f.read(4))[0]
    type = struct.unpack("<B", f.read(1))[0]
    #print "normal string, type is 0x%02x" %(type)
    return '"%s"' % f.read(len)


def get_filter_arg_string_by_offset_with_type(f, offset):
    f.seek(offset * 8)
    len = struct.unpack("<I", f.read(4))[0]
    type = struct.unpack("<B", f.read(1))[0]
    append = ""
    if type == 0x01:
        append = "path"
    elif type == 0x00:
        append = "literal"
    return (append, '"%s"' % f.read(len))


def get_filter_arg_string_by_offset_no_skip(f, offset):
    f.seek(offset * 8)
    len = struct.unpack("<I", f.read(4))[0]-1
    return '"%s"' % f.read(len)


def get_filter_arg_network_address(f, offset):
    f.seek(offset * 8)

    host, port = struct.unpack("<HH", f.read(4))
    host_port_string = ""
    if host == 0x1:
        proto = "ip4"
        host_port_string += "*"
    elif host == 0x2:
        proto = "ip6"
        host_port_string += "*"
    elif host == 0x3:
        proto = "ip"
        host_port_string += "*"
    elif host == 0x5:
        proto = "tcp4"
        host_port_string += "*"
    elif host == 0x6:
        proto = "tcp6"
        host_port_string += "*"
    elif host == 0x7:
        proto = "tcp"
        host_port_string += "*"
    elif host == 0x9:
        proto = "udp4"
        host_port_string += "*"
    elif host == 0xa:
        proto = "udp6"
        host_port_string += "*"
    elif host == 0xb:
        proto = "udp"
        host_port_string += "*"
    elif host == 0x101:
        proto = "ip4"
        host_port_string += "localhost"
    elif host == 0x102:
        proto = "ip6"
        host_port_string += "localhost"
    elif host == 0x103:
        proto = "ip"
        host_port_string += "localhost"
    elif host == 0x105:
        proto = "tcp4"
        host_port_string += "localhost"
    elif host == 0x106:
        proto = "tcp6"
        host_port_string += "localhost"
    elif host == 0x107:
        proto = "tcp"
        host_port_string += "localhost"
    elif host == 0x109:
        proto = "udp4"
        host_port_string += "localhost"
    elif host == 0x10a:
        proto = "udp6"
        host_port_string += "localhost"
    elif host == 0x10b:
        proto = "udp"
        host_port_string += "localhost"
    else:
        proto = "unknown"
        host_port_string += "0x%x" % host

    if port == 0:
        host_port_string += ":*"
    else:
        host_port_string += ":%d" % (port)
    return '%s "%s"' % (proto, host_port_string)


def get_filter_arg_integer(f, arg):
    return '%d' % arg


def get_filter_arg_octal_integer(f, arg):
    return '#o%04o' % arg


def get_filter_arg_boolean(f, arg):
    if arg == 1:
        return '#t'
    else:
        return '#f'


regex_list = []
def get_filter_arg_regex_by_id(f, regex_id):
    global regex_list
    return_string = ""
    for regex in regex_list[regex_id]:
        return_string += ' #"%s"' % (regex)
    return return_string[1:]


def get_filter_arg_ctl(f, arg):
    letter = chr(arg >> 8)
    number = arg & 0xff
    return '(_IO "%s" %d)' % (letter, number)


def get_filter_arg_vnode_type(f, arg):
    arg_types = {
            0x01: "REGULAR-FILE",
            0x02: "DIRECTORY",
            0x03: "BLOCK-DEVICE",
            0x04: "CHARACTER-DEVICE",
            0x05: "SYMLINK",
            0x06: "SOCKET",
            0x07: "FIFO",
            0xffff: "TTY"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_owner(f, arg):
    arg_types = {
            0x01: "self",
            0x02: "pgrp",
            0x03: "others",
            0x04: "children",
            0x05: "same-sandbox"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_socket_domain(f, arg):
    arg_types = {
            0: "AF_UNSPEC",
            1: "AF_UNIX",
            2: "AF_INET",
            3: "AF_IMPLINK",
            4: "AF_PUP",
            5: "AF_CHAOS",
            6: "AF_NS",
            7: "AF_ISO",
            8: "AF_ECMA",
            9: "AF_DATAKIT",
            10: "AF_CCITT",
            11: "AF_SNA",
            12: "AF_DECnet",
            13: "AF_DLI",
            14: "AF_LAT",
            15: "AF_HYLINK",
            16: "AF_APPLETALK",
            17: "AF_ROUTE",
            18: "AF_LINK",
            19: "pseudo_AF_XTP",
            20: "AF_COIP",
            21: "AF_CNT",
            22: "pseudo_AF_RTIP",
            23: "AF_IPX",
            24: "AF_SIP",
            25: "pseudo_AF_PIP",
            27: "AF_NDRV",
            28: "AF_ISDN",
            29: "pseudo_AF_KEY",
            30: "AF_INET6",
            31: "AF_NATM",
            32: "AF_SYSTEM",
            33: "AF_NETBIOS",
            34: "AF_PPP",
            35: "pseudo_AF_HDRCMPLT",
            36: "AF_RESERVED_36",
            37: "AF_IEEE80211",
            38: "AF_UTUN",
            40: "AF_MAX"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_socket_type(f, arg):
    arg_types = {
        0x01: "SOCK_STREAM",
        0x02: "SOCK_DGRAM",
        0x03: "SOCK_RAW",
        0x04: "SOCK_RDM",
        0x05: "SOCK_SEQPACKET"
        }
    if arg in arg_types.keys():
        return '"%s"' % (arg_types[arg])
    else:
        return '%d' % arg


def get_none(f, arg):
    return None


filters = {
        0x81: {
            "name": "regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
        0x01: {
            "name": "",
            "arg_process_fn": get_filter_arg_string_by_offset_with_type
            },
        0x03: {
            "name": "xattr",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
        0x06: {
            "name": "global-name",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
        0x07: {
            "name": "local-name",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
        0x0e: {
            "name": "target",
            "arg_process_fn": get_filter_arg_owner
            },
        0x85: {
            "name": "ipc-posix-name-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
        0x87: {
            "name": "local-name-regex",
            "arg_process_fn": get_filter_arg_regex_by_id
            },
        0x05: {
            "name": "ipc-posix-name",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
        0x04: {
            "name": "file-mode",
            "arg_process_fn": get_filter_arg_octal_integer
            },
        0x1d: {
            "name": "vnode-type",
            "arg_process_fn": get_filter_arg_vnode_type
            },
        0x22: {
            "name": "info-type",
            "arg_process_fn": get_filter_arg_string_by_offset
            },
        0x08: {
            "name": "local",
            "arg_process_fn": get_filter_arg_network_address
            },
        0x09: {
                "name": "remote",
                "arg_process_fn": get_filter_arg_network_address
                },
        0x11: {
                "name": "iokit-user-client-class",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x12: {
                "name": "iokit-property",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x13: {
                "name": "iokit-connection",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x16: {
                "name": "device-conforms-to",
                "arg_process_fn": get_filter_arg_string_by_offset_no_skip
                },
        0x0a: {
                "name": "control-name",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x17: {
                "name": "extension",
                "arg_process_fn": get_filter_arg_string_by_offset_no_skip
                },
        0x83: {
                "name": "xattr-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x0b: {
                "name": "socket-domain",
                "arg_process_fn": get_filter_arg_socket_domain
                },
        0x0d: {
                "name": "socket-protocol",
                "arg_process_fn": get_filter_arg_integer
                },
        0x19: {
                "name": "appleevent-destination",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x99: {
                "name": "appleevent-destination-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x1b: {
                "name": "right-name",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x9b: {
                "name": "right-name-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x18: {
                "name": "extension-class",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x82: {
                "name": "mount-relative-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x86: {
                "name": "global-name-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x1c: {
                "name": "preference-domain",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x0f: {
                "name": "fsctl-command",
                "arg_process_fn": get_filter_arg_ctl
                },
        0x10: {
                "name": "ioctl-command",
                "arg_process_fn": get_filter_arg_ctl
                },
        0x1e: {
                "name": "require-entitlement",
                "arg_process_fn": get_filter_arg_string_by_offset_no_skip
                },
        0x23: {
                "name": "notification-name",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x24: {
                "name": "notification-payload",
                "arg_process_fn": get_filter_arg_integer
                },
        0xa3: {
                "name": "notification-name-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x14: {
                "name": "device-major",
                "arg_process_fn": get_filter_arg_integer
                },
        0x15: {
                "name": "device-minor",
                "arg_process_fn": get_filter_arg_integer
                },
        0x02: {
                "name": "mount-relative",
                "arg_process_fn": get_filter_arg_string_by_offset_with_type
                },
        0x98: {
                "name": "extension-class-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0xa0: {
                "name": "entitlement-value-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x91: {
                "name": "iokit-user-client-class-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x92: {
                "name": "iokit-connection-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x93: {
                "name": "iokit-property-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x9c: {
                "name": "preference-domain-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x26: {
                "name": "sysctl-name",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0xa6: {
                "name": "sysctl-name-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x27: {
                "name": "process-name",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0xa7: {
                "name": "process-name-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x21: {
                "name": "kext-bundle-id",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0xa1: {
                "name": "kext-bundle-id-regex",
                "arg_process_fn": get_filter_arg_regex_by_id
                },
        0x25: {
                "name": "semaphore-owner",
                "arg_process_fn": get_filter_arg_owner
                },
        0x0c: {
                "name": "socket-type",
                "arg_process_fn": get_filter_arg_socket_type
                },
        0x1f: {
                "name": "entitlement-value",
                "arg_process_fn": get_filter_arg_boolean
                },
        0x20: {
                "name": "entitlement-value",
                "arg_process_fn": get_filter_arg_string_by_offset
                },
        0x1a: {
                "name": "debug-mode",
                "arg_process_fn": get_none
                }
        }


def convert_filter_callback(f, filter_id, filter_arg):
    """Convert binary filter (id and argument) to pair of strings:
    name and argument as string.
    """
    if not filter_id in filters.keys():
        return (None, None)
    filter = filters[filter_id]
    if not filter["arg_process_fn"]:
        return (None, None)
    if filter["arg_process_fn"] == get_filter_arg_string_by_offset_with_type:
        (append, result) = filter["arg_process_fn"](f, filter_arg)
        if filter_id == 0x01 and append == "path":
            append = "subpath"
        return (filter["name"] + append, result)
    return (filter["name"], filter["arg_process_fn"](f, filter_arg))


def entitlement_needs_removing(f, match_offset, unmatch_offset):
    f.seek(match_offset * 8)
    match_is_terminal = ord(f.read(1)) == 1
    match_filter, match_filter_arg, match_next_match, match_next_unmatch = struct.unpack("<BHHH", f.read(7))

    f.seek(unmatch_offset * 8)
    unmatch_is_terminal = ord(f.read(1)) == 1
    unmatch_filter, unmatch_filter_arg, unmatch_next_match, unmatch_next_unmatch = struct.unpack("<BHHH", f.read(7))

    if match_is_terminal:
        return False, None
    if match_next_unmatch == unmatch_offset:
        f.seek(match_next_match * 8)
        terminal, result = struct.unpack("<BB", f.read(2))
        return True, {0: 'allow', 1: 'deny'}[result & 1]

    return False, None


def offset_is_terminal(f, offset):
    f.seek(offset * 8)
    return ord(f.read(1)) == 1


def get_terminal_result(f, offset):
    f.seek(offset * 8)
    is_terminal = f.read(1)
    f.read(1) # padding
    result = ord(f.read(1))
    resultstr = {0 : 'allow', 1 : 'deny'}[result & 1]
    return resultstr


result_list = []
filter_list = []
def parse_filter(f, offset):
    global result_list
    global filter_list
    f.seek(offset * 8)

    is_terminal = ord(f.read(1)) == 1
    if is_terminal:
        return get_terminal_result(f, offset)
    else:
        fil, filter_arg, match, unmatch = struct.unpack("<BHHH", f.read(7))
        if (fil, filter_arg, match, unmatch) in filter_list:
            return None
        filter_list.append((fil, filter_arg, match, unmatch))
        if fil in filters.keys():
            if fil == 0x1f:
                return None
            if filters[fil]["name"]:
                resultstr = "%s %s" %  (filters[fil]["name"], filters[fil]["arg_process_fn"](f, filter_arg))
            else:
                resultstr = "0x%x arg 0x%x" % (fil, filter_arg)
        else:
            resultstr = "0x%x arg 0x%x" % (fil, filter_arg)
        if offset_is_terminal(f, match):
            result_list.append((parse_filter(f, match), resultstr))
            parse_filter(f, unmatch)
        else:
            result_list.append(('require-all', resultstr))
            parse_filter(f, match)
            parse_filter(f, unmatch)
            result_list.append(('require-all', 'stop'))

    return resultstr


def usage():
    print >> sys.stderr, "Usage: %s binary_sandbox_file operations_file output_file" % (sys.argv[0])


def format_result_list(sb_op):
    global result_list

    allow_list = []
    deny_list = []
    require_all_depth = 0
    require_all_allow_list = []
    require_all_deny_list = []
    require_all_tmp_list = []
    for type, filter in result_list:
        if filter == 'single':
            return '(%s %s)\n' % (type, sb_op)
        if type == 'allow':
            if require_all_depth > 0:
                require_all_allow_list.extend(require_all_tmp_list)
                require_all_tmp_list = []
                require_all_allow_list.append(filter)
            else:
                allow_list.append(filter)
        if type == 'deny':
            if require_all_depth > 0:
                require_all_deny_list.extend(require_all_tmp_list)
                require_all_tmp_list = []
                require_all_deny_list.append(filter)
            else:
                deny_list.append(filter)
        if type == 'require-all':
            if filter == 'stop':
                require_all_depth -= 1
                continue
            if require_all_depth == 0:
                require_all_tmp_list.append(filter)
            require_all_depth += 1

    resultstr = ""
    if allow_list or require_all_allow_list:
        resultstr += "(allow %s\n" % sb_op
        for item in allow_list:
            resultstr += "  (%s)\n" % item
        if require_all_allow_list:
            resultstr += "  (require-all\n"
            for item in require_all_allow_list:
                resultstr += "    (%s)\n" % item
            resultstr += "  )\n"
        resultstr += ")\n"
    if deny_list or require_all_deny_list:
        resultstr += "(deny %s\n" % sb_op
        for item in deny_list:
            resultstr += "  (%s)\n" % item
        if require_all_deny_list:
            resultstr += "  (require-all\n"
            for item in require_all_deny_list:
                resultstr += "    (%s)\n" % item
            resultstr += "  )\n"
        resultstr += ")\n"

    return resultstr


def main():
    if len(sys.argv) != 4:
        usage()
        sys.exit(1)

    # Read sandbox operations.
    sb_ops = [l.strip() for l in open(sys.argv[2])]
    num_sb_ops = len(sb_ops)
    print "num_sb_ops:", num_sb_ops

    f = open(sys.argv[1], "rb")
    out_f = open(sys.argv[3], "wt")

    header = struct.unpack("<H", f.read(2))[0]

    re_table_offset = struct.unpack("<H", f.read(2))[0]
    re_table_count = struct.unpack("<H", f.read(2))[0]
    print "header: 0x%x" % (header)
    print "re_table_offset: 0x%x" % re_table_offset
    print "re_table_count: 0x%x" % re_table_count

    print "\n\nregular expressions:\n"
    global regex_list
    if re_table_count > 0:
        f.seek(re_table_offset * 8)
        re_offsets_table = struct.unpack("<%dH" % re_table_count, f.read(2 * re_table_count))
        re_table = []
        for offset in re_offsets_table:
            f.seek(offset * 8)
            re_length = struct.unpack("<I", f.read(4))[0]
            re = struct.unpack("<%dB" % re_length, f.read(re_length))
            print "    total_re_length: 0x%x" % re_length
            print "    re: [", ", ".join([hex(i) for i in re]), "]"
            regex_list.append(parse_regex(re))
    print regex_list

    f.seek(6)
    op_table = struct.unpack("<%dH" % num_sb_ops, f.read(2 * num_sb_ops))
    #print "operations: [", ", ".join([hex(i) for i in op_table]), "]"

    #global result_list
    #global filter_list
    out_f.write("(version 1)\n")
    #for i, op in enumerate(op_table):
    #    result_list = []
    #    filter_list = []
    #    if offset_is_terminal(f, op):
    #        result_list = [ (get_terminal_result(f, op), 'single') ]
    #    else:
    #        parse_filter(f, op)
    #    out_f.write(format_result_list(sb_ops[i]))

    # Read sandbox operations.
    operation_nodes = operation_node.build_operation_nodes(f, num_sb_ops)
    for n in operation_nodes:
        n.convert_filter(convert_filter_callback, f)

    # Extract node for 'default' operation (index 0).
    default_node = operation_node.find_operation_node_by_offset(operation_nodes, op_table[0])
    out_f.write("(%s default)\n" % (default_node.terminal))

    # For each operation expand operation node.
    for idx in range(1, len(op_table)):
        offset = op_table[idx]
        operation = sb_ops[idx]
        node = operation_node.find_operation_node_by_offset(operation_nodes, offset)
        if not node:
            print "operation %s (index %d) has no operation node" % (operation, idx)
            continue
        g = operation_node.build_operation_node_graph(node)
        if g:
            rg = operation_node.reduce_operation_node_graph(g)
            rg.print_vertices_with_operation(operation, out_f)
        else:
            if node.terminal:
                if node.terminal.type != default_node.terminal.type:
                    out_f.write("(%s %s)\n" % (node.terminal, operation))

    f.close()
    out_f.close()


if __name__ == "__main__":
    sys.exit(main())
