from elftools.common.py3compat import bytes2str
from elftools.dwarf.descriptions import (
    describe_form_class,
    describe_attr_value,
    set_global_machine_arch,
    describe_reg_name,
)
from elftools.dwarf.locationlists import LocationParser, LocationEntry, LocationExpr
from elftools.dwarf.dwarf_expr import DWARFExprParser, DW_OP_name2opcode

import os
import sys

here = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, here)
from location import get_register_from_expr, get_dwarf_from_expr


"""
% Library A has functions  hello world and goodbye world
% A node belongs to a namespace (A) has a unique id within that space idx) a type and name
node("A", "id0", "func", "goodbye_world").
node("A", "id1", "func", "hello_world").

% Library A has these flattened attributes attributes
node("A", "id3", "parameter", "name").
node("A", "id6", "parameter", "greeting").
node("A", "id4", "default", "Vanessa").
node("A", "id5", "size", 16).
node("A", "id7", "default", "Hello").

% function hello_world has parameter "name"
% and parameter name has default Vanessa
relation("A", "id1", "has", "id3").
relation("A", "id3", "has", "id4").
relation("A", "id3", "has", "id5").
relation("A", "id1", "has", "id6").
relation("A", "id6", "has", "id7").

% Library B only has function hello world (with a different default)
% Note that the identifier namespace is internal to B (e.g., A.id0 vs B.id0 are different)
node("B", "id0", "func", "adios_world").
node("B", "id1", "func", "hello_world").

% Functions have these attributes. We will change the default of name for hello_world
% We change the default to squidward here
node("B", "id3", "parameter", "name").
node("B", "id4", "default", "Squidward").
node("B", "id5", "size", 14).
node("B", "id6", "parameter", "greeting").
node("B", "id7", "default", "Helloooo").


% function hello_world has parameter name
% parameter name has default squidward
relation("B", "id1", "has", "id3").
relation("B", "id3", "has", "id4").
relation("B", "id3", "has", "id5").
relation("B", "id1", "has", "id6").
relation("B", "id6", "has", "id7").
"""

# Human friendly names for general tag "types"
known_die_types = {"DW_TAG_array_type": "array"}


class Counter:
    """
    A simple counter (iterator) that will yield the next number with some prefix.
    """

    def __init__(self, prefix="id"):
        self.prefix = prefix

    def __next__(self):
        self.count += 1
        return "%s%s" % (self.prefix, self.count)

    def __iter__(self):
        # Actually start counting at 0
        self.count = -1
        return self


def get_counter(prefix="id"):
    counter = Counter(prefix)
    return iter(counter)


class Node:
    """
    A node in a graph.
    """

    def __init__(self, uid, name, value):
        self.uid = uid
        self.name = name
        self.value = value

    @property
    def args(self):
        return self.uid, self.name, self.value


class Graph:
    def __init__(self):

        # A counter to keep track of ids in this space
        self.count = get_counter()

        # A lookup of DIE -> identifier. An identifier can be present even
        # if the DIE has not been parsed (if derived as parent)
        self.ids = {}

        # Lookup of nodes to indicate it has been parsed!
        self.nodes = {}
        self.lookup = {}
        self.relations = {}

    def next(self):
        """
        Return next id in the counter.
        """
        return next(self.count)

    def node(self, name, value, nodeid=None):
        """
        Generate a node with a name (type) and value
        """
        if not nodeid:
            nodeid = self.next()
        return Node(nodeid, name, value)

    def generate_node(self, node):
        """
        Given a node, yield the type "node" and args
        """
        return "node", node.args

    def generate_relation(self, parent, child, relation="has"):
        """
        Generate a relation between parent and child
        relation("A", "id6", "has", "id7").
        """
        return "relation", parent, relation, child

    def gen(self, name, value, parent, nodeid=None):
        """
        Generate a node and relation in one swoop!
        A parent is required.
        """
        if not nodeid:
            nodeid = self.next()
        node = Node(nodeid, name, value)
        relation = self.generate_relation(parent, node.uid)
        return ["node", node.args], relation


class DieParser(Graph):
    """
    Helper class to parse a die (in a flat way) and return interesting attributes.
    each function should yield an iterable of facts that will be parsed into
    this ASP structure:

    node("A", "id0", "func", "goodbye_world").
    node("A", "id1", "func", "hello_world").
    """

    def __init__(self, corpus):
        self.corpus = corpus
        super().__init__()
        self.type_lookup = self.corpus.get_type_lookup()
        self._prepare_location_parser()

    def _prepare_location_parser(self):
        """
        Prepare the location parser using the dwarf info
        """
        location_lists = self.corpus.location_lists

        # Needed to decode register names in DWARF expressions.
        set_global_machine_arch(self.corpus.machine_arch)
        self.loc_parser = LocationParser(location_lists)

    def iter_facts(self):
        """
        Iterate over DIEs and yield groups of facts
        """
        for die in self.corpus.iter_dwarf_information_entries():
            if not die or not die.tag:
                continue
            for entry in self.facts(die):
                if not entry:
                    continue
                yield entry[0], entry[1]

    def generate_parent(self, die):
        """
        Generate the parent, if one exists.
        relation("A", "id6", "has", "id7").
        """
        parent = die.get_parent()
        if parent:
            if parent not in self.ids:
                self.ids[parent] = self.next()
            return self.generate_relation(self.ids[parent], self.ids[die])

    def facts(self, die):
        """
        Yield facts for a die. We keep track of ids and relationships here.
        """
        # Have we parsed it yet?
        if die in self.lookup:
            return

        # Assume we are parsing all dies
        if die not in self.ids:
            self.ids[die] = self.next()
        self.lookup[die] = self.ids[die]

        if die.tag == "DW_TAG_namespace":
            return self.parse_namespace(die)

        if die.tag == "DW_TAG_compile_unit":
            return self.parse_compile_unit(die)

        if die.tag == "DW_TAG_class_type":
            return self.parse_class_type(die)

        if die.tag == "DW_TAG_subprogram":
            return self.parse_subprogram(die)

        if die.tag == "DW_TAG_formal_parameter":
            return self.parse_formal_parameter(die)

        # If we are consistent with base type naming, we don't
        # need to associate a base type size with everything that uses it,
        # but rather just the one base type
        if die.tag == "DW_TAG_base_type":
            return self.parse_base_type(die)

        # TODO haven't seen these yet
        print(die)
        import IPython

        IPython.embed()

        if die.tag == "DW_TAG_variable":
            return self.parse_variable(die)

        if die.tag == "DW_TAG_union_type":
            return self.parse_union_type(die)

        if die.tag == "DW_TAG_enumeration_type":
            return self.parse_enumeration_type(die)

        if die.tag == "DW_TAG_array_type":
            return self.parse_array_type(die)

        if die.tag == "DW_TAG_structure_type":
            return self.parse_structure_type(die)

        if die.tag == "DW_TAG_lexical_block":
            return self.parse_die(die)

        if die.tag == "DW_TAG_member":
            return self.parse_member(die)

        if die.tag == "DW_TAG_base_type":
            return self.parse_base_type(die)

        # Legical blocks wrap other things
        if die.tag == "DW_TAG_lexical_block":
            return self.parse_children(die)

    def parse_base_type(self, die):
        """
        Parse a namespace, which is mostly a name and relationship
        """
        yield self.generate_node(self.node("basetype", get_name(die), self.ids[die]))
        yield self.generate_parent(die)
        for entry in self.gen("size", get_size(die), parent=self.ids[die]):
            yield entry

    def parse_namespace(self, die):
        """
        Parse a namespace, which is mostly a name and relationship
        """
        yield self.generate_node(self.node("namespace", get_name(die), self.ids[die]))
        yield self.generate_parent(die)

    def parse_class_type(self, die):
        """
        Parse a class.
        """
        yield self.generate_node(self.node("class", get_name(die), self.ids[die]))
        yield self.generate_parent(die)

        # Return the size of the class
        for entry in self.gen("size", get_size(die), parent=self.ids[die]):
            yield entry

    def parse_formal_parameter(self, die):
        """
        Parse a formal parameter
        """
        yield self.generate_node(self.node("parameter", get_name(die), self.ids[die]))
        yield self.generate_parent(die)
        for entry in self.gen("size", get_size(die), parent=self.ids[die]):
            yield entry
        for entry in self.gen(
            "type", self.get_underlying_type(die), parent=self.ids[die]
        ):
            yield entry
        loc = self.parse_location(die)
        if not loc:
            return
        for entry in self.gen("location", loc, parent=self.ids[die]):
            yield entry

    def parse_location(self, die):
        """
        Look to see if the DIE has DW_AT_location, and if so, parse to get registers
        """
        if "DW_AT_location" not in die.attributes:
            return
        attr = die.attributes["DW_AT_location"]
        if self.loc_parser.attribute_has_location(attr, die.cu["version"]):
            loc = self.loc_parser.parse_from_attribute(attr, die.cu["version"])

            # Attribute itself contains location information
            if isinstance(loc, LocationExpr):
                loc = get_register_from_expr(
                    loc.loc_expr, die.dwarfinfo.structs, die.cu.cu_offset
                )

                # The first entry is the register
                return self.parse_register(loc[0])

            # List is reference to .debug_loc section
            elif isinstance(loc, list):
                loc = self.get_loclist(loc, die)
                return self.parse_register(loc[0][0])

    def parse_register(self, register):
        """
        Given the first register entry, remove dwarf
        """
        # DW_OP_fbreg is signed LEB128 offset from  the DW_AT_frame_base address of the current function.
        if "DW_OP_fbreg" in register:
            return "framebase" + register.split(":")[-1].strip()
        # If we have a ( ) this is the register name
        if re.search(r"\((.*?)\)", register):
            return "%" + re.sub(
                "(\(|\))", "", re.search(r"\((.*?)\)", register).group(0)
            )
        # Still need to parse
        if register == "null":
            return None
        return register

    def parse_subprogram(self, die):
        """
        Add a function (subprogram) parsed from DWARF
        """
        # If has DW_TAG_external, we know it's external outside of this CU
        if "DW_AT_external" not in die.attributes:
            return

        yield self.generate_node(self.node("function", get_name(die), self.ids[die]))
        yield self.generate_parent(die)

        # Generate the node and the relation in one swoop
        for entry in self.gen(
            "type", self.get_underlying_type(die), parent=self.ids[die]
        ):
            yield entry

    def parse_compile_unit(self, die):
        """
        Parse a top level compile unit.
        """
        # Generate node, parent (unlikely to have one)
        yield self.generate_node(self.node("compileunit", get_name(die), self.ids[die]))
        yield self.generate_parent(die)

        # we could load low/high PC here if needed
        lang = die.attributes.get("DW_AT_language", None)
        if lang:
            die_lang = describe_attr_value(lang, die, die.offset)
            node = self.node("language", die_lang)
            yield self.generate_node(node)
            self.generate_relation(self.ids[die], node.uid)

    def get_underlying_type(self, die, pointer=False):
        """
        Given a type, parse down to the underlying type (and count pointer indirections)
        """
        if die.tag == "DW_TAG_base_type":
            if pointer:
                return "*%s" % get_name(die)
            return get_name(die)

        if "DW_AT_type" not in die.attributes:
            return "unknown"

        # Can we get the underlying type?
        type_die = self.type_lookup.get(die.attributes["DW_AT_type"].value)
        if not type_die:
            return "unknown"

        # Case 1: It's an array (and type is for elements)
        if type_die and type_die.tag in known_die_types:
            if pointer:
                return "*%s" % known_die_types[type_die.tag]
            return known_die_types[type_die.tag]

        if type_die.tag == "DW_TAG_base_type":
            if pointer:
                return "*%s" % get_name(type_die)
            return get_name(type_die)

        # Otherwise, keep digging
        elif type_die:
            while "DW_AT_type" in type_die.attributes:

                if type_die.tag == "DW_TAG_pointer_type":
                    pointer = True

                # Stop when we don't have next dies to parse
                next_die = self.type_lookup.get(type_die.attributes["DW_AT_type"].value)
                if not next_die:
                    break
                type_die = next_die

        if type_die:
            return self.get_underlying_type(type_die, pointer)
        return "unknown"

    ############################ UNDER

    def parse_call_site(self, die, parent):
        """
        Parse a call site
        """
        entry = {}

        # The abstract origin points to the function
        if "DW_AT_abstract_origin" in die.attributes:
            origin = self.type_die_lookup.get(
                die.attributes["DW_AT_abstract_origin"].value
            )
            entry.update({"name": self.get_name(origin)})

        params = []
        for child in die.iter_children():
            # TODO need better param parsing
            if child.tag == "DW_TAG_GNU_call_site_parameter":
                param = self.parse_call_site_parameter(child)
                if param:
                    params.append(param)
            else:
                raise Exception("Unknown call site parameter!:\n%s" % child)

        if entry and params:
            entry["params"] = params
            self.callsites.append(entry)

    def parse_call_site_parameter(self, die):
        """
        Given a callsite parameter, parse the dwarf expression
        """
        param = {}
        loc = self.parse_location(die)
        if loc:
            param["location"] = loc
        if "DW_AT_GNU_call_site_value" in die.attributes:
            expr_parser = DWARFExprParser(die.dwarfinfo.structs)
            expr = die.attributes["DW_AT_GNU_call_site_value"].value
            # print(get_dwarf_from_expr(expr, die.dwarfinfo.structs, cu_offset=die.cu.cu_offset))
        return param

    # TAGs to parse
    def parse_lexical_block(self, die, code=None):
        """
        Lexical blocks typically have variable children?
        """
        for child in die.iter_children():
            if child.tag == "DW_TAG_variable":
                self.parse_variable(child)

            # We found a loop
            elif child.tag == "DW_AT_lexical_block":
                if code == die.abbrev_code:
                    return
                return self.parse_lexical_block(die)

    def parse_structure_type(self, die):
        """
        Parse a structure type.
        """
        # The size here includes padding
        entry = {
            "name": self.get_name(die),
            "size": self.get_size(die),
            "class": "Struct",
        }

        # Parse children (members of the union)
        fields = []
        for child in die.iter_children():
            fields.append(self.parse_member(child))

        if fields:
            entry["fields"] = fields
        return entry

    def parse_union_type(self, die):
        """
        Parse a union type.
        """
        # The size here includes padding
        entry = {
            "name": self.get_name(die),
            "size": self.get_size(die),
            "class": "Union",
        }

        # TODO An incomplete union won't have byte size attribute and will have DW_AT_declaration attribute.
        # page https://dwarfstd.org/doc/DWARF4.pdf 85

        # Parse children (members of the union)
        fields = []
        for child in die.iter_children():
            fields.append(self.parse_member(child))

        if fields:
            entry["fields"] = fields
        return entry

    def parse_location(self, die):
        """
        Look to see if the DIE has DW_AT_location, and if so, parse to get
        registers. The loc_parser is called by elf.py (once) and addde
        to the corpus here when it is parsing DIEs.
        """
        if "DW_AT_location" not in die.attributes:
            return
        attr = die.attributes["DW_AT_location"]
        if self.loc_parser.attribute_has_location(attr, die.cu["version"]):
            loc = self.loc_parser.parse_from_attribute(attr, die.cu["version"])

            # Attribute itself contains location information
            if isinstance(loc, LocationExpr):
                loc = get_register_from_expr(
                    loc.loc_expr, die.dwarfinfo.structs, die.cu.cu_offset
                )
                # The first entry is the register
                return self.parse_register(loc[0])

            # List is reference to .debug_loc section
            elif isinstance(loc, list):
                loc = self.get_loclist(loc, die)
                return self.parse_register(loc[0][0])

    def parse_register(self, register):
        """
        Given the first register entry, remove dwarf
        """
        # DW_OP_fbreg is signed LEB128 offset from  the DW_AT_frame_base address of the current function.
        if "DW_OP_fbreg" in register:
            return "framebase" + register.split(":")[-1].strip()
        # If we have a ( ) this is the register name
        if re.search(r"\((.*?)\)", register):
            return "%" + re.sub(
                "(\(|\))", "", re.search(r"\((.*?)\)", register).group(0)
            )
        # Still need to parse
        if register == "null":
            return None
        return register

    def get_loclist(self, loclist, die):
        """
        Get the parsed location list

        # TODO double check that we can use the cu/dwarfinfo off of the die instance
        """
        registers = []
        for loc_entity in loclist:
            if isinstance(loc_entity, LocationEntry):
                registers.append(
                    get_register_from_expr(
                        loc_entity.loc_expr, die.dwarfinfo.structs, die.cu.cu_offset
                    )
                )
            else:
                registers.append(str(loc_entity))
        return registers

    def parse_member(self, die):
        """
        Parse a member, typically belonging to a union (something else?)
        """
        entry = {"name": self.get_name(die)}
        underlying_type = self.parse_underlying_type(die)
        if underlying_type:
            entry.update(underlying_type)
        return entry

    def parse_array_type(self, die):
        """
        Get an entry for an array.
        """
        # TODO what should I do if there is DW_AT_sibling? Use it for something instead?
        entry = {"class": "Array", "name": self.get_name(die)}

        # Get the type of the members
        member_type = self.parse_underlying_type(die)

        # TODO we might want to handle order
        # This can be DW_AT_col_order or DW_AT_row_order, and if not present
        # We use the language default
        if "DW_AT_ordering" in die.attributes:
            entry["order"] = die.attributes["DW_AT_ordering"].value

        # Case 1: the each member of the array uses a non-traditional storage
        member_size = self._find_nontraditional_size(die)

        # Children are the members of the array
        entries = []
        children = list(die.iter_children())

        size = 0
        total_size = 0
        total_count = 0
        for child in children:
            member = None

            # Each array dimension is DW_TAG_subrange_type or DW_TAG_enumeration_type
            if child.tag == "DW_TAG_subrange_type":
                member = self.parse_subrange_type(child)
            elif child.tag == "DW_TAG_enumeration_type":
                member = self.parse_enumeration_type(child)
            else:
                l.warning("Unknown array member tag %s" % child.tag)

            if not member:
                continue

            count = member.get("count", 0)
            size = member.get("size") or member_size
            if count != "unknown" and size:
                total_size += count * size
            entries.append(member)

        entry["size"] = total_size
        entry["count"] = total_count
        return entry

    def parse_enumeration_type(self, die):
        entry = {
            "name": self.get_name(die),
            "size": self.get_size(die),
            "class": "Scalar",
        }
        underlying_type = self.parse_underlying_type(die)
        entry.update(underlying_type)

        fields = []
        for child in die.iter_children():
            field = {
                "name": self.get_name(child),
                "value": child.attributes["DW_AT_const_value"].value,
            }
            fields.append(field)
        if fields:
            entry["fields"] = fields
        return entry

    def parse_subrange_type(self, die):
        """
        Parse a subrange type
        """
        entry = {"name": self.get_name(die)}
        entry.update(self.parse_underlying_type(die))

        # If we have DW_AT_count, this is the length of the subrange
        if "DW_AT_count" in die.attributes:
            entry["count"] = die.attributes["DW_AT_count"].value

        # If we have both upper and lower bound
        elif (
            "DW_AT_upper_bound" in die.attributes
            and "DW_AT_lower_bound" in die.attributes
        ):
            entry["count"] = (
                die.attributes["DW_AT_upper_bound"].value
                - die.attributes["DW_AT_lower_bound"].value
            )

        # If the lower bound value is missing, the value is assumed to be a language-dependent default constant.
        elif "DW_AT_upper_bound" in die.attributes:

            # TODO need to get language in here to derive
            # TODO: size seems one off.
            # The default lower bound is 0 for C, C++, D, Java, Objective C, Objective C++, Python, and UPC.
            # The default lower bound is 1 for Ada, COBOL, Fortran, Modula-2, Pascal and PL/I.
            lower_bound = 0
            entry["count"] = die.attributes["DW_AT_upper_bound"].value - lower_bound

        # If the upper bound and count are missing, then the upper bound value is unknown.
        else:
            entry["count"] = "unknown"
        return entry

    def parse_pointer(self, die):
        """
        Parse a pointer.
        """
        if "DW_AT_type" not in die.attributes:
            l.debug("Cannot parse pointer %s without a type." % die)
            return

        entry = {"class": "Pointer", "size": self.get_size(die)}

        # We already have one pointer indirection
        entry["underlying_type"] = self.parse_underlying_type(die, 1)
        return entry

    def parse_sibling(self, die):
        """
        Try parsing a sibling.
        """
        sibling = self.type_die_lookup.get(die.attributes["DW_AT_sibling"].value)
        return self.parse_underlying_type(sibling)

    def add_class(self, die):
        """
        Given a type, add the class
        """
        if die.tag == "DW_TAG_base_type":
            return "Scalar"
        if die.tag == "DW_TAG_structure_type":
            return "Struct"
        if die.tag == "DW_TAG_array_type":
            return "Array"
        return "Unknown"

    def _find_nontraditional_size(self, die):
        """
        Tag DIEs can have attributes to indicate their members use a nontraditional
        amount of storage, in which case we find this. Otherwise, look at member size.
        """
        if "DW_AT_byte_stride" in die.attributes:
            return die.attributes["DW_AT_byte_stride"].value
        if "DW_AT_bit_stride" in die.attributes:
            return die.attributes["DW_AT_bit_stride"].value * 8


# Helper functions to parse a die
def get_name(die):
    """
    A common function to get the name for a die
    """
    name = "unknown"
    if "DW_AT_linkage_name" in die.attributes:
        return bytes2str(die.attributes["DW_AT_linkage_name"].value)
    if "DW_AT_name" in die.attributes:
        return bytes2str(die.attributes["DW_AT_name"].value)
    return name


def get_size(die):
    """
    Return size in bytes (not bits)
    """
    size = 0
    if "DW_AT_byte_size" in die.attributes:
        return die.attributes["DW_AT_byte_size"].value
    # A byte is 8 bits
    if "DW_AT_bit_size" in die.attributes:
        return die.attributes["DW_AT_bit_size"].value * 8
    if "DW_AT_data_bit_offset" in die.attributes:
        raise Exception("Found data_bit_offset in die to parse:\n%s" % die)
    return size
