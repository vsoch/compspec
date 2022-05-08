"""
A Corpus object is used to extract Dwarf and ELF symbols from a library.
We exclude most of the Dwarf Information Entries to expose a reduced set.
Entries can be added as they are needed.
"""

import sys
import os
import elftools
import elftools.elf.gnuversions as gnuversions
from elftools.elf.descriptions import (
    describe_symbol_type,
    describe_symbol_bind,
    describe_symbol_visibility,
    describe_symbol_shndx,
)
from elftools.elf.elffile import ELFFile


class CorpusReader(ELFFile):
    """
    A CorpusReader wraps an elffile.

    This allows us to easily open/close and keep the stream open while we are
    interacting with content. We close the file handle on any exit.
    """

    def __init__(self, filename):
        self.fd = open(filename, "rb")
        self.filename = filename
        self.type_lookup = {}
        try:
            self.elffile = ELFFile(self.fd)
        except Exception:
            sys.exit("%s is not an ELF file." % filename)

        # Cannot continue without dwarf info
        if not self.elffile.has_dwarf_info():
            sys.exit("%s is missing DWARF info." % self.filename)
        self.get_version_lookup()
        self.get_shndx_sections()

    def __str__(self):
        return "[CorpusReader:%s]" % self.filename

    def __repr__(self):
        return str(self)

    @property
    def header(self):
        return dict(self.elffile.header)

    def __exit__(self):
        self.fd.close()

    def get_architecture(self):
        return self.elffile.header.get("e_machine")

    def get_elf_class(self):
        return self.elffile.elfclass

    def get_machine_arch(self):
        return self.elffile.get_machine_arch()

    def get_version_lookup(self):
        """Get versioning used (GNU or Solaris)
        https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py#L915
        """
        lookup = dict()
        types = {
            gnuversions.GNUVerSymSection: "versym",
            gnuversions.GNUVerDefSection: "verdef",
            gnuversions.GNUVerNeedSection: "verneed",
            elftools.elf.dynamic.DynamicSection: "type",
        }

        for section in self.elffile.iter_sections():
            if type(section) in types:
                identifier = types[type(section)]
                if identifier == "type":
                    for tag in section.iter_tags():
                        if tag["d_tag"] == "DT_VERSYM":
                            lookup["type"] = "GNU"
                else:
                    lookup[identifier] = section

        # If we don't have a type but we have verneed or verdef, it's solaris
        if not lookup.get("type") and (lookup.get("verneed") or lookup.get("verdef")):
            lookup["type"] = "Solaris"
        self._versions = lookup

    def get_shndx_sections(self):
        """
        Get section indices.

        We want a mapping from a symbol table index to a corresponding
        section object. The SymbolTableIndexSection was added in pyelftools 0.27.
        """
        self._shndx_sections = {
            x.symboltable: x
            for x in self.elffile.iter_sections()
            if isinstance(x, elftools.elf.sections.SymbolTableIndexSection)
        }

    def get_symbols(self):
        symbols = {}

        # We want .symtab and .dynsym
        tables = [
            (idx, s)
            for idx, s in enumerate(self.elffile.iter_sections())
            if isinstance(s, elftools.elf.sections.SymbolTableSection)
        ]

        for idx, section in tables:
            # Symbol table has no entries if this is zero
            # section.num_symbols() shows count, section.name is name
            if section["sh_entsize"] == 0:
                continue

            # We need the index of the symbol to look up versions
            for sym_idx, symbol in enumerate(section.iter_symbols()):

                # Version info is from the versym / verneed / verdef sections.
                version_info = self._get_symbol_version(section, sym_idx, symbol)

                # Symbol Type
                symbol_type = describe_symbol_type(symbol["st_info"]["type"])

                # Symbol Binding
                binding = describe_symbol_bind(symbol["st_info"]["bind"])

                # Symbol Visibility
                visibility = describe_symbol_visibility(
                    symbol["st_other"]["visibility"]
                )
                defined = describe_symbol_shndx(
                    self._get_symbol_shndx(symbol, sym_idx, idx)
                ).strip()

                # We aren't considering st_value, which could be many things
                # https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblj/index.html#chapter6-35166
                symbols[symbol.name] = {
                    "version_info": version_info,
                    "type": symbol_type,
                    "binding": binding,
                    "visibility": visibility,
                    "defined": defined,
                }

        return symbols

    def _get_symbol_version(self, section, sym_idx, symbol):
        """
        Given a section, symbol index, and symbol, return version info.

        https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py#L400
        """
        version_info = ""

        # I'm not sure why this would be empty
        if not self._versions:
            return version_info

        # readelf doesn't display version info for Solaris versioning
        if section["sh_type"] == "SHT_DYNSYM" and self._versions["type"] == "GNU":
            version = self._symbol_version(sym_idx)
            if version["name"] != symbol.name and version["index"] not in (
                "VER_NDX_LOCAL",
                "VER_NDX_GLOBAL",
            ):

                # This is an external symbol
                if version["filename"]:
                    version_info = "@%(name)s (%(index)i)" % version

                # This is an internal symbol
                elif version["hidden"]:
                    version_info = "@%(name)s" % version
                else:
                    version_info = "@@%(name)s" % version
        return version_info

    def _symbol_version(self, idx):
        """We can get version information for a symbol based on it's index
        https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py#L942
        """
        symbol_version = dict.fromkeys(("index", "name", "filename", "hidden"))

        # No version information available
        if (
            not self._versions.get("versym")
            or idx >= self._versions.get("versym").num_symbols()
        ):
            return None

        symbol = self._versions["versym"].get_symbol(idx)
        index = symbol.entry["ndx"]
        if index not in ("VER_NDX_LOCAL", "VER_NDX_GLOBAL"):
            index = int(index)

            # GNU versioning means highest bit is used to store symbol visibility
            if self._versions["type"] == "GNU":
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version["hidden"] = True

            if (
                self._versions.get("verdef")
                and index <= self._versions["verdef"].num_versions()
            ):
                _, verdaux_iter = self._versions["verdef"].get_version(index)
                symbol_version["name"] = next(verdaux_iter).name
            else:
                verneed, vernaux = self._versions["verneed"].get_version(index)
                symbol_version["name"] = vernaux.name
                symbol_version["filename"] = verneed.name

        symbol_version["index"] = index
        return symbol_version

    def _get_symbol_shndx(self, symbol, symbol_index, symtab_index):
        """Every symbol table entry is defined in relation to some section.
        The st_shndx of a symbol holds the relevant section header table index.
        https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py#L994
        """
        if symbol["st_shndx"] != elftools.elf.constants.SHN_INDICES.SHN_XINDEX:
            return symbol["st_shndx"]

        # Check for or lazily construct index section mapping (symbol table
        # index -> corresponding symbol table index section object)
        if self._shndx_sections is None:
            self._shndx_sections = {
                sec.symboltable: sec
                for sec in self.elffile.iter_sections()
                if isinstance(sec, et.sections.SymbolTableIndexSection)
            }
        return self._shndx_sections[symtab_index].get_section_index(symbol_index)

    def get_dynamic_tags(self):
        """
        Get the dyamic tags in the ELF file.
        """
        tags = {}
        for section in self.elffile.iter_sections():
            if not isinstance(section, elftools.elf.dynamic.DynamicSection):
                continue

            # We are interested in architecture, soname, and needed
            def add_tag(section, tag):
                if section not in tags:
                    tags[section] = []
                tags[section].append(tag)

            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    add_tag("needed", tag.needed)
                elif tag.entry.d_tag == "DT_RPATH":
                    add_tag("rpath", tag.rpath)
                elif tag.entry.d_tag == "DT_RUNPATH":
                    add_tag("runpath", tag.runpath)
                elif tag.entry.d_tag == "DT_SONAME":
                    tags["soname"] = tag.soname

            return tags

    @property
    def location_lists(self):
        dwarfinfo = self.elffile.get_dwarf_info()
        return dwarfinfo.location_lists()

    def iter_dwarf_information_entries(self):
        """
        Yield a flattened list of DIEs
        """
        dwarfinfo = self.elffile.get_dwarf_info()

        # A CU is a Compilation Unit
        for cu in dwarfinfo.iter_CUs():

            # A DIE is a dwarf information entry
            for die in cu.iter_DIEs():
                yield die

    def _get_type_lookup(self):
        """
        Parse entries once to generate a type lookup
        """
        if self.type_lookup:
            return self.type_lookup
        dwarfinfo = self.elffile.get_dwarf_info()

        # Parse all dies recursively
        def parse_die_types(die):
            self.type_lookup[die.offset] = die
            for child in die.iter_children():
                parse_die_types(child)

        for cu in dwarfinfo.iter_CUs():
            # scan the whole die tree for DW_TAG_base_type and DW_TAG_typedef
            for die in cu.iter_DIEs():
                parse_die_types(die)
        return self.type_lookup


class Corpus:
    """
    Generate an ABi corpus.

    A Corpus is an ELF file header combined with complete elf symbols,
    variables, and nested Dwarf Information Entries
    """

    def __init__(self, filename):
        filename = os.path.abspath(filename)
        if not os.path.exists(filename):
            sys.exit("%s does not exist." % filename)

        self.elfheader = {}
        self.elfsymbols = {}
        self.path = filename
        self.dynamic_tags = {}
        self.architecture = None
        self._soname = None
        self._location_lists = None
        self.read_elf_corpus()

    def __str__(self):
        return "[Corpus:%s]" % self.path

    def __repr__(self):
        return str(self)

    def exists(self):
        return self.path is not None and os.path.exists(self.path)

    @property
    def basename(self):
        return os.path.basename(self.path)

    @property
    def soname(self):
        return self.dynamic_tags.get("soname")

    @property
    def needed(self):
        return self.dynamic_tags.get("needed", [])

    @property
    def runpath(self):
        return self.dynamic_tags.get("runpath")

    @property
    def rpath(self):
        return self.dynamic_tags.get("rpath")

    @property
    def location_lists(self):
        if self._location_lists:
            return self._location_lists
        reader = CorpusReader(self.path)
        self._location_lists = reader.location_lists
        return self._location_lists

    def get_type_lookup(self):
        """
        Generate a type lookup on demand.
        """
        reader = CorpusReader(self.path)
        return reader._get_type_lookup()

    def iter_dwarf_information_entries(self):
        """
        Return flattened list of DIEs (Dwarf Information Entrys)
        """
        reader = CorpusReader(self.path)
        for entry in reader.iter_dwarf_information_entries():
            yield entry

    def read_elf_corpus(self):
        """
        Read the entire elf corpus, including dynamic and other sections.
        """
        reader = CorpusReader(self.path)

        # Read in the header section as part of the corpus
        self.elfheader = reader.header

        # Read in dynamic tags, and symbols
        self.dynamic_tags = reader.get_dynamic_tags()
        self.architecture = reader.get_architecture()
        self.machine_arch = reader.get_machine_arch()
        self.elfclass = reader.get_elf_class()
        self.elfsymbols = reader.get_symbols()
