import clingo
import os
import json
import sys

here = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, here)
from corpus import Corpus
from die import DieParser

clingo_cffi = hasattr(clingo.Symbol, "_rep")


def _id(thing):
    """
    Quote string if needed for it to be a valid identifier.
    """
    if isinstance(thing, AspFunction):
        return thing
    elif isinstance(thing, int):
        return str(thing)
    # boolean and other casese
    return '"%s"' % str(thing)


def argify(arg):
    """
    Convert an argument into a clingo one.
    """
    if isinstance(arg, bool):
        return clingo.String(str(arg))
    elif isinstance(arg, int):
        return clingo.Number(arg)
    return clingo.String(str(arg))


class AspFunction:
    """
    An asp function
    """

    def __init__(self, name, args=None):
        self.name = name
        self.args = [] if args is None else args

    def __call__(self, *args):
        return AspFunction(self.name, args)

    def symbol(self, positive=True):
        return clingo.Function(
            self.name, [argify(arg) for arg in self.args], positive=positive
        )

    def __getitem___(self, *args):
        self.args[:] = args
        return self

    def __str__(self):
        return "%s(%s)" % (self.name, ", ".join(str(_id(arg)) for arg in self.args))

    def __repr__(self):
        return str(self)


class AspFunctionBuilder(object):
    def __getattr__(self, name):
        return AspFunction(name)


fn = AspFunctionBuilder()


class Result:
    """
    Result of an ASP solve.
    """

    def __init__(self, asp=None):
        self.asp = asp
        self.satisfiable = None
        self.optimal = None
        self.warnings = None
        self.nmodels = 0

        # specs ordered by optimization level
        self.answers = []
        self.cores = []


class PyclingoDriver:
    def __init__(self, cores=True, out=None):
        """
        Driver for the Python clingo interface.
        Arguments:
            cores (bool): whether to generate unsatisfiable cores for better
                error reporting.
            out (file-like): optional stream to write a text-based ASP program
                for debugging or verification.
        """
        if out:
            self.out = out
        else:
            self.devnull()
        self.cores = cores

    def devnull(self):
        self.f = open(os.devnull, "w")
        self.out = self.f

    def __exit__(self):
        self.f.close()

    def title(self, name, char):
        self.out.write("\n")
        self.out.write("%" + (char * 76))
        self.out.write("\n")
        self.out.write("%% %s\n" % name)
        self.out.write("%" + (char * 76))
        self.out.write("\n")

    def h1(self, name):
        self.title(name, "=")

    def h2(self, name):
        self.title(name, "-")

    def newline(self):
        self.out.write("\n")

    def fact(self, head):
        """
        ASP fact (a rule without a body).
        """
        symbol = head.symbol() if hasattr(head, "symbol") else head
        self.out.write("%s.\n" % str(symbol))
        atom = self.backend.add_atom(symbol)
        self.backend.add_rule([atom], [], choice=self.cores)
        if self.cores:
            self.assumptions.append(atom)

    def solve(
        self,
        setup,
        nmodels=0,
        stats=False,
        logic_programs=None,
        facts_only=False,
    ):
        """
        Run the solver for a model and some number of logic programs
        """
        # logic programs to give to the solver
        logic_programs = logic_programs or []
        if not isinstance(logic_programs, list):
            logic_programs = [logic_programs]

        # Initialize the control object for the solver
        self.control = clingo.Control()
        self.control.configuration.solve.models = nmodels
        self.control.configuration.asp.trans_ext = "all"
        self.control.configuration.asp.eq = "5"
        self.control.configuration.configuration = "tweety"
        self.control.configuration.solve.parallel_mode = "2"
        self.control.configuration.solver.opt_strategy = "usc,one"

        # set up the problem -- this generates facts and rules
        self.assumptions = []
        with self.control.backend() as backend:
            self.backend = backend
            setup.setup(self)

        # If we only want to generate facts, cut out early
        if facts_only:
            return

        # read in provided logic programs
        for logic_program in logic_programs:
            self.control.load(logic_program)

        # Grounding is the first step in the solve -- it turns our facts
        # and first-order logic rules into propositional logic.
        self.control.ground([("base", [])])

        # With a grounded program, we can run the solve.
        result = Result()
        models = []  # stable models if things go well
        cores = []  # unsatisfiable cores if they do not

        def on_model(model):
            models.append((model.cost, model.symbols(shown=True, terms=True)))

        # Won't work after this, need to write files
        solve_kwargs = {
            "assumptions": self.assumptions,
            "on_model": on_model,
            "on_core": cores.append,
        }
        if clingo_cffi:
            solve_kwargs["on_unsat"] = cores.append
        solve_result = self.control.solve(**solve_kwargs)

        # once done, construct the solve result
        result.satisfiable = solve_result.satisfiable

        def stringify(x):
            if clingo_cffi:
                # Clingo w/ CFFI will throw an exception on failure
                try:
                    return x.string
                except RuntimeError:
                    return str(x)
            else:
                return x.string or str(x)

        if result.satisfiable:
            min_cost, best_model = min(models)
            result.answers = {}
            for sym in best_model:
                if sym.name not in result.answers:
                    result.answers[sym.name] = []
                result.answers[sym.name].append([stringify(a) for a in sym.arguments])

        elif cores:
            symbols = dict((a.literal, a.symbol) for a in self.control.symbolic_atoms)
            for core in cores:
                core_symbols = []
                for atom in core:
                    sym = symbols[atom]
                    core_symbols.append(sym)
                result.cores.append(core_symbols)

        if stats:
            print("Statistics:")
            logger.info(self.control.statistics)
        return result


class Diffspec:
    """
    Solver class to orchestrate a diff between two things.
    """

    def __init__(self, lib1, lib2, out=None):
        """
        Create a driver to run a compatibility model test for two libraries.
        """
        # The driver will generate facts rules to generate an ASP program.
        self.driver = PyclingoDriver(out=out)
        self.setup = FactGenerator(lib1, lib2)

    def setup(self, driver):
        """
        Setup to prepare for the solve.
        """
        self.gen = driver

    def solve(self, logic_programs, detail=True):
        """
        Run the solve
        """
        result = self.driver.solve(self.setup, logic_programs=logic_programs)
        return result.answers


class FactGenerator:
    """
    The FactGenerator takes two libraries and generates facts for the solver.
    We do this by loading them as a corpus.
    """

    def __init__(self, lib1, lib2):
        self.lib1 = lib1
        self.lib2 = lib2
        self.A = Corpus(lib1)
        self.B = Corpus(lib2)

    def setup(self, driver):
        """
        Setup data for two libraries to prepare for the solve.
        """
        self.gen = driver
        self.gen.h1("Library Facts")

        # Set the library namespace
        self.gen.fact(fn.is_a("A"))
        self.gen.fact(fn.is_b("B"))
        self.add_library(self.A, self.lib1, "A")
        self.add_library(self.B, self.lib2, "B")

    def add_library(self, lib, libpath, namespace):
        """
        Generate facts for a namespaced corpus
        """
        self.gen.h2("Library: %s" % lib.basename)

        # Die parser to yield information, provided with types
        parser = DieParser(lib)

        for entrytype, entry in parser.iter_facts():
            if entrytype == "relation":
                self.gen.fact(fn.relation(namespace, *entry))
            elif entrytype == "node":
                self.gen.fact(fn.node(namespace, *entry))


class Runner:
    """
    Runner to run a compspec comparison, meaning we:
    1. extract facts (corpora) from each library
    2. write facts into domain specific compspec model.
    3. run the solver and report results.
    """

    def __init__(self):
        self.lp = os.path.join(here, "is-compatible.lp")
        self.records = []

    def diff(self, lib1, lib2, detail=False, out=None):
        """
        Run the diff to compare two entries.
        """
        # We must have the stability program!
        if not os.path.exists(self.lp):
            logger.exit("Logic program %s does not exist!" % self.lp)

        # Setup and run the stability solver
        setup = Diffspec(lib1, lib2, out=out)
        return setup.solve(logic_programs=self.lp)


def main():
    # Hard coded examples, for now
    lib1 = os.path.join(here, "libmath.v1.so")
    lib2 = os.path.join(here, "libmath.v2.so")

    for lib in lib1, lib2:
        if not os.path.exists(lib):
            sys.exit(f"{lib} does not exist.")

    # Run the diff
    runner = Runner()
    result = runner.diff(lib1, lib2)
    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()
