# Asp

This is the most basic (lowest level) of comparison because we are starting
with ASP, which will be the underlying logic (for a solve) to run any comparison.
You will need clingo to run this example, which you can [install to your system](https://potassco.org/doc/start/)
or use a container (my preference).

```bash
$ docker run -v $PWD:/code -it ghcr.io/autamus/clingo bash
```
```bash
cd /code
root@60c93ee1a2bf:/code# clingo --out-ifs=\\n is-compatible.lp 
```
```bash
clingo version 5.5.1
Reading from is-compatible.lp
Solving...
Answer: 1
is_a("A")
is_b("B")
is_different("A","B")
added_node("A","B","func","goodbye_world")
removed_node("A","B","func","adios_world")
changed_node_value("A","B","id4","id4","default","Vanessa","Squidward")
changed_node_value("A","B","id5","id5","size",16,14)
changed_node_value("A","B","id7","id7","default","Hello","Helloooo")
SATISFIABLE

Models       : 1
Calls        : 1
Time         : 0.015s (Solving: 0.00s 1st Model: 0.00s Unsat: 0.00s)
CPU Time     : 0.015s
```

In the above, from very basic (general) facts we can see how the graph changed. 
E.g., either something was entirely removed or added, or it was present in both
but the value changed! The reason this is powerful is because it's a very simple
design that (hopefully) can be extended to any kind of graph with relationships
and attributes. And any domain (ABI, software, etc.) can plug in their specific
set of node types and relationships to derive this change set.

- [Notes on ASP w.r.t Graphs](https://www.cs.cmu.edu/~cmartens/asp-notes.pdf)
