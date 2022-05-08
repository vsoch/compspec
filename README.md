# Composition Specs (compspec)

Tools to assess an application binary interface (ABI) typically can output a diff, or
the result of a set of comparisons between one version of a library or another. Examples
of such tools include [libabigail](https://sourceware.org/libabigail/), and often the output
is dumped into the terminal, and in a format that is not easy to parse. This is a problem
of comparison. The problen can be simplified almost to an extreme, first for one library:

```
[library] -- extract facts --> [facts]
```

or for two libraries, for example that we want to compare:

```
[library A] -- extract facts --> [facts A]
                                           -- facts diff --> [change set] 
[library B] -- extract facts --> [facts B]
```

And more generally, we don't need to be talking about a library. The library in
the example above could be static code, version or metadata files, containers,
or binaries. Or even more simply:


```
A 
   --> A-B --> change set
B
```

In modern day tooling, if we imagine there is a continuum for understanding differences,
it might look like this:

1. Create a definition for facts (and a way to namespace them) (a composition)
2. Define a method for diff-ing two (or more) sets of facts (compspec)
3. Structure the output of the diff into a specification (diffspec)
4. Apply 1-3 to a specific domain to instantiate a compspec (examples below)
5. Create implementations that can take an input, derive and save facts, and optionally diff, and provide a humanly understandable output.

If you look at the above steps, you might guess the problem - our modern day tools
like libabigail started at step 5, and as a result the process and rules are a black box and
largely the output is "snowflake special" to libabigail and we can't easily understand,
extend, or programatically use it.

## Rationale

I want to step back and work on steps 1-4. I believe that if we can better
define a language to express changes, and not just for one domain but any domain,
this will empower creators of tools to create implementations for software that can
easily perform a diff or extraction of facts. The only thing that would need to
be decided by the implementer are the domain specific details. 

### Application Binary Interfaces

With respect to ABI, if we expect to not only develop better tools and APIs for assessing it, we need
the following:

1. To write down a list of humanly understandable checks
2. To provide a format for representing these facts (a compspec).
3. To provide a format for showing differences between these facts (a changespec).

This repository is an attempt to define such a standard for points 2 and 3, and to think
about design. If we are attempting to model complex software there is likely no way around needing
a graph design. But perhaps we can "flatten" the graph into a set of facts with associated
identifiers and then give the entire thing to a solver (as a faster solution than
manual parsing). I think using [clingo](https://potassco.org/clingo/) should work nicely.
We can also try more traditional graph methods, if clingo is not sufficient.

### Use Cases

This standard or spec should be able to support:

1. changes in version files
2. changes in software static / source code or binaries
3. changes in package manager metadata
4. changes in container metadata (or interactions)

### Prototype

To prototype this idea, we will start with a simple use case (changes in Python functions)
and use [caliper](https://github.com/vsoch/caliper) to:

1. Extract facts for a Python library of interest and represent the facts in a format that can be further parsed
2. Define a simple way to perform a diff and show the changeset between two versions of something.

I have always been interested in analyzing software - the caliper library above I made before joining
the lab, and I've been doing small analyses to study software for at least a decade. This project
is well in line with my interests (and I hope) others as well!

## Examples

## Facts

```asp
isEntity("<identifier>", "<entity-type>", "<entity-name>")
isEntity("id0", "function", "goodbye_world")
isEntity("id1", "function", "hello_world")

hasAttribute("<identifier>", "<parent-identifier>", "<attribute-name>", "<attribute-value>")
hasAttribute("id2", "id1", "parameter", "name")
hasAttribute("id3", "default", "Vanessa")
```

vs 

```asp
isEntity("id1", "function", "hello_world")
hasAttribute("id2", "id1", "parameter", "name")
hasAttribute("id3", "default", "Squidward")
```

Note that the namespace should be relevant and meaningful (e.g., a uuid is not meaningful, but
mylib.v1.develop is) but also scoped to be done within a particular comparison. There will
be default provided methods (via a solver) that know how to do the diff or comparison.
This means that for any domain, we only need to define:

- A namespace for comparison (e.g., evertying from uuid to a package-name + version + arch
- A space of entities
- For each entity, a set of attributes (and attributes are also given uuids and can have attributes up to any level of nesting)

## Changes

We'd want to say things like (for the above example)

- Function goodbye_world has been removed
- Function hello_world has a new default for "name" -> "Squidward"

And if we are general about attributes and entities, we can really do a side
by side comparison of any domain specific thing.

For more detailed examples, see:

 - [asp](asp): the simplest of examples
 - [abi](abi): writing out checks for an ABI check
 - [python](python): for python libraries 
 
**under development!** I'll likely get these written and up here in the next few days (they aren't added yet).
 
## Implementation Suggestions

- During a parsing, a namespace should be "wrapped" to some respect so the raw identifiers are not the same (or they should be removed entirely). They are there for tracing back to an original object and mapping relationsips, but (for comparison between things) we should be matching entities.
- We can likely do iterative parsing, meaning starting either on a higher level or with a piece of the thing to parse, and we can cut out early as soon as we find an incompatibility (unless there is some setting that says to parsee in completion).

## TODO

- write asp example
- looking into clingo for go
- write python example
- write abi example
- write out actual full spec
