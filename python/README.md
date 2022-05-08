# Python Changes

Now that we've seen a simple example using [asp](../asp) it might make sense
to try to extend this example to Python, and reading binary dwarf. We will
use [this repository](https://github.com/buildsi/build-abi-test-mathclient) that has two versions of a 
library to build - a math client with the same namespace  / class / functions
but parameter type changes.

## Setup

Let's clone the different versions and build them!

```bash
git clone https://github.com/buildsi/build-abi-test-mathclient
cd build-abi-test-mathclient
git fetch
```
Build version 2.0

```bash
make
cp libmath.so ../libmath.v2.so
```

And version 1!

```bash
git checkout 1.0.0
make
cp libmath.so ../libmath.v1.so
```

These libraries will be required for the example, so make sure you have them!

## Usage

First, prepare your environment. You will need to install clingo (or the Python wrapper to it).

```bash
$ python -m venv env
$ source env/bin/activate
$ pip install -r requirements.txt
```

And then run the example!

```bash
$ python example.py
```
```bash
$ python example.py 
{
    "is_a": [
        [
            "A"
        ]
    ],
    "is_b": [
        [
            "B"
        ]
    ],
    "is_different": [
        [
            "A",
            "B"
        ]
    ],
    "removed_node": [
        [
            "A",
            "B",
            "function",
            "_ZN11MathLibrary10Arithmetic3AddEii"
        ],
        [
            "A",
            "B",
            "type",
            "int"
        ],
        [
            "A",
            "B",
            "basetype",
            "int"
        ],
        [
            "A",
            "B",
            "size",
            "4"
        ],
        [
            "A",
            "B",
            "location",
            "framebase-20"
        ]
    ],
    "added_node": [
        [
            "A",
            "B",
            "function",
            "_ZN11MathLibrary10Arithmetic3AddEdd"
        ]
    ]
}
```

Note that the scripts here can be integrated into a module proper if this
idea makes sense. The current example is very simple, and I'll need to parse more complex
ones (e.g., with more DWARF DIE tag types) to finish it up.
