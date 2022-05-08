%=============================================================================
% A and B are two instances of the same library. Can B replace A?
%=============================================================================

%=============================================================================
% FACTS (the facts below are the corpora for each of A and B written in asp
% the rules is_entity and has_attribute are part of the comparison spec,
% while the specific values used (e.g., func for an entity name) are specific
% to a domain (like ABI).

% Each library (A and B) has facts exported in its namespace
% This sets the context for the comparison - A vs. (or diff) B
is_a("A").
is_b("B").

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

%=============================================================================
% Diff rules (the rules below define the diffspec
% This will be directional going from A to B (B-A)

% Libraries A and B are different if A!=B
% This is a sanity check that the unique id of things we're compating is different!
is_different(A, B) :- is_a(A), is_b(B), A != B.

% A node is a parent of another if they have a relation
is_parent(Namespace, NodeA, NodeB, Relation) :-
    node(Namespace, NodeA, _, _),   
    node(Namespace, NodeB, _, _),   
    relation(Namespace, NodeA, Relation, NodeB).

is_parent(Namespace, NodeA, NodeB, NameA, NameB, Relation) :-
    node(Namespace, NodeA, NameA, _),   
    node(Namespace, NodeB, NameB, _),   
    relation(Namespace, NodeA, Relation, NodeB).


% This could be reversed using the same function above,
% but we can provide the named function as a courtesy
is_child(Namespace, NodeA, NodeB, Relation) :-
    node(Namespace, NodeA, _, _),   
    node(Namespace, NodeB, _, _),   
    relation(Namespace, NodeB, Relation, NodeA).

% Return children of node in namespace, any parent node or relation
get_node_parents(Namespace, Parent, Node) :- is_parent(Namespace, Parent, Node, _).

% Note that we simply count 1 if the node has any parents, this isn't an accurate number.
has_parents(Namespace, Node) :- N = #count{ 1 : get_node_parents(Namespace, _, Node)}, node(Namespace, Node, _, _), N>0.
is_root(Namespace, Node) :- N = #count{ 1 : get_node_parents(Namespace, _, Node)}, node(Namespace, Node, _, _), N == 0.
 
% What is removed if we move from A to B? 
% This covers anything with a parent (not a root)
removed_node(A, B, Name) :-
    is_a(A), is_b(B),
    node(A, NodeA, Name, _),
    not node(B, NodeB, Name, _),
    shared_parent_missing(NodeA, NodeB, Name).

% This covers top level cases (no parents)
removed_node(A, B, Name, Value) :-
    is_a(A), is_b(B),
    node(B, _, Name, Value),
    not node(A, _, Name, Value),
    not changed_node_value(A, B, _, _, Name, _, _).

% What is added if we move from A to B?
% We have the entity in B but not A
added_node(A, B, Name, Value) :- 
    is_a(A), is_b(B),
    node(A, _, Name, Value),
    not node(B, _, Name, Value),
    not changed_node_value(A, B, _, _, Name, _, _).    

% What nodes are shared (at the highest level) 
shared_nodes(A, B, EntityA, EntityB, Type, Name) :-
    is_a(A), is_b(B),
    node(B, EntityB, Type, Name),
    node(A, EntityA, Type, Name).

% or values
changed_node_value(A, B, EntityA, EntityB, Name, ValueA, ValueB) :-
    is_a(A), is_b(B),
    node(A, EntityA, Name, ValueA),
    node(B, EntityB, Name, ValueB),
    shared_parent(EntityA, EntityB, Name),
    ValueA != ValueB.

% A removed relation
removed_relation(A, B, EntityA, EntityB, Type, Name, Relation, Value) :-
    is_a(A), is_b(B),
    node(A, EntityA, Type, Name),
    node(B, EntityB, Type, Name),
    relation(A, EntityA, Relation, Value),
    not relation(B, EntityB, Relation, _).

% IF up to the root we can say the relationship holds...

% Two nodes have a shared parent (across states A and B) if:
shared_parent(NodeA, NodeB, Name) :-
    node(NamespaceA, NodeA, Name, _),
    node(NamespaceB, NodeB, Name, _),
    is_parent(NamespaceA, ParentA, NodeA, ParentName, _, Relation),
    is_parent(NamespaceB, ParentB, NodeB, ParentName, _, Relation),
    shared_parent(NodeA, NodeB, ParentName),
    NamespaceA != NamespaceB.

shared_parent(NodeA, NodeB, Name) :-
    node(NamespaceA, NodeA, Name, _),
    node(NamespaceB, NodeB, Name, _),
    is_parent(NamespaceA, ParentA, NodeA, ParentName, _, Relation),
    is_parent(NamespaceB, ParentB, NodeB, ParentName, _, Relation),
    NamespaceA != NamespaceB,
    NodeA == NodeB.

% This function is used to determine if two nodes have the same parent tree
% even if one is missing.
shared_parent_missing_node(NodeA, NodeB, Name) :-
    node(NamespaceA, NodeA, Name, _),
    not node(NamespaceB, NodeB, Name, _),
    is_parent(NamespaceA, ParentA, NodeA, ParentName, _, Relation),
    is_parent(NamespaceB, ParentB, NodeB, ParentName, _, Relation),
    shared_parent_missing(NodeA, NodeB, ParentName),
    NamespaceA != NamespaceB.

shared_parent_missing(NodeA, NodeB, Name) :-
    node(NamespaceA, NodeA, Name, _),
    not node(NamespaceB, NodeB, Name, _),
    is_parent(NamespaceA, ParentA, NodeA, ParentName, _, Relation),
    is_parent(NamespaceB, ParentB, NodeB, ParentName, _, Relation),
    NamespaceA != NamespaceB,
    NodeA == NodeB.

#show is_different/2.
#show is_a/1.
#show is_b/1.
#show added_node/4.
#show removed_node/4.
#show changed_node_value/7.
%#show removed_relation/8.
%#show is_parent/4.
%#show is_child/4.
%#show has_parents/2.
%#show is_root/2.
%#show shared_parent/3.
%#show added_attribute/7.
%#show shared_attribute/7.
