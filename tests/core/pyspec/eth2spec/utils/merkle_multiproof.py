from typing import (Sequence, Tuple, Union, Set)

from eth2spec.utils.hash_function import hash
from eth2spec.utils.ssz.ssz_typing import (Bytes32, Container,  ByteList, uint64, List)
from eth2spec.deneb.mainnet import (GeneralizedIndex, SSZVariableName, BeaconBlock, floorlog2)
from remerkleable.tree import (RootNode, Root, gindex_bit_iter)
from remerkleable.tree import Node
from remerkleable.byte_arrays import ByteVector as BaseBytes
from remerkleable.complex import List as BaseList


# TODO: define types so that other code doesn't break        (reuse remerkleable types where you can)
#       consensus-specs/ssz/merkle-proofs.md  code here.  We want to expose  
#       `verify_merkle_multiproof()` within test_merkle_multiproof.py.

# Helper functions
def get_power_of_two_ceil(x: int) -> int:
    """
    Get the power of 2 for given input, or the closest higher power of 2 if the input is not a power of 2.
    Commonly used for "how many nodes do I need for a bottom tree layer fitting x elements?"
    Example: 0->1, 1->1, 2->2, 3->4, 4->4, 5->8, 6->8, 7->8, 8->8, 9->16.
    """
    if x <= 1:
        return 1
    elif x == 2:
        return 2
    else:
        return 2 * get_power_of_two_ceil((x + 1) // 2)

def get_power_of_two_floor(x: int) -> int:
    """
    Get the power of 2 for given input, or the closest lower power of 2 if the input is not a power of 2.
    The zero case is a placeholder and not used for math with generalized indices.
    Commonly used for "what power of two makes up the root bit of the generalized index?"
    Example: 0->1, 1->1, 2->2, 3->2, 4->4, 5->4, 6->4, 7->4, 8->8, 9->8
    """
    if x <= 1:
        return 1
    if x == 2:
        return x
    else:
        return 2 * get_power_of_two_floor(x // 2)


# Generalized Merkle tree index
def merkle_tree(leaves: Sequence[Bytes32]) -> Sequence[Bytes32]:
    """
    Return an array representing the tree nodes by generalized index: 
    [0, 1, 2, 3, 4, 5, 6, 7], where each layer is a power of 2. The 0 index is ignored. The 1 index is the root.
    The result will be twice the size as the padded bottom layer for the input leaves.
    """
    bottom_length = get_power_of_two_ceil(len(leaves))
    o = [Bytes32()] * bottom_length + list(leaves) + [Bytes32()] * (bottom_length - len(leaves))
    for i in range(bottom_length - 1, 0, -1):
        o[i] = hash(o[i * 2] + o[i * 2 + 1])
    return o


# SSZ object to index
def item_length(typ) -> int:
    """
    Return the number of bytes in a basic type, or 32 (a full hash) for compound types.
    """
    if issubclass(typ, BasicValue):
        return typ.byte_len
    else:
        return 32

def get_elem_type(typ: Union[BaseBytes, BaseList, Container],
                  index_or_variable_name: Union[int, SSZVariableName]):
    """
    Return the type of the element of an object of the given type with the given index
    or member variable name (eg. `7` for `x[7]`, `"foo"` for `x.foo`)
    """
    return typ.get_fields()[index_or_variable_name] if issubclass(typ, Container) else typ.elem_type

def chunk_count(typ) -> int:
    """
    Return the number of hashes needed to represent the top-level elements in the given type
    (eg. `x.foo` or `x[7]` but not `x[7].bar` or `x.foo.baz`). In all cases except lists/vectors
    of basic types, this is simply the number of top-level elements, as each element gets one
    hash. For lists/vectors of basic types, it is often fewer because multiple basic elements
    can be packed into one 32-byte chunk.
    """
    # typ.length describes the limit for list types, or the length for vector types.
    if issubclass(typ, BasicValue):
        return 1
    elif issubclass(typ, Bits):
        return (typ.length + 255) // 256
    elif issubclass(typ, Elements):
        return (typ.length * item_length(typ.elem_type) + 31) // 32
    elif issubclass(typ, Container):
        return len(typ.get_fields())
    else:
        raise Exception(f"Type not supported: {typ}")

def get_item_position(typ, index_or_variable_name: Union[int, SSZVariableName]) -> Tuple[int, int, int]:
    """
    Return three variables:
        (i) the index of the chunk in which the given element of the item is represented;
        (ii) the starting byte position within the chunk;
        (iii) the ending byte position within the chunk.
    For example: for a 6-item list of uint64 values, index=2 will return (0, 16, 24), index=5 will return (1, 8, 16)
    """
    if issubclass(typ, Elements):
        index = int(index_or_variable_name)
        start = index * item_length(typ.elem_type)
        return start // 32, start % 32, start % 32 + item_length(typ.elem_type)
    elif issubclass(typ, Container):
        variable_name = index_or_variable_name
        return typ.get_field_names().index(variable_name), 0, item_length(get_elem_type(typ, variable_name))
    else:
        raise Exception("Only lists/vectors/containers supported")

def get_generalized_index(typ, *path: Union[int, SSZVariableName]) -> GeneralizedIndex:
    """
    Converts a path (eg. `[7, "foo", 3]` for `x[7].foo[3]`, `[12, "bar", "__len__"]` for
    `len(x[12].bar)`) into the generalized index representing its position in the Merkle tree.
    """
    root = GeneralizedIndex(1)
    for p in path:
        assert not issubclass(typ, BasicValue)  # If we descend to a basic type, the path cannot continue further
        if p == '__len__':
            assert issubclass(typ, (List, ByteList))
            typ = uint64
            root = GeneralizedIndex(root * 2 + 1)
        else:
            pos, _, _ = get_item_position(typ, p)
            base_index = (GeneralizedIndex(2) if issubclass(typ, (List, ByteList)) else GeneralizedIndex(1))
            root = GeneralizedIndex(root * base_index * get_power_of_two_ceil(chunk_count(typ)) + pos)
            typ = get_elem_type(typ, p)
    return root


# Helpers for generalized indices
def concat_generalized_indices(*indices: GeneralizedIndex) -> GeneralizedIndex:
    """
    Given generalized indices i1 for A -> B, i2 for B -> C .... i_n for Y -> Z, returns
    the generalized index for A -> Z.
    """
    o = GeneralizedIndex(1)
    for i in indices:
        o = GeneralizedIndex(o * get_power_of_two_floor(i) + (i - get_power_of_two_floor(i)))
    return o

def get_generalized_index_length(index: GeneralizedIndex) -> int:
    """
    Return the length of a path represented by a generalized index.
    """
    return int(log2(index))

def get_generalized_index_bit(index: GeneralizedIndex, position: int) -> bool:
    """
    Return the given bit of a generalized index.
    """
    return (index & (1 << position)) > 0

def generalized_index_sibling(index: GeneralizedIndex) -> GeneralizedIndex:
    return GeneralizedIndex(index ^ 1)

def generalized_index_child(index: GeneralizedIndex, right_side: bool) -> GeneralizedIndex:
    return GeneralizedIndex(index * 2 + right_side)

def generalized_index_parent(index: GeneralizedIndex) -> GeneralizedIndex:
    return GeneralizedIndex(index // 2)

# Merkle Multiproofs
def get_branch_indices(tree_index: GeneralizedIndex) -> Sequence[GeneralizedIndex]:
    """
    Get the generalized indices of the sister chunks along the path from the chunk with the
    given tree index to the root.
    """
    o = [generalized_index_sibling(tree_index)]
    while o[-1] > 1:
        o.append(generalized_index_sibling(generalized_index_parent(o[-1])))
    return o[:-1]

def get_path_indices(tree_index: GeneralizedIndex) -> Sequence[GeneralizedIndex]:
    """
    Get the generalized indices of the chunks along the path from the chunk with the
    given tree index to the root.
    """
    o = [tree_index]
    while o[-1] > 1:
        o.append(generalized_index_parent(o[-1]))
    return o[:-1]

def get_helper_indices(indices: Sequence[GeneralizedIndex]) -> Sequence[GeneralizedIndex]:
    """
    Get the generalized indices of all "extra" chunks in the tree needed to prove the chunks with the given
    generalized indices. Note that the decreasing order is chosen deliberately to ensure equivalence to the
    order of hashes in a regular single-item Merkle proof in the single-item case.
    """
    all_helper_indices: Set[GeneralizedIndex] = set()
    all_path_indices: Set[GeneralizedIndex] = set()
    for index in indices:
        all_helper_indices = all_helper_indices.union(set(get_branch_indices(index)))
        all_path_indices = all_path_indices.union(set(get_path_indices(index)))

    return sorted(all_helper_indices.difference(all_path_indices), reverse=True)

def calculate_merkle_root(leaf: Bytes32, proof: Sequence[Bytes32], index: GeneralizedIndex) -> Root:
    assert len(proof) == get_generalized_index_length(index)
    for i, h in enumerate(proof):
        if get_generalized_index_bit(index, i):
            leaf = hash(h + leaf)
        else:
            leaf = hash(leaf + h)
    return leaf

def verify_merkle_proof(leaf: Bytes32, proof: Sequence[Bytes32], index: GeneralizedIndex, root: Root) -> bool:
    return calculate_merkle_root(leaf, proof, index) == root

def calculate_multi_merkle_root(leaves: Sequence[Bytes32],
                                proof: Sequence[Bytes32],
                                indices: Sequence[GeneralizedIndex]) -> Root:
    assert len(leaves) == len(indices)
    helper_indices = get_helper_indices(indices)
    assert len(proof) == len(helper_indices)  
    objects = {
        **{index: node for index, node in zip(indices, leaves)},
        **{index: node for index, node in zip(helper_indices, proof)}  
    }
    keys = sorted(objects.keys(), reverse=True)
    pos = 0
    
    while pos < len(keys):
        k = keys[pos]
        if k in objects and k ^ 1 in objects and k // 2 not in objects:
            objects[GeneralizedIndex(k // 2)] = hash(
                objects[GeneralizedIndex((k | 1) ^ 1)] +
                objects[GeneralizedIndex(k | 1)]
            )
            keys.append(GeneralizedIndex(k // 2))
            keys.append(GeneralizedIndex(k // 2))
            parent = GeneralizedIndex(k // 2)
        pos += 1
     
    return objects[GeneralizedIndex(1)]

def verify_merkle_multiproof(leaves: Sequence[Bytes32],
                             proof: Sequence[Bytes32],
                             indices: Sequence[GeneralizedIndex],
                             root: RootNode) -> bool:
    return calculate_multi_merkle_root(leaves, proof, indices) == root

# TODO: 
def create_merkle_multiproof(gindexes: Sequence[GeneralizedIndex], all_leaves: Sequence[Bytes32]):  # -> gindex leaves, proof, root
    tree = calc_merkle_tree_from_leaves(all_leaves)
    leaves_to_prove, proof = calc_proof_from_tree(gindexes, tree)

# TODO: Understand why `zerohashes` is necessary.
ZERO_BYTES32 = b'\x00' * 32
zerohashes = [ZERO_BYTES32]
for layer in range(1, 100):
    zerohashes.append(hash(zerohashes[layer - 1] + zerohashes[layer - 1]))

def calc_merkle_tree_from_leaves(values: Sequence[Bytes32]):
    depth = floorlog2(len(values))
    values = list(values)
    tree = [values[::]]
    
    # TODO: Go back to original code once i figure out why individual leaves are seen as `ints`, not `bytes`.
    for d in range(depth + 1):
        parent_values = []
        if len(values) % 2 == 1:
            values.append(zerohashes[d])
        for i in range(0, len(values), 2):
            if isinstance(values[i], int):
                values[i] = values[i].to_bytes(32, 'big')
            if isinstance(values[i+1], int):
                values[i+1] = values[i+1].to_bytes(32, 'big')
            hashed_value = hash(values[i] + values[i + 1])
            parent_values.append(hashed_value) 
        values = parent_values
        tree.append(values[::])
    return tree

# TODO:
def calc_proof_from_tree(gindexes: Sequence[GeneralizedIndex], tree: list[list[Bytes32]]):   #    return leaves_to_prove, proof
    helper_indices = get_helper_indices(gindexes)
    
    # Debugging:
    for l in range(len(tree)):
        print(f"layer {l}: {tree[l]}")
    
    raise NotImplementedError("calc_proof_from_tree is not implemented yet")