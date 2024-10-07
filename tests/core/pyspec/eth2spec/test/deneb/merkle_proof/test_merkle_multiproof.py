import eth2spec.deneb.mainnet

from eth2spec.utils.ssz.ssz_impl import serialize
from eth2spec.utils.merkle_multiproof import (verify_merkle_multiproof, create_merkle_multiproof)
from eth2spec.test.context import (
    spec_state_test,
    with_deneb_and_later,
    with_test_suite_name,
)
from eth2spec.test.helpers.block import (
    build_empty_block_for_next_slot,
    sign_block,
)
from eth2spec.test.helpers.execution_payload import (
    compute_el_block_hash,
)
from eth2spec.test.helpers.sharding import (
    get_sample_opaque_tx,
)
from eth2spec.debug.random_value import (
    RandomizationMode,
    get_random_ssz_object,
)

# verify_merkle_multiproof passes with single leaf and proof
def _run_blob_kzg_commitment_merkle_multiproof_test_single_leaf(spec, state, rng=None):
    opaque_tx, blobs, blob_kzg_commitments, proofs = get_sample_opaque_tx(spec, blob_count=1)
    if rng is None:
        block = build_empty_block_for_next_slot(spec, state)
    else:
        block = get_random_ssz_object(
            rng,
            spec.BeaconBlock,
            max_bytes_length=2000,
            max_list_length=2000,
            mode=RandomizationMode,
            chaos=True,
        )
    block.body.blob_kzg_commitments = blob_kzg_commitments
    block.body.execution_payload.transactions = [opaque_tx]
    block.body.execution_payload.block_hash = compute_el_block_hash(spec, block.body.execution_payload, state)
    signed_block = sign_block(spec, state, block, proposer_index=0)
    blob_sidecars = spec.get_blob_sidecars(signed_block, blobs, proofs)
    blob_index = 0
    blob_sidecar = blob_sidecars[blob_index]

    yield "object", block.body
    kzg_commitment_inclusion_proof = blob_sidecar.kzg_commitment_inclusion_proof
    gindex = spec.get_generalized_index(spec.BeaconBlockBody, 'blob_kzg_commitments', blob_index)
    yield "proof", {
        "leaf": "0x" + blob_sidecar.kzg_commitment.hash_tree_root().hex(),
        "leaf_index": gindex,
        "branch": ['0x' + root.hex() for root in kzg_commitment_inclusion_proof]
    }
    assert verify_merkle_multiproof(
        leaves=[blob_sidecar.kzg_commitment.hash_tree_root()],
        proof=blob_sidecar.kzg_commitment_inclusion_proof,
        indices=[gindex],
        root=blob_sidecar.signed_block_header.message.body_root,
    )

# TODO: Test `verify_merkle_multiproof()`
def _run_blob_kzg_commitment_merkle_multiproof_test_multi_leaf(spec, state, rng=None):
    opaque_tx, blobs, blob_kzg_commitments, proofs = get_sample_opaque_tx(spec, blob_count=3)
    if rng is None:
        block = build_empty_block_for_next_slot(spec, state)
    else:
        block = get_random_ssz_object(
            rng,
            spec.BeaconBlock,
            max_bytes_length=2000,
            max_list_length=2000,
            mode=RandomizationMode,
            chaos=True,
        )
    block.body.blob_kzg_commitments = blob_kzg_commitments
    block.body.execution_payload.transactions = [opaque_tx]
    block.body.execution_payload.block_hash = compute_el_block_hash(spec, block.body.execution_payload, state)
    signed_block = sign_block(spec, state, block, proposer_index=0)
    
    gindex_blob_commit0 = spec.get_generalized_index(spec.BeaconBlockBody, 'blob_kzg_commitments', 0)
    gindex_blob_commit2 = spec.get_generalized_index(spec.BeaconBlockBody, 'blob_kzg_commitments', 2)
    leaves_to_prove = [block.body.blob_kzg_commitments[0].hash_tree_root(), block.body.blob_kzg_commitments[2].hash_tree_root()]    
    gindexes = [gindex_blob_commit0, gindex_blob_commit2] 

    all_leaves = serialize(block.body)
    # TODO: Implement `create_merkle_multiproof()`
    blob_commitments_multi_proof = create_merkle_multiproof(gindexes, all_leaves)

    # TODO: Get `verify_merkle_multiproof()` passing on tests created with our multiproofs.
    assert verify_merkle_multiproof(
        leaves_to_prove,
        proof=blob_commitments_multi_proof,
        indices=gindexes,
        root=signed_block.message.body_root,  # root=blob_sidecar.signed_block_header.message.body_root   for consistancy
    )


@with_test_suite_name("BeaconBlockBody")
@with_deneb_and_later
@spec_state_test
def test_blob_kzg_commitment_merkle_multiproof_single_leaf__basic(spec, state):
    yield from _run_blob_kzg_commitment_merkle_multiproof_test_single_leaf(spec, state)

@with_test_suite_name("BeaconBlockBody")
@with_deneb_and_later
@spec_state_test
def test_blob_kzg_commitment_merkle_multiproof_multi_leaf__basic(spec, state):
    yield from _run_blob_kzg_commitment_merkle_multiproof_test_multi_leaf(spec, state)