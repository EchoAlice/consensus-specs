from eth2spec.test.helpers.state import (
    state_transition_and_sign_block,
)
from eth2spec.test.helpers.block import (
    build_empty_block_for_next_slot
)
from eth2spec.test.context import (
    spec_state_test,
    with_eip4844_and_later,
)
from eth2spec.test.helpers.sharding import (
    get_sample_opaque_tx,
    compute_proof_single,
    compute_proof_from_blobs,
    get_sample_blob,
    commit_to_poly,
    eval_poly_at,
)
from eth2spec.test.helpers.keys import privkeys


@with_eip4844_and_later
@spec_state_test
def test_verify_blobs_sidecar(spec, state):
    blob_count = 1
    block = build_empty_block_for_next_slot(spec, state)
    opaque_tx, blobs, blob_kzgs = get_sample_opaque_tx(spec, blob_count=blob_count)
    block.body.blob_kzgs = blob_kzgs
    block.body.execution_payload.transactions = [opaque_tx]
    state_transition_and_sign_block(spec, state, block)

    blobs_sidecar = spec.get_blobs_sidecar(block, blobs)
    proof = compute_proof_from_blobs(spec, blobs)
    blobs_sidecar.kzg_aggregated_proof = proof
    privkey = privkeys[1]
    spec.get_signed_blobs_sidecar(state, blobs_sidecar, privkey)
    expected_kzgs = [spec.blob_to_kzg(blobs[i]) for i in range(blob_count)]
    assert spec.verify_blobs_sidecar(block.slot, block.hash_tree_root(), expected_kzgs, blobs_sidecar)


@with_eip4844_and_later
@spec_state_test
def test_single_proof(spec, state):
    x = 3
    polynomial = get_sample_blob(spec)
    polynomial = [int(i) for i in polynomial]
    commitment = commit_to_poly(spec, polynomial)
    y = eval_poly_at(spec, polynomial, x)
    proof = compute_proof_single(spec, polynomial, x)
    assert spec.verify_kzg_proof(commitment, x, y, proof)
