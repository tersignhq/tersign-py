"""Signer addresses whose private keys are PUBLISHED — anyone can sign as them.

A signature from one of these keys recovers and verifies like any other, so a verifier that
stays silent about it hands a stranger a receipt that looks authored when anyone could have
minted it. They are what worked examples and test suites sign with (ours included: the
synthetic evidence bundle uses dev-mnemonic accounts #0 and #1), which is exactly why a
real-looking artifact carrying one must be flagged rather than passed quietly.

The table is DERIVED, not transcribed: tests/test_verify_signer_binding.py re-derives every
address from its published secret (BIP-39/BIP-32 over the stdlib and this package's own
secp256k1), so a typo here fails the suite instead of silently un-flagging a key. The same
twenty addresses were cross-checked against viem's independent derivation when the table was
written. Deliberately narrow: keys whose secret is published as a convention, not every key
that has ever leaked.
"""

# BIP-39 mnemonic shipped as the default dev account set by Hardhat (20 accounts) and Anvil
# (10), derived at m/44'/60'/0'/0/i.
DEV_MNEMONIC = "test test test test test test test test test test test junk"

_DEV_MNEMONIC_ADDRESSES = (
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
    "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
    "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
    "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
    "0x976ea74026e726554db657fa54763abd0c3a0aa9",
    "0x14dc79964da2c08b23698b3d3cc7ca32193d9955",
    "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f",
    "0xa0ee7a142d267c1f36714e4a8f75612f20a79720",
    "0xbcd4042de499d14e55001ccbb24a551f3b954096",
    "0x71be63f3384f5fb98995898a86b02fb2426c5788",
    "0xfabb0ac9d68b0b445fb7357272ff202c5651694a",
    "0x1cbd3b2770909d4e10f157cabc84c7264073c9ec",
    "0xdf3e18d64bc6a983f673ab319ccae4f1a57c7097",
    "0xcd3b766ccdd6ae721141f452c550ca635964ce71",
    "0x2546bcd3c84621e976d8185a91a922ae77ecec30",
    "0xbda5747bfd65f08deb54cb465eb87d40e51b197e",
    "0xdd2fd4581271e230360230f9337d5c0430bf44c0",
    "0x8626f6940e2eb28930efb4cef49b2d1f2c9c1199",
)

# Private keys 1, 2 and 3 — the other convention for "obviously a test key".
_SMALL_SCALAR_ADDRESSES = (
    "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
    "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf",
    "0x6813eb9362372eef6200f3b1dbc3f819671cba69",
)

PUBLISHED_TEST_KEYS = {
    **{a: "Hardhat/Anvil default dev mnemonic, account #%d" % i
       for i, a in enumerate(_DEV_MNEMONIC_ADDRESSES)},
    **{a: "private key 0x%x (a small scalar)" % (i + 1) for i, a in enumerate(_SMALL_SCALAR_ADDRESSES)},
}


def published_key_label(address):
    """The published-secret label for `address`, or None when it is not a known test key."""
    if not isinstance(address, str):
        return None
    return PUBLISHED_TEST_KEYS.get(address.lower())
