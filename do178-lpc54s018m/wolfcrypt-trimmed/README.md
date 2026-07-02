# Trimmed wolfCrypt sources (LPC54S018M DO-178C DAL A)

These are the wolfCrypt units the wolfBoot image compiles, trimmed to only the
code this ECDSA P-384 + SHA-384 verify build reaches. They live here as a
reference bundle because `lib/wolfssl` is a git submodule and cannot be edited
in-place from this repo. The trimmed wolfBoot sources ARE edited in place (see
the diff on src/, hal/, include/).
