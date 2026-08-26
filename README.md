# VISS OS — embedded assessment

Second-stage exercise for the VISS OS embedded team: a self-contained C++17
implementation task on the device-side cryptography of the VISS OS tree —
hashing, signature verification and authorisation.

**Everything you need is in [`candidate/`](candidate/).**
Read [`candidate/README.md`](candidate/README.md) first, then
[`candidate/SPEC.md`](candidate/SPEC.md) in full before writing anything.

It is scoped to a **hard six-hour window**, and you work in a fork of this
repository and hand it back as a pull request. Both are explained in
`candidate/README.md`.

```bash
# after forking this repository to your own account
git clone https://github.com/<your-username>/viss-asses.git
cd viss-asses/candidate
cmake -B build && cmake --build build -j
./build/tests/viss-tests      # 0 of 4 passing — that is the start state
```

Sort the build out **before** your window starts. You need a C++17 compiler,
CMake and `libssl-dev`; on Windows that means WSL. Losing an hour of six to a
missing header helps nobody.
