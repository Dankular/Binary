// Deliberately structured so add() lands at a different address than in
// sig_a.c (extra functions before it) — a real test of signature matching
// has to identify the function despite that, not just find it by luck at
// the same offset. See scripts/signature_smoke_test.sh.
int padding1(int a) { return a * 2; }
int padding2(int a, int b, int c) { return a + b - c; }
int padding3(void) { return 42; }
int add(int a, int b) { return a + b; }

int main(void) { return add(10, 20); }
