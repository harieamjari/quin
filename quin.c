/* Copyright (C) 2025 The TQC-135 authors.
 *
 * Licensed under MIT License.
 *
 * From the article A quinary cipher for SMS encryption.
 *
 * This source code contains the reference implementation for TQC-135.
 */



#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#ifndef NO_LOCALE
#include <locale.h>
#endif

#include <wchar.h>

#define T int16_t
#define P 5
#define N 45
#define BLOCK_SIZE 135
#define GAMMA                                                                  \
  (T[N]){0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3,              \
         4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2,              \
         3, 4, 0, 1, 2, 3, 4}


#define MODULUS_POLYNOMIAL                                                     \
  (T[2 * N]){2, 2, 3, 4, 3, 3, 2, 2, 4, 4, 1, 0, 0, 4, 3, 1,                   \
             3, 1, 4, 0, 2, 4, 2, 0, 1, 4, 2, 1, 0, 2, 1, 2,                   \
             1, 2, 1, 4, 0, 1, 3, 1, 2, 2, 1, 0, 1, 1}

wchar_t *gsm_3quin[125] = {
    L"@", L"£", L"$", L"¥", L"è", L"é", L"ù",  L"ì", L"ò", L"Ç", L"ñ", L"Ø", L"ø", L"ü",
    L"Å", L"å", L"Δ", L"_", L"Φ", L"Γ", L"Λ",  L"Ω", L"Π", L"Ψ", L"Σ", L"Θ", L"Ξ", L"à",
    L"Æ", L"æ", L"ß", L"É", L" ", L"!", L"\"", L"#", L"¤", L"%", L"&", L"'", L"(", L")",
    L"*", L"+", L",", L"-", L".", L"/", L"0",  L"1", L"2", L"3", L"4", L"5", L"6", L"7",
    L"8", L"9", L":", L";", L"<", L"=", L">",  L"?", L"¡", L"A", L"B", L"C", L"D", L"E",
    L"F", L"G", L"H", L"I", L"J", L"K", L"L",  L"M", L"N", L"O", L"P", L"Q", L"R", L"S",
    L"T", L"U", L"V", L"W", L"X", L"Y", L"Z",  L"Ä", L"Ö", L"Ñ", L"Ü", L"§", L"¿", L"a",
    L"b", L"c", L"d", L"e", L"f", L"g", L"h",  L"i", L"j", L"k", L"l", L"m", L"n", L"o",
    L"p", L"q", L"r", L"s", L"t", L"u", L"v",  L"w", L"x", L"y", L"z", L"ä", L"ö"};
uint16_t gsm_utf8[125] = {
    0x40,   0xc2a3, 0x24,   0xc2a5, 0xc3a8, 0xc3a9, 0xc3b9, 0xc3ac, 0xc3b2,
    0xc387, 0xc3b1, 0xc398, 0xc3b8, 0xc3bc, 0xc385, 0xc3a5, 0xce94, 0x5f,
    0xcea6, 0xce93, 0xce9b, 0xcea9, 0xcea0, 0xcea8, 0xcea3, 0xce98, 0xce9e,
    0xc3a0, 0xc386, 0xc3a6, 0xc39f, 0xc389, 0x20,   0x21,   0x22,   0x23,
    0xc2a4, 0x25,   0x26,   0x27,   0x28,   0x29,   0x2a,   0x2b,   0x2c,
    0x2d,   0x2e,   0x2f,   0x30,   0x31,   0x32,   0x33,   0x34,   0x35,
    0x36,   0x37,   0x38,   0x39,   0x3a,   0x3b,   0x3c,   0x3d,   0x3e,
    0x3f,   0xc2a1, 0x41,   0x42,   0x43,   0x44,   0x45,   0x46,   0x47,
    0x48,   0x49,   0x4a,   0x4b,   0x4c,   0x4d,   0x4e,   0x4f,   0x50,
    0x51,   0x52,   0x53,   0x54,   0x55,   0x56,   0x57,   0x58,   0x59,
    0x5a,   0xc384, 0xc396, 0xc391, 0xc39c, 0xc2a7, 0xc2bf, 0x61,   0x62,
    0x63,   0x64,   0x65,   0x66,   0x67,   0x68,   0x69,   0x6a,   0x6b,
    0x6c,   0x6d,   0x6e,   0x6f,   0x70,   0x71,   0x72,   0x73,   0x74,
    0x75,   0x76,   0x77,   0x78,   0x79,   0x7a,   0xc3a4, 0xc3b6};

int degree(T *p, int n) {
  for (int i = 1; i < n+1; i++)
    if (p[n-i])
      return n-i;
  return 0;
}

T mod(T a, T p) {
  while (a < 0)
    a += p;
  return a % p;
}

const T minv[P] = {0, 1, 3, 2, 4};

void long_division(T p[2*N], T q[2*N], T r[2*N], T d[2*N]){
  /* pq + r = d */
  memcpy(r, d, sizeof(T)*2*N);
  int deg;
  while (1) {
    if ((deg = degree(r, 2*N)) < degree(p, 2*N))
      break;
    if (!degree(r, 2*N) && !r[0]) {
      printf("should be fatal on finding multiplicative inverse\n");
      break;
    }

    /* subtrahend */
    T s[2*N] = {0};
    /* since degree(r) >= degree(p). w >= 0 */
    int shifts = degree(r, 2*N) - degree(p, 2*N); 

    memcpy(s + shifts, p, sizeof(T)*(degree(p, 2*N)+1));
    assert(degree(s, 2*N) == degree(r, 2*N));
    T mv = minv[s[degree(s, 2*N)]];
    q[shifts] += mv*r[deg];
    q[shifts] = mod(q[shifts], P);
    for (int i = 0; i < 2*N; i++) {
      s[i] *= mv*r[deg];
    }
    for (int i = 0; i < 2*N; i++) {
      r[i] = mod(r[i] - s[i], P);
    }
  }
}

void multiply(T dst[N], T a[N], T b[N]) {
  T a_[N], b_[N];
  memcpy(a_, a, sizeof(T)*N);
  memcpy(b_, b, sizeof(T)*N);

  T cd[2*N] = {0};
  /* concolve */
  for (int i = 0; i < N; i++)
    for (int j = 0; j < N; j++)
      cd[i+j] += a_[i]*b_[j];

  for (int i = 0; i < 2*N; i++)
    cd[i] = mod(cd[i], P);

  T r[2*N] = {0};
  long_division(MODULUS_POLYNOMIAL, (T[2*N]){0}, r, cd);
  assert(degree(r, 2*N) < N);
  memcpy(dst, r, sizeof(T)*N);
}

void add(T dst[N], T a[N], T b[N]) {
  T a_[N], b_[N];
  memcpy(a_, a, sizeof(T)*N);
  memcpy(b_, b, sizeof(T)*N);
  for (int i = 0; i < N; i++)
    dst[i] = mod(a_[i] + b_[i], P);
}

void additive_inverse(T dst[N], T a[N]) {
  for (int i = 0; i < N; i++)
    dst[i] = mod(-a[i], P);
}

void multiplicative_inverse(T dst[N], T p[N]) {
  if (degree(p, N) == 0) {
    dst[0] = minv[p[0]];
    return;
  }
  /* 1/p = q/(-r) */
  T p_[2*N] = {0}, r_[2*N] = {0}, q_[2*N] = {0};
  memcpy(p_, p, sizeof(T)*N);
  long_division(p_, q_, r_, MODULUS_POLYNOMIAL);
  assert(degree(q_, 2*N) < N);

  T temp[N] = {0};
  additive_inverse(temp, r_);
  multiplicative_inverse(temp, temp);
  multiply(temp, temp, q_);
  memcpy(dst, temp, sizeof(T)*N);
}


void printq(T *q, int n) {
  for (int i = 0; i < n; i++) {
    if ((i % 3) == 0)
      putchar(' ');
    printf("%d", q[i]);
  }
}

void print_qchar(T *b, int n) {
  printq(b, n);
  printf("  ");
  for (int i = 0; i < n/3; i++)
    wprintf(L"%S", gsm_3quin[b[i*3] + b[i*3 + 1]*5 + b[i*3 + 2]*25]);
  puts("");
}

void add_roundkey(T s[BLOCK_SIZE], T k[BLOCK_SIZE]){
  for (int i = 0; i < BLOCK_SIZE; i++) {
    s[i] += k[i];
    s[i] = mod(s[i], P);
  }
}

void add_roundkeyi(T s[BLOCK_SIZE], T k[BLOCK_SIZE]){
  for (int i = 0; i < BLOCK_SIZE; i++) {
    s[i] -= k[i];
    s[i] = mod(s[i], P);
  }
}

void substitute_columns(T s[BLOCK_SIZE]) {
  T c0[N] = {0};
  T c1[N] = {0};
  T c2[N] = {0};

  memcpy(c0+0*15, s+0*45 + 0*15, sizeof(T)*15);
  memcpy(c0+1*15, s+1*45 + 0*15, sizeof(T)*15);
  memcpy(c0+2*15, s+2*45 + 0*15, sizeof(T)*15);

  memcpy(c1+0*15, s+0*45 + 1*15, sizeof(T)*15);
  memcpy(c1+1*15, s+1*45 + 1*15, sizeof(T)*15);
  memcpy(c1+2*15, s+2*45 + 1*15, sizeof(T)*15);

  memcpy(c2+0*15, s+0*45 + 2*15, sizeof(T)*15);
  memcpy(c2+1*15, s+1*45 + 2*15, sizeof(T)*15);
  memcpy(c2+2*15, s+2*45 + 2*15, sizeof(T)*15);

  if (memcmp(c0, (T[N]){0}, sizeof(T)*N))
    multiplicative_inverse(c0, c0);
  add(c0, c0, GAMMA);
  if (memcmp(c1, (T[N]){0}, sizeof(T)*N))
    multiplicative_inverse(c1, c1);
  add(c1, c1, GAMMA);
  if (memcmp(c2, (T[N]){0}, sizeof(T)*N))
    multiplicative_inverse(c2, c2);
  add(c2, c2, GAMMA);

  memcpy(s+0*45 + 0*15, c0+0*15, sizeof(T)*15);
  memcpy(s+1*45 + 0*15, c0+1*15, sizeof(T)*15);
  memcpy(s+2*45 + 0*15, c0+2*15, sizeof(T)*15);

  memcpy(s+0*45 + 1*15, c1+0*15, sizeof(T)*15);
  memcpy(s+1*45 + 1*15, c1+1*15, sizeof(T)*15);
  memcpy(s+2*45 + 1*15, c1+2*15, sizeof(T)*15);

  memcpy(s+0*45 + 2*15, c2+0*15, sizeof(T)*15);
  memcpy(s+1*45 + 2*15, c2+1*15, sizeof(T)*15);
  memcpy(s+2*45 + 2*15, c2+2*15, sizeof(T)*15);
}

void substitute_columnsi(T s[BLOCK_SIZE]) {
  T c0[N] = {0};
  T c1[N] = {0};
  T c2[N] = {0};

  T g[N] = {0};
  memcpy(g, GAMMA, sizeof(T)*N);
  additive_inverse(g, g);

  memcpy(c0+0*15, s+0*45 + 0*15, sizeof(T)*15);
  memcpy(c0+1*15, s+1*45 + 0*15, sizeof(T)*15);
  memcpy(c0+2*15, s+2*45 + 0*15, sizeof(T)*15);

  memcpy(c1+0*15, s+0*45 + 1*15, sizeof(T)*15);
  memcpy(c1+1*15, s+1*45 + 1*15, sizeof(T)*15);
  memcpy(c1+2*15, s+2*45 + 1*15, sizeof(T)*15);

  memcpy(c2+0*15, s+0*45 + 2*15, sizeof(T)*15);
  memcpy(c2+1*15, s+1*45 + 2*15, sizeof(T)*15);
  memcpy(c2+2*15, s+2*45 + 2*15, sizeof(T)*15);

  add(c0, c0, g);
  if (memcmp(c0, (T[N]){0}, sizeof(T)*N))
    multiplicative_inverse(c0, c0);
  add(c1, c1, g);
  if (memcmp(c1, (T[N]){0}, sizeof(T)*N))
    multiplicative_inverse(c1, c1);
  add(c2, c2, g);
  if (memcmp(c2, (T[N]){0}, sizeof(T)*N))
    multiplicative_inverse(c2, c2);

  memcpy(s+0*45 + 0*15, c0+0*15, sizeof(T)*15);
  memcpy(s+1*45 + 0*15, c0+1*15, sizeof(T)*15);
  memcpy(s+2*45 + 0*15, c0+2*15, sizeof(T)*15);

  memcpy(s+0*45 + 1*15, c1+0*15, sizeof(T)*15);
  memcpy(s+1*45 + 1*15, c1+1*15, sizeof(T)*15);
  memcpy(s+2*45 + 1*15, c1+2*15, sizeof(T)*15);

  memcpy(s+0*45 + 2*15, c2+0*15, sizeof(T)*15);
  memcpy(s+1*45 + 2*15, c2+1*15, sizeof(T)*15);
  memcpy(s+2*45 + 2*15, c2+2*15, sizeof(T)*15);
}

void shift_rows(T s[BLOCK_SIZE]){
  T s_[BLOCK_SIZE] = {0};
  memcpy(s_, s, sizeof(T)*BLOCK_SIZE);

  memcpy(s + 15*3, s_ + 15*4, sizeof(T)*15);
  memcpy(s + 15*4, s_ + 15*5, sizeof(T)*15);
  memcpy(s + 15*5, s_ + 15*3, sizeof(T)*15);

  memcpy(s + 15*6, s_ + 15*8, sizeof(T)*15);
  memcpy(s + 15*7, s_ + 15*6, sizeof(T)*15);
  memcpy(s + 15*8, s_ + 15*7, sizeof(T)*15);
}

void shift_rowsi(T s[BLOCK_SIZE]){
  T s_[BLOCK_SIZE] = {0};
  memcpy(s_, s, sizeof(T)*BLOCK_SIZE);

  memcpy(s + 15*4, s_ + 15*3, sizeof(T)*15);
  memcpy(s + 15*5, s_ + 15*4, sizeof(T)*15);
  memcpy(s + 15*3, s_ + 15*5, sizeof(T)*15);

  memcpy(s + 15*8, s_ + 15*6, sizeof(T)*15);
  memcpy(s + 15*6, s_ + 15*7, sizeof(T)*15);
  memcpy(s + 15*7, s_ + 15*8, sizeof(T)*15);
}

void next_key(T d[BLOCK_SIZE], T s[BLOCK_SIZE]) {
  T taps[BLOCK_SIZE] = {
      [134] = 2,  [132] = 4, [131] = 4, [130] = 3, [129] = 3, [128] = 1,
      [127] = 2, [126] = 2, [125] = 1, [124] = 3, [123] = 4, [122] = 3,
      [120] = 1, [119] = 3, [117] = 2, [116] = 1, [115] = 1, [114] = 2,
      [113] = 3, [112] = 3, [111] = 1, [110] = 1, [108] = 1, [107] = 2,
      [105] = 2, [104] = 3, [103] = 3, [102] = 1, [101] = 4, [99] = 1,
      [98] = 4,  [96] = 2,  [95] = 1,  [94] = 1,  [93] = 3,  [92] = 3,
      [91] = 4,  [90] = 2,  [89] = 2,  [87] = 2,  [85] = 1,  [84] = 3,
      [83] = 4,  [82] = 4,  [81] = 2,  [80] = 3,  [79] = 4,  [78] = 3,
      [77] = 4,  [76] = 2,  [75] = 1,  [74] = 3,  [73] = 2,  [72] = 1,
      [68] = 2,  [67] = 1,  [66] = 1,  [65] = 3,  [64] = 3,  [63] = 2,
      [62] = 4,  [61] = 4,  [60] = 2,  [59] = 3,  [58] = 2,  [57] = 4,
      [56] = 3,  [55] = 4,  [54] = 4,  [53] = 1,  [52] = 1,  [50] = 2,
      [49] = 2,  [45] = 2,  [43] = 3,  [42] = 2,  [41] = 3,  [40] = 3,
      [39] = 2,  [38] = 4,  [37] = 1,  [36] = 3,  [35] = 2,  [34] = 4,
      [33] = 2,  [31] = 3,  [30] = 2,  [29] = 2,  [27] = 1,  [26] = 3,
      [24] = 3,  [23] = 4,  [22] = 2,  [21] = 2,  [19] = 2,  [18] = 1,
      [17] = 2,  [16] = 4,  [12] = 4,  [11] = 3,  [10] = 4,  [8] = 4,
      [7] = 4,   [6] = 2,   [5] = 4,   [4] = 2,   [3] = 4,   [2] = 3,
      [0] = 3};

  T k[BLOCK_SIZE] = {0};
  memcpy(k, s, sizeof(T)*BLOCK_SIZE);
  for (int i = 0; i < 10; i++) {
    shift_rows(k);
    substitute_columns(k);
    T v = k[BLOCK_SIZE - 1];
    for (int i = 0; i < BLOCK_SIZE-1; i++) {
      k[i + 1] = k[i];
    }
    k[0] = 0;
    for (int i = 0; i < BLOCK_SIZE; i++) {
      k[i] -= taps[i]*v;
      k[i] = mod(k[i], P);
    }
  }
  memcpy(d, k, sizeof(T)*BLOCK_SIZE);
}

void tqc_encrypt(T dst[BLOCK_SIZE], T m[BLOCK_SIZE], T k[BLOCK_SIZE], int rounds) {
  T s[BLOCK_SIZE], rkey[BLOCK_SIZE];
  memcpy(s, m, sizeof(T)*BLOCK_SIZE);
  memcpy(rkey, k, sizeof(T)*BLOCK_SIZE);

  for (int i = 0; i < rounds; i++) {
    add_roundkey(s, rkey);
    substitute_columns(s);
    shift_rows(s);
    next_key(rkey, rkey);
  }
  add_roundkey(s, rkey);
  substitute_columns(s);
  next_key(rkey, rkey);
  add_roundkey(s, rkey);

  memcpy(dst, s, sizeof(T)*BLOCK_SIZE);
}

void tqc_decrypt(T dst[BLOCK_SIZE], T m[BLOCK_SIZE], T k[BLOCK_SIZE], int rounds) {
  T s[BLOCK_SIZE];
  memcpy(s, m, sizeof(T)*BLOCK_SIZE);
  T rkeys[rounds + 2][BLOCK_SIZE];
  memcpy(rkeys[0], k, sizeof(T)*BLOCK_SIZE);
  for (int i = 0; i < rounds + 1; i++) {
    next_key(rkeys[i + 1], rkeys[i]);
  }

  add_roundkeyi(s, rkeys[rounds + 1]);
  substitute_columnsi(s);
  add_roundkeyi(s, rkeys[rounds]);
  for (int i = 0; i < rounds; i++) {
    shift_rowsi(s);
    substitute_columnsi(s);
    add_roundkeyi(s, rkeys[rounds - (i+1)]);
  }

  memcpy(dst, s, sizeof(T)*BLOCK_SIZE);
}

int sizeof_utf8char(char p) {
  if ((p >> 5) == 6)
    return 2;
  if ((p >> 7) == 0)
    return 1;
  return 0;
}

void int_to_quin(T d[3], int i) {
  d[0] = i % 5;
  i /= 5;
  d[1] = i % 5;
  i /= 5;
  d[2] = i % 5;
}

int utf8_to_quins(T d[BLOCK_SIZE], char *str) {
  int i = 0;
  int s;
  while (*str && (s = sizeof_utf8char(*str))  && i < BLOCK_SIZE) {
    uint16_t c = s == 1 ? *str : ((uint16_t)*(str) << 8) | *(str + 1);
    for (int j = 0; j < 125; j++) {
      if (c == gsm_utf8[j]) {
        int_to_quin(d + i, j);
        i += 3;
        break;
      } else if ( j == 124) {
        //printf("%c\n",(char)(c&0xff));
        return 1;
      }
    }
    str += s;
  }
  return 0;
}

int main(int argc, char *argv[]) {
//  T p[N] = {0, 1, 0, 3, 1, 2, 4};
//  for (int i = 0; i < 300; i++){ 
//    multiply(p, p, (T[N]){0, 1});
//    print_qchar(p, N);
//  }
#ifndef NO_LOCALE
  setlocale(LC_ALL, "en_US.UTF-8");
#endif
  if (argc != 4) {
    printf("usage: %s [e|d] message key\n", argv[0]);
    return 0;
  }


  /* message */
  T m[BLOCK_SIZE] = {0};
  /* key */
  T k[BLOCK_SIZE] = {0};

  if (utf8_to_quins(m, argv[2])) {
    printf("invalid message characters\n");
    return 1;
  }

  if (utf8_to_quins(k, argv[3])) {
    printf("invalid key characters\n");
    return 1;
  }

  if (argv[1][0] == 'e') {
    tqc_encrypt(m, m, k, 5);
  } else if (argv[1][0] == 'd') {
    tqc_decrypt(m, m, k, 5);
  }

  print_qchar(m, BLOCK_SIZE);


  return 0;
}
