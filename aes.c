#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

uint8_t s_box[256] = {
#include "sbox.txt"
};

uint8_t r_box[256] = {
#include "rsbox.txt"
};

union Word {
    uint32_t w;
    uint8_t b[4];
};

union Block {
    __uint128_t i_128;
    uint32_t row[4];
    uint8_t cell[16];
    uint8_t cell_2d[4][4];
};

#define subW(x) sub_word((union Word)x)
uint32_t sub_word(union Word W)
{
    for (int i = 0; i < 4; i++)
        W.b[i] = s_box[W.b[i]];
    return W.w;
}

#define SWAP(a, b) (a) ^= (b), (b) ^= (a), (a) ^= (b)
void transpose4x4(uint8_t cell[16])
{
    for (int i = 0; i < 4; i++)
        for (int j = i+1; j < 4; j++)
            SWAP(cell[i*4+j], cell[j*4+i]);
}

#define ROTL(n, r) ((n >> r) | (n << (sizeof(n)*8 - r)))

// https://en.wikipedia.org/wiki/AES_key_schedule
void key_schedule_128(union Block *key, uint32_t W[44])
{
    const uint8_t N = 4;
    const uint8_t R = 11;
    const uint8_t rc[11] = {
         0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    memcpy(W, key, sizeof(union Block));

    uint8_t i = 4;
    while (i < 44) {
        W[i] = W[i-N] ^ (subW(ROTL(W[i-1], 8)) ^ rc[i/4]), ++i;
        W[i] = W[i-N] ^ W[i-1], ++i;
        W[i] = W[i-N] ^ W[i-1], ++i;
        W[i] = W[i-N] ^ W[i-1], ++i;
    }
}

void print_block(union Block *block)
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            printf("%x ", block->cell[i*4+j]);
        printf("\n");
    }
    printf("\n");
}

void sub_bytes(u_int8_t *cell)
{
    for (int i = 0; i < 16; i++)
        cell[i] = s_box[cell[i]];
}

void shift_rows(union Block *b)
{
    transpose4x4(b->cell);
    for (uint8_t i = 1; i < 4; i++)
        b->row[i] = ROTL(b->row[i], i*8);
    transpose4x4(b->cell);
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// Function is mostly from
// https://github.com/kokke/tiny-AES-c/blob/master/aes.c
static void mix_columns(uint8_t state[4][4])
{
  uint8_t Tmp, t;
  for (uint8_t i = 0; i < 4; ++i)
  {  
    t = state[i][0];
    Tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3] ;
    state[i][0] ^= xtime(state[i][0] ^ state[i][1]) ^ Tmp;
    state[i][1] ^= xtime(state[i][1] ^ state[i][2]) ^ Tmp;
    state[i][2] ^= xtime(state[i][2] ^ state[i][3]) ^ Tmp;
    state[i][3] ^= xtime(state[i][3] ^ t) ^ Tmp;
  }
}

union ex_Key {
    union Block block[11];
    uint8_t bytes[176];
    uint32_t words[44];
};

void add_round_key(union Block *text, union Block *key)
{
    for (uint8_t i = 0; i < 4; i++)
        text->row[i] ^= key->row[i];
}

void ecb_encrypt(union Block *text, union ex_Key *key)
{
    add_round_key(text, key->block);

    for (int i = 1; i < 11; i++) {
        sub_bytes(text->cell);
        shift_rows(text);
        if (i != 10)
            mix_columns(text->cell_2d);
        add_round_key(text, key->block + i);
    }
}

int main(int argc, char *argv[])
{
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a
    };

    union Block key = {
          .cell[0] = 0x2b,
          .cell[1] = 0x7e,
          .cell[2] = 0x15,
          .cell[3] = 0x16,
          .cell[4] = 0x28,
          .cell[5] = 0xae,
          .cell[6] = 0xd2,
          .cell[7] = 0xa6,
          .cell[8] = 0xab,
          .cell[9] = 0xf7,
          .cell[10] = 0x15,
          .cell[11] = 0x88,
          .cell[12] = 0x09,
          .cell[13] = 0xcf,
          .cell[14] = 0x4f,
          .cell[15] = 0x3c
      };

    printf("key block:\n0x");
    for (int i = 0; i < 16; i++)
        printf("%x", key.cell[i]);
    printf("\n\n");

    union ex_Key ex_key;

    key_schedule_128(&key, ex_key.words);

    printf("expanded key:\n0x");
    for (int i = 0; i < 176; i++)
        printf("%x", ex_key.bytes[i]);
    printf("\n\n");

    printf("plaintext block:\n0x");
    for (int i = 0; i < 16; i++)
        printf("%x", plaintext[i]);
    printf("\n\n");

    ecb_encrypt((union Block*)plaintext, &ex_key);

    printf("encrypted block:\n0x");
    for (int i = 0; i < 16; i++)
        printf("%x", plaintext[i]);
    printf("\n");
}

