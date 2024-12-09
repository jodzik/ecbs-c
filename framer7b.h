#ifndef FRAMER7B
#define FRAMER7B

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

enum {
	FRAMER7B__DATA_SIZE = 4096,
	FRAMER7B__BUF_SIZE = FRAMER7B__DATA_SIZE + FRAMER7B__DATA_SIZE / 7 + 2
};

typedef struct Framer7b {
	uint8_t buf[FRAMER7B__BUF_SIZE];
	size_t bufptr;
	uint8_t state;
	uint8_t id;
} Framer7b;

int framer7b__push(Framer7b* framer, uint8_t byte);
int framer7b__make(Framer7b* framer, size_t ndata);
uint8_t* framer7b__get_packet_buf_to_make(Framer7b* framer);
uint8_t* framer7b__get_received_packet_buf(Framer7b* framer);
uint8_t const* framer7b__get_frame_buf_to_send(Framer7b const* framer);
void framer7b__reset(Framer7b* framer);

#ifdef __cplusplus
}
#endif

#endif // !FRAMER7B
