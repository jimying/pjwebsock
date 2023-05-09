APP   := test
XOS   := $(shell uname)
BUILD := obj

CFLAGS ?= -Wall
CFLAGS += -Wextra
#CFLAGS += -Wunused-but-set-variable
#CFLAGS += -Wcast-function-type
#CFLAGS += -Wsingle-bit-bitfield-constant-conversion
#CFLAGS += -DNDEBUG

CFLAGS += -I ./ -I ./websock
CFLAGS += `pkg-config --cflags libpjproject`

LIBS = `pkg-config --libs libpjproject`
LIBS += -lm -pthread

ifeq ($(XOS), Linux)
	LIBS += -luuid
	#LIBS += -lgnutls
	#LIBS += -lcrypto -lssl
else ifeq ($(XOS), Darwin)
	LIBS += -framework Cocoa
else ifeq ($(XOS), OpenBSD)
	LIBS += -lcrypto -lssl
endif


SRCS = tests/test.c
SRCS += websock/websock.c
SRCS += websock/websock_transport.c
SRCS += websock/websock_transport_tcp.c
SRCS += websock/websock_transport_tls.c
SRCS += websock/http.c
OBJS = $(addprefix $(BUILD)/, $(addsuffix .o,$(basename $(SRCS))))

all: $(APP)
clean:
	@rm -rf $(APP) $(BUILD)

$(BUILD): Makefile
	@mkdir -p $(BUILD)/tests $(BUILD)/websock

$(APP): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^  $(LIBS)

$(BUILD)/%.o: %.c Makefile | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)


