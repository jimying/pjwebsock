APP		   := test
ARCH       := $(shell uname -p)
BUILD      := obj
ifeq ($(ARCH), x86_64)
	PATH_3RD := thirdparty
else
	PATH_3RD := thirdparty.$(ARCH)
endif
CFLAGS := -Wall
CFLAGS += -DPJ_AUTOCONF
#CFLAGS += -DNDEBUG
CFLAGS += -g

INC = -I./ -I websock -I $(PATH_3RD)/pjsip/include
LIBS = \
	   $(PATH_3RD)/pjsip/lib/libpjlib-util.a \
	   $(PATH_3RD)/pjsip/lib/libpj.a
LIBS += -lm -pthread
#LIBS += -framework Cocoa
LIBS += -luuid
LIBS += -lgnutls

SRCS = main.c
SRCS += websock/websock.c
SRCS += websock/websock_transport.c
SRCS += websock/websock_transport_tcp.c
SRCS += websock/websock_transport_tls.c
OBJS = $(addprefix $(BUILD)/, $(addsuffix .o,$(basename $(SRCS))))

all: $(APP)
clean:
	@rm -rf $(APP) $(BUILD)

$(BUILD): Makefile
	@mkdir -p $(BUILD) $(BUILD)/websock

$(APP): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^  $(LIBS)

$(BUILD)/%.o: %.c Makefile | $(BUILD)
	$(CC) $(CFLAGS) $(INC) -c $< -o $@ $(DFLAGS)


