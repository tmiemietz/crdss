#
# Makefile for the crdss project.
#

# unfortunately, we can not use the one and only C (89) due to RDMA libraries
CFLAGS := -Wall -Wextra -Werror -pedantic -O2 -fPIC

SRCDIR := src
OBJDIR := obj
INCDIR := src/include

TGTDIR := bin
TGTS   := crdss-srv crdss-capmgr libcrdss testclt

LIBS   := -lpthread -lsodium -libverbs

#
# Actual commands below
#

SOURCES := $(shell find $(SRCDIR) -name *.c -type f)
HEADERS := $(shell find $(INCDIR) -name *.h -type f)
OBJECTS := $(subst $(SRCDIR),$(OBJDIR),$(SOURCES:.c=.o))
TGTOBJS := $(addprefix $(OBJDIR)/, $(addsuffix .o, $(TGTS)))

all: $(TGTS)

crdss-srv: obj/crdss-srv.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -o $(TGTDIR)/$@ $^ $(LIBS)

crdss-capmgr: obj/crdss-capmgr.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -o $(TGTDIR)/$@ $^ $(LIBS)

testclt: obj/testclt.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -o $(TGTDIR)/$@ -Llib $^ $(LIBS) -lcrdss

libcrdss: obj/libcrdss.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -shared -o lib/$@.so $^

$(OBJDIR)/%.o: $(SOURCES) $(HEADERS)
	@echo "Building object file $@..."
	$(CC) -c $(CFLAGS) -o $@ $(subst $(OBJDIR), $(SRCDIR), $(@:.o=.c))

.PHONY: clean

clean:
	rm -f $(OBJECTS)
	rm -f $(wildcard $(TGTDIR)/*)
