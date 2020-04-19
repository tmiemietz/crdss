#
# Makefile for the crdss project.
#

# unfortunately, we can not use the one and only C (89) due to RDMA libraries
CFLAGS := -Wall -Wextra -Werror -O2 -fPIC

SRCDIR := src
OBJDIR := obj
INCDIR := src/include

TGTDIR := bin
TGTS   := crdss-srv crdss-capmgr libcrdss testclt crdss-srv-dummy crdss-srv-nocap gap_read gap_read_cap sqlite_bench sqlite_setup crdss-cp crdss-rd

LIBS   := -lpthread -lsodium -libverbs -ldl -lm

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
	$(CC) -pedantic -o $(TGTDIR)/$@ $^ $(LIBS)

crdss-srv-nocap: obj/crdss-srv-nocap.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ $^ $(LIBS)

crdss-srv-dummy: obj/crdss-srv-dummy.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ $^ $(LIBS)

crdss-capmgr: obj/crdss-capmgr.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ $^ $(LIBS)

testclt: obj/testclt.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ -Llib $^ $(LIBS) -lcrdss

gap_read: obj/gap_read.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ $^ $(LIBS)

crdss-cp: obj/crdss-cp.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ $^ $(LIBS)

crdss-rd: obj/crdss-rd.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ $^ $(LIBS)

sqlite_bench: obj/sqlite_bench.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ $^ $(LIBS) -lsqlite3

sqlite_setup: obj/sqlite_setup.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ $^ $(LIBS) -lsqlite3

gap_read_cap: obj/gap_read_cap.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -pedantic -o $(TGTDIR)/$@ -Llib $^ $(LIBS) -lcrdss

libcrdss: obj/libcrdss.o $(filter-out $(TGTOBJS), $(OBJECTS))
	@echo "Linking $@..."
	$(CC) -shared -o lib/$@.so $^ $(LIBS)

$(OBJDIR)/%.o: $(SOURCES) $(HEADERS)
	@echo "Building object file $@..."
	$(CC) -c $(CFLAGS) -o $@ $(subst $(OBJDIR), $(SRCDIR), $(@:.o=.c))

.PHONY: clean

clean:
	rm -f $(OBJECTS)
	rm -f $(wildcard $(TGTDIR)/*)
	rm -f lib/*
