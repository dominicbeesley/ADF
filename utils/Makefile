BASICTOOL=basictool --basic-2

BUILD=./build
HOSTFS=~/hostfs/adfsutils

UC = $(shell echo '$*' | tr '[:lower:]' '[:upper:]')

TARGETS=$(BUILD)/dumpadfs.tok
SSD=$(BUILD)/ADFUTIL.ssd

$(shell mkdir -p $(BUILD))

all: $(SSD)

hostfs: $(SSD)
	$(shell mkdir -p $(HOSTFS))
	dfs read -i -d $(HOSTFS) $(SSD)

$(SSD):$(TARGETS)
	dfs form -80 $(SSD)
	dfs add $(SSD) $(TARGETS)
	dfs opt4 -3 $(SSD)

$(BUILD)/%.tok:%.bbc
	basictool -t $< $@
	echo "\$$.$(call UC, $(basename $(notdir $@))) FFFF8023 FFFF8023" >$@.inf

clean:
	-rm $(BUILD)/*
