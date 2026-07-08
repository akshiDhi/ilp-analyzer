# ============================================================
# Makefile for ILP Tracer PinTool
# ============================================================
# Usage:
#   make PIN_ROOT=/path/to/pin
#
# The PIN_ROOT must point to the extracted Intel PinKit directory.
# Example: PIN_ROOT=/opt/pin-3.31-98869-g71afcc22e-gcc-linux

ifndef PIN_ROOT
    $(error PIN_ROOT is not set. Usage: make PIN_ROOT=/path/to/pin)
endif

# ---- Pin kit configuration ----
PIN_KIT       := $(PIN_ROOT)
CONFIG_ROOT   := $(PIN_KIT)/source/tools/Config
TOOL_ROOTS := ilp_tracer
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

# ---- Compiler flags ----
TOOL_CXXFLAGS += -std=c++17 -Wall -Wextra -Wno-error -Wno-cast-function-type -Wno-unused-parameter -O2


# ---- Object files ----
ilp_tracer$(PINTOOL_SUFFIX): ilp_tracer$(OBJ_SUFFIX)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $< $(TOOL_LPATHS) $(TOOL_LIBS)

ilp_tracer$(OBJ_SUFFIX): ilp_tracer.cpp
	$(CXX) $(TOOL_CXXFLAGS) $(COMP_OBJ)$@ $<

.PHONY: clean
clean:
	rm -f *.o *.so *.dylib *.dll

.PHONY: help
help:
	@echo "ILP Tracer PinTool Build"
	@echo "Usage: make PIN_ROOT=/path/to/pin"
	@echo ""
	@echo "After build, run with:"
	@echo "  \$$(PIN_ROOT)/pin -t ilp_tracer.so -o trace.out -- ./target_binary"
