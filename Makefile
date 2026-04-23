# Insider Threat Agent — MinGW Build
#
# Prerequisites:
#   MinGW-w64 with gcc in PATH
#   Windows SDK headers (usually bundled with MinGW-w64)
#
# Usage:
#   make          — build agent.exe
#   make clean    — remove agent.exe
#   make run      — build and launch agent.exe (no console window, use DebugView to see output)

# Requires MSYS2 MinGW-w64 gcc in PATH (the gcc that ships with MSYS2, not MinGW.org).
# Run make from PowerShell or MSYS2 terminal where `gcc --version` shows "MSYS2 project".
CC      = gcc
TARGET  = agent.exe
SRC     = agent.c

CFLAGS  = -Wall -Wextra -O2 \
          -mwindows \
          -DUNICODE \
          -D_UNICODE \
          -D_WIN32_WINNT=0x0600 \
          -DWIN32_LEAN_AND_MEAN

# Library link order matters in MinGW one-pass linker.
# winhttp and iphlpapi depend on kernel32/ws2_32; list them before.
LDFLAGS = -lwinhttp \
          -liphlpapi \
          -lgdi32 \
          -luser32 \
          -lkernel32 \
          -lole32 \
          -ladvapi32 \
          -lws2_32

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

# --- Optional install targets (commented out for safety) ---
# install: $(TARGET)
# 	cp $(TARGET) /c/Windows/System32/$(TARGET)
#
# install-service: $(TARGET)
# 	sc create SystemHealthMonitor binPath="$(CURDIR)/$(TARGET)" start=auto
# 	sc start SystemHealthMonitor

.PHONY: clean run
