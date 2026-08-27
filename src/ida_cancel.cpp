#include <pro.h>
#include <kernwin.hpp>

extern "C" void ida_mcp_set_cancelled() { set_cancelled(); }

extern "C" void ida_mcp_clear_cancelled() { clr_cancelled(); }
