#include "dbg_help_wrapper.h"

std::mutex DbgHelpWrapper::m_Mutex;
std::unordered_map< HANDLE, DbgHelpWrapper::SessionInfo> DbgHelpWrapper::sessions;
