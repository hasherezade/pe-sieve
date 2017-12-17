#include "scanner.h"

#include <sstream>
#include <iomanip>

std::string make_module_path(MODULEENTRY32 &module_entry, std::string directory, bool is_dll)
{
    std::stringstream stream;
    stream << directory;
    stream << "\\";
    stream << std::hex << module_entry.modBaseAddr;
    if (is_dll) {
        stream << ".dll";
    } else {
        stream << ".exe";
    }
    return stream.str();
}