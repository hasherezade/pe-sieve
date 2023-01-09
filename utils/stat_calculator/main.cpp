#include <windows.h>
#include <iostream>

#define _KEEP_STR
#include "../stats.h"
#include "../stats_analyzer.h"

using namespace pesieve::util;

struct Buffer
{
    Buffer()
        : data(nullptr), data_size(0) {}

    bool load(char* filename)
    {
        if (data) {
            return false; // already filled
        }
        FILE* fp = fopen(filename, "rb");
        if (!fp) return false;

        fseek(fp, 0, SEEK_END);
        size_t file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        data = (BYTE*)calloc(file_size, sizeof(BYTE));
        if (data) {
            data_size = fread(data, sizeof(BYTE), file_size, fp);
        }
        fclose(fp);
        if (data_size) {
            return true;
        }
        return false;
    }

    BYTE* data;
    size_t data_size;
};


void printHistogram(ChunkStats<BYTE> currArea, std::stringstream& outs)
{
    for (auto itr = currArea.histogram.begin(); itr != currArea.histogram.end(); ++itr) {
        outs << std::hex << std::setfill('0') << std::setw(2) << (UINT)itr->first
            << " : " << IS_PRINTABLE(itr->first)
            << " : " << std::dec << std::setfill(' ') << std::setw(5) << itr->second
            << " : " << (double)itr->second / (double)currArea.size << "\n";
    }
}

void printStrings(ChunkStats<BYTE> currArea, std::stringstream& outs)
{
#ifdef _KEEP_STR
    outs << "Strings: "  << currArea.allStrings.size() << "\n";
    for (auto itr = currArea.allStrings.begin(); itr != currArea.allStrings.end(); ++itr) {
        const std::string str = *itr;
        outs << str << "\n";
    }
#endif
}

int main(size_t argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "Supply a file to be analyzed!\n";
        return 0;
    }
    Buffer buf;
    if (!buf.load(argv[1])) {
        std::cout << "Failed loading the file!\n";
        return 0;
    }

    std::cout << "Ready!\n";

    AreaStats<BYTE> stats;
    AreaStatsCalculator<BYTE> calc(buf.data, buf.data_size);
    if (calc.fill(stats)) {
        std::cout << "Stats filled!\n";
    }
    std::stringstream outs;
    stats.toJSON(outs, 0);
    outs << "---\n";
    printHistogram(stats.currArea, outs);

    outs << "---\n";
    printStrings(stats.currArea, outs);
    outs << "---\n";

    std::cout << outs.str();
    return 0;
}
