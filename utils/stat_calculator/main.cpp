#include <windows.h>
#include <iostream>

#define _KEEP_STR
#include "../stats.h"
#include "../stats_analyzer.h"
#include "../basic_buffer.h"

using namespace pesieve::util;

struct FileBuffer : public BasicBuffer
{
    FileBuffer()
        : BasicBuffer()
    {
    }

    ~FileBuffer()
    {
        if (this->isFilled()) {
            free(data);
            data = nullptr;
            data_size = 0;
        }
    }

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
        //TODO: different alloc
        data = (BYTE*)calloc(file_size, sizeof(BYTE));
        if (data) {
            data_size = fread(data, sizeof(BYTE), file_size, fp);
        }
        fclose(fp);
        trim();
        if (data_size) {
            return true;
        }
        return false;
    }


};

void printHistogram(ChunkStats<BYTE> &currArea, std::stringstream& outs)
{
    if (!currArea.size) return;

    outs << "Counts:\n";
    for (auto itr = currArea.histogram.begin(); itr != currArea.histogram.end(); ++itr) {
        outs << std::hex << std::setfill('0') << std::setw(2) << (UINT)itr->first
            << " : " << IS_PRINTABLE(itr->first)
            << " : " << std::dec << std::setfill(' ') << std::setw(5) << itr->second
            << " : " << (double)itr->second / (double)currArea.size << "\n";
    }
}


void printFrequencies(ChunkStats<BYTE>& currArea, std::stringstream& outs)
{
    if (!currArea.size) return;

    size_t max = 10;
    outs << "Top "<< max <<" Frequencies:\n";
    size_t i = 0;
    for (auto itr1 = currArea.frequencies.rbegin(); itr1 != currArea.frequencies.rend() && i < max; ++itr1, ++i) {
        std::set<BYTE> vals = itr1->second;
        size_t counter = itr1->first;
        for (auto itr2 = vals.begin(); itr2 != vals.end(); ++itr2) {
            const BYTE val = *itr2;
            outs << std::hex << std::setfill('0') << std::setw(2) << (UINT)val
                << " : " << IS_PRINTABLE(val)
                << " : " << std::dec << std::setfill(' ') << std::setw(5) << counter
                << " : " << (double)counter / (double)currArea.size << "\n";
        }
    }
}

void printStrings(ChunkStats<BYTE> &currArea, std::stringstream& outs)
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
    FileBuffer buf;
    if (!buf.load(argv[1])) {
        std::cout << "Failed loading the file!\n";
        return 0;
    }
    
    std::cout << "Ready!\n";
    AreaStats<BYTE> stats;
    AreaStatsCalculator<BYTE> calc((BYTE*)buf.getData(true), buf.getDataSize(true));
    if (calc.fill(stats)) {
        std::cout << "Stats filled!\n";
    }
    std::stringstream outs;
    stats.toJSON(outs, 0);
    outs << "---\n";
    printHistogram(stats.currArea, outs);
    outs << "\n---\n";

    printFrequencies(stats.currArea, outs);
    outs << "\n---\n";
    printStrings(stats.currArea, outs);
    outs << "\n---\n";

    AreaInfo info;
    if (isSuspicious(stats, info)) {
        outs << "Suspicious!\n";
    }
    else {
        outs << "NOT Suspicious!\n";
    }
    info.toJSON(outs, 0);
    outs << "---\n";
    std::cout << outs.str();
    std::cout << "Distinct frequencies: " << stats.currArea.frequencies.size() << "\n";
    std::cout << "Real start: " << buf.real_start << "\n";
    std::cout << "Real end: " << buf.real_end << "\n";
    std::cout << "Padding: " << buf.padding << " = 0x" << std::hex << buf.padding << "\n";
    return 0;
}
