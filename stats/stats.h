#pragma once

#include "entropy.h"
#include "../utils/byte_buffer.h"

namespace pesieve {

    struct AreaStats {
        AreaStats()
            : area_size(0), area_start(0),
            entropy(0.0)
        {
        }

        // Copy constructor
        AreaStats(const AreaStats& p1)
            :  area_size(p1.area_size), area_start(p1.area_start),
            entropy(p1.entropy)
        {
        }

        const virtual bool toJSON(std::stringstream& outs, size_t level)
        {
            if (!isFilled()) {
                return false;
            }
            OUT_PADDED(outs, level, "\"stats\" : {\n");
            fieldsToJSON(outs, level + 1);
            outs << "\n";
            OUT_PADDED(outs, level, "}");
            return true;
        }

        bool isFilled() const
        {
            return area_size > 0 ? true : false;
        }

        double entropy;

    protected:

        const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
        {
            OUT_PADDED(outs, level, "\"area_start\" : ");
            outs << "\"" << std::hex << area_start << "\"";
            outs << ",\n";
            OUT_PADDED(outs, level, "\"area_size\" : ");
            outs << "\"" << std::hex << area_size << "\"";
            outs << ",\n";
            OUT_PADDED(outs, level, "\"entropy\" : ");
            outs << std::dec << entropy;
        }

        size_t area_size;
        size_t area_start;

        friend class AreaStatsCalculator;

    }; // AreaStats


    class AreaStatsCalculator {
    public:
        AreaStatsCalculator(const util::ByteBuffer& _buffer)
            : buffer(_buffer)
        {
        }

        bool fill(AreaStats& stats)
        {
            const bool skipPadding = true;
            const size_t data_size = buffer.getDataSize(skipPadding);
            const BYTE* data_buf = buffer.getData(skipPadding);
            if (!data_size || !data_buf) {
                return false;
            }
            stats.area_size = data_size;
            stats.area_start = buffer.getStartOffset(skipPadding);
            stats.entropy = util::ShannonEntropy(data_buf, data_size);
            return true;
        }

    private:
        const util::ByteBuffer& buffer;
    };

}; //pesieve
