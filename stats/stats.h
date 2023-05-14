#pragma once

#include "entropy.h"

namespace pesieve {

    struct AreaStats {
        AreaStats()
            : area_size(0), entropy(0.0)
        {
        }

        // Copy constructor
        AreaStats(const AreaStats& p1)
            : entropy(p1.entropy), area_size(p1.area_size)
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
        size_t area_size;

    protected:

        const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
        {
            OUT_PADDED(outs, level, "\"area_size\" : ");
            outs << "\"" << std::hex << area_size << "\"";
            outs << ",\n";
            OUT_PADDED(outs, level, "\"entropy\" : ");
            outs << std::dec << entropy;
        }
    }; // AreaStats


    class AreaStatsCalculator {
    public:
        AreaStatsCalculator(BYTE _data[], size_t _elements)
            :data(_data), elements(_elements)
        {
        }

        bool fill(AreaStats& stats)
        {
            if (!data || !elements) return false;
            stats.area_size = elements;
            stats.entropy = util::ShannonEntropy(data, elements);
            return true;
        }

    private:
        BYTE* data;
        size_t  elements;
    };

}; //pesieve
