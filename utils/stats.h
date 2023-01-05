#pragma once

#include <map>
namespace pesieve {

    namespace util {

        // from: https://stackoverflow.com/questions/20965960/shannon-entropy
        template <typename T> static float ShannonEntropy(T data[], size_t elements)
        {
            double entropy = 0;
            std::map<T, size_t> counts;
            typename std::map<T, size_t>::iterator it;
            //
            for (size_t dataIndex = 0; dataIndex < elements; ++dataIndex) {
                const T val = data[dataIndex];
                counts[val]++;
            }
            if (!elements) return 0;
            //
            for (it = counts.begin(); it != counts.end(); ++it) {
                double p_x = (double)it->second / elements;
                if (p_x > 0) entropy -= p_x * log(p_x) / log(2);
            }
            return entropy;
        }

    }; // namespace util

}; //namespace pesieve

