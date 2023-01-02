#pragma once

#include <map>
namespace pesieve {

    namespace util {

        // from: https://stackoverflow.com/questions/20965960/shannon-entropy
        template <typename T> static float ShannonEntropy(T data[], size_t elements)
        {
            float entropy = 0;
            std::map<T, long> counts;
            typename std::map<T, long>::iterator it;
            //
            for (int dataIndex = 0; dataIndex < elements; ++dataIndex) {
                counts[data[dataIndex]]++;
            }
            //
            it = counts.begin();
            while (it != counts.end()) {
                float p_x = (float)it->second / elements;
                if (p_x > 0) entropy -= (p_x * log(p_x)) / log(2);
                it++;
            }
            return entropy;
        }

    }; // namespace util

}; //namespace pesieve

