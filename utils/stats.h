#pragma once

#include <map>

namespace pesieve {

    namespace util {

        struct AreaStats {
            AreaStats() 
                : entropy(0)
            {
            }

            double entropy;
        };

        template <typename T>
        class AreaStatsCalculator {
        public:
            AreaStatsCalculator(T _data[], size_t _elements)
                :data(_data), elements(_elements)
            {
            }

            bool fill()
            {
                if (!data || !elements) return false;

                stats.entropy = 0; // Shannon's Entropy calculation based on: https://stackoverflow.com/questions/20965960/shannon-entropy
                std::map<T, size_t> counts;
                typename std::map<T, size_t>::iterator it;
                //
                for (size_t dataIndex = 0; dataIndex < elements; ++dataIndex) {
                    const T val = data[dataIndex];
                    counts[val]++;
                }
                //
                for (it = counts.begin(); it != counts.end(); ++it) {
                    double p_x = (double)it->second / elements;
                    if (p_x > 0) stats.entropy -= p_x * log(p_x) / log(2);
                }
                return true;
            }

            AreaStats stats;

        private:
            T *data;
            size_t  elements;
        };

    }; // namespace util

}; //namespace pesieve

