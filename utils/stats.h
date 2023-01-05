#pragma once

#include <map>
#include "format_util.h"

namespace pesieve {

    namespace util {

        // Shannon's Entropy calculation based on: https://stackoverflow.com/questions/20965960/shannon-entropy
        template <typename T>
        double calcShannonEntropy(std::map<T, size_t>& histogram, size_t totalSize)
        {
            if (!totalSize) return 0;
            double entropy = 0;
            for (auto it = histogram.begin(); it != histogram.end(); ++it) {
                double p_x = (double)it->second / totalSize;
                if (p_x > 0) entropy -= p_x * log(p_x) / log(2);
            }
            return entropy;
        }

        template <typename T>
        std::string hexdumpValue(const BYTE* in_buf, const size_t max_size)
        {
            std::stringstream ss;
            for (size_t i = 0; i < max_size; i++) {
                ss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)in_buf[i];
            }
            return ss.str();
        }

        template <typename T>
        T getMostFrequentValue(std::map<T, size_t>& histogram)
        {
            T mVal = 0;
            size_t mFreq = 0;
            for (auto itr = histogram.begin(); itr != histogram.end(); ++itr) {
                if (itr->second > mFreq) {
                    mFreq = itr->second;
                    mVal = itr->first;
                }
            }
            return mVal;
        }

        template <typename T>
        struct ChunkStats {
            //
            ChunkStats() 
                : size(0), offset(0)
            {
            }

            // Copy constructor
            ChunkStats(const ChunkStats& p1)
                : size(p1.size), offset(p1.offset), histogram(p.histogram.begin(), p.histogram.end())
            {
            }

            ChunkStats(size_t _size, size_t _offset)
                : size(_size), offset(_offset)
            {
            }

            void append(T val)
            {
                size++;
                histogram[val]++;
            }

            const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"offset\" : ");
                outs << std::hex << "\"" << offset << "\"";
                outs << ",\n";
                OUT_PADDED(outs, level, "\"size\" : ");
                outs << std::hex << "\"" << size << "\"";
                
                T mVal = getMostFrequentValue(histogram);
                if (mVal) {
                    outs << ",\n";
                    OUT_PADDED(outs, level, "\"most_freq_val\" : ");
                    outs << std::hex << "\"" << hexdumpValue<BYTE>((BYTE*)&mVal, sizeof(T)) << "\"";
                }
                outs << ",\n";
                OUT_PADDED(outs, level, "\"entropy\" : ");
                outs << std::dec << calcShannonEntropy(histogram, size);
            }


            size_t size;
            size_t offset;
            T lastVal;
            std::map<T, size_t> histogram;
        };

        template <typename T>
        struct AreaStats {
            AreaStats() 
                : entropy(0)
            {
            }

            // Copy constructor
            AreaStats(const AreaStats& p1)
                : entropy(p1.entropy), biggestChunk(p1.biggestChunk)
            {
            }

            const virtual bool toJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"stats\" : {\n");
                fieldsToJSON(outs, level + 1);
                outs << "\n";
                OUT_PADDED(outs, level, "}");
                return true;
            }

            const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"entropy\" : ");
                outs << std::dec << entropy;
                outs << ",\n";
                OUT_PADDED(outs, level, "\"most_freq_val\" : ");
                outs << std::hex << "\"" << hexdumpValue<BYTE>((BYTE*)&mostFreq, sizeof(T)) << "\"";
                outs << ",\n";
                // print chunk stats
                OUT_PADDED(outs, level, "\"biggest_chunk\" : {\n");
                biggestChunk.fieldsToJSON(outs, level + 1);
                outs << "\n";
                OUT_PADDED(outs, level, "}");
            }

            bool isFilled()
            {
                return (entropy && biggestChunk.size);
            }

            double entropy;
            T mostFreq;
            ChunkStats<T> biggestChunk;//< biggest continuous chunk (not interrupted by a defined delimiter)
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

                const T kDelim = 0; // delimiter of continuous chunks
                ChunkStats<T> currArea(0, elements); //stats for the full area
                stats.biggestChunk = ChunkStats<T>();
                stats.entropy = 0;
                //
                ChunkStats<T> currChunk;
                T lastVal = 0;
                for (size_t dataIndex = 0; dataIndex < elements; ++dataIndex) {
                    const T val = data[dataIndex];
                    if (val == kDelim) {
                        if (currChunk.size > stats.biggestChunk.size) { // delimiter found, finish the chunk
                            stats.biggestChunk = currChunk;
                        }
                        currChunk = ChunkStats<T>(0, dataIndex);
                    }
                    if (lastVal == kDelim && val != kDelim) {
                        // start a new chunk
                        currChunk = ChunkStats<T>(0, dataIndex);
                    }
                    currArea.append(val);
                    currChunk.append(val);
                    lastVal = val;
                }
                //
                stats.mostFreq = getMostFrequentValue(currArea.histogram);
                stats.entropy = calcShannonEntropy(currArea.histogram, currArea.size);
                return true;
            }

            AreaStats<T> stats;

        private:
            T *data;
            size_t  elements;
        };

    }; // namespace util

}; //namespace pesieve

