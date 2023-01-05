#pragma once

#include <map>
#include "format_util.h"

namespace pesieve {

    namespace util {


        template <typename T>
        struct ChunkStats {

            static std::string hexdump(const BYTE* in_buf, const size_t max_size)
            {
                std::stringstream ss;
                for (size_t i = 0; i < max_size; i++) {
                    ss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)in_buf[i];
                }
                return ss.str();
            }
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
                
                T mVal = getMostFrequentValue();
                if (mVal) {
                    outs << ",\n";
                    OUT_PADDED(outs, level, "\"most_freq_val\" : ");
                    outs << std::hex << "\"" << hexdump((BYTE*)&mVal, sizeof(T)) << "\"";
                }
                
            }

            T getMostFrequentValue()
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
                stats.biggestChunk = ChunkStats<T>();
                stats.entropy = 0; // Shannon's Entropy calculation based on: https://stackoverflow.com/questions/20965960/shannon-entropy
                std::map<T, size_t> counts;
                typename std::map<T, size_t>::iterator it;
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
                    currChunk.append(val);
                    counts[val]++;
                    lastVal = val;
                }
                //
                for (it = counts.begin(); it != counts.end(); ++it) {
                    double p_x = (double)it->second / elements;
                    if (p_x > 0) stats.entropy -= p_x * log(p_x) / log(2);
                }
                return true;
            }

            AreaStats<T> stats;

        private:
            T *data;
            size_t  elements;
        };

    }; // namespace util

}; //namespace pesieve

