#pragma once
#include <windows.h>

namespace pesieve {

    namespace util {

        struct BasicBuffer
        {
        public:
            BasicBuffer()
                : data(nullptr), data_size(0),
                real_start(0), real_end(0), padding(0)
            {
            }

            bool isFilled()
            {
                if (data) {
                    return true; // already filled
                }
                return false;
            }

            void trim()
            {
                if (!data) return;

                real_start = 0;
                real_end = 0;
                padding = 0;
                for (size_t i = 0; i < data_size; i++, padding++) {
                    if (data[i] != 0) {
                        real_start = i;
                        break;
                    }
                }

                for (size_t i = data_size; i != 0; i--, padding++) {
                    if (data[i - 1] != 0) {
                        real_end = i;
                        break;
                    }
                }
            }

            size_t getDataSize(bool trimmed = false)
            {
                if (!data || !data_size) return 0;

                if (trimmed && (padding < data_size)) {
                    return data_size - padding;
                }
                return data_size;
            }

            const BYTE* getData(bool trimmed = false)
            {
                if (!data || !data_size) return nullptr;

                if (trimmed && (padding < data_size)) {
                    return (data + real_start);
                }
                return data;
            }

            BYTE* data;

            size_t real_start;
            size_t real_end;
            size_t padding;

        protected:
            size_t data_size;
        };

    }; // namespace util

}; // namespace pesieve

