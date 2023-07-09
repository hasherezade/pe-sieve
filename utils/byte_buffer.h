#pragma once
#include <windows.h>
#include <peconv.h>

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
            
            size_t getStartOffset(bool trimmed) const
            {
                if (!trimmed) return 0;
                if (!data || real_start >= data_size) return 0;
                return real_start;
            }

            size_t getDataSize(bool trimmed = false) const
            {
                if (!data || !data_size) return 0;

                if (trimmed && (padding < data_size)) {
                    return data_size - padding;
                }
                return data_size;
            }

            const BYTE* getData(bool trimmed = false) const
            {
                if (!data || !data_size) return nullptr;

                if (trimmed && (padding < data_size)) {
                    return (data + real_start);
                }
                return data;
            }

            BYTE* data;

        protected:

            size_t real_start;
            size_t real_end;
            size_t padding;

            size_t data_size;
        };

        //---

        struct ByteBuffer : public BasicBuffer
        {
            ByteBuffer()
                : BasicBuffer()
            {
            }

            // Copy constructor
            ByteBuffer(const ByteBuffer& p1)
                : BasicBuffer()
            {
                copy(p1);
            }

            ~ByteBuffer()
            {
                freeBuffer();
            }

            virtual ByteBuffer& operator=(const ByteBuffer&p1) {
                this->copy(p1);
                return *this;
            }

            bool isValidPtr(BYTE * field_bgn, size_t field_size)
            {
                return peconv::validate_ptr(this->data, this->data_size, field_bgn, field_size);
            }

            bool isDataContained(const BYTE* rawData, size_t r_size)
            {
                size_t smaller_size = data_size > r_size ? r_size : data_size;
                if (::memcmp(data, rawData, smaller_size) == 0) {
                    return true;
                }
                return false;
            }

            bool allocBuffer(size_t size)
            {
                freeBuffer();
                data = peconv::alloc_aligned(size, PAGE_READWRITE);
                if (data == nullptr) {
                    return false;
                }
                data_size = size;
                padding = 0;
                return true;
            }

            void freeBuffer()
            {
                if (!data) {
                    data_size = 0;
                    padding = 0;
                    return;
                }
                peconv::free_aligned(data, data_size);
                data = nullptr;
                data_size = 0;
                padding = 0;
            }

        protected:

            bool copy(const ByteBuffer& p1)
            {
                if (!allocBuffer(p1.data_size)) {
                    return false;
                }
                ::memcpy(this->data, p1.data, this->data_size);
                this->real_start = p1.real_start;
                this->real_end = p1.real_end;
                this->padding = p1.padding;
                return true;
            }

        };

    }; // namespace util

}; // namespace pesieve

