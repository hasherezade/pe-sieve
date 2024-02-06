#pragma once
#include <stdint.h>

namespace pesieve {
	namespace util {
		
		// from: https://gist.github.com/timepp/1f678e200d9e0f2a043a9ec6b3690635

		struct CRC32_s
		{
			void generate_table(uint32_t(&table)[256])
			{
				uint32_t polynomial = 0xEDB88320;
				for (uint32_t i = 0; i < 256; i++)
				{
					uint32_t c = i;
					for (size_t j = 0; j < 8; j++)
					{
						if (c & 1) {
							c = polynomial ^ (c >> 1);
						}
						else {
							c >>= 1;
						}
					}
					table[i] = c;
				}
			}

			uint32_t update(uint32_t(&table)[256], uint32_t initial, const void* buf, size_t len)
			{
				uint32_t c = initial ^ 0xFFFFFFFF;
				const uint8_t* u = static_cast<const uint8_t*>(buf);
				for (size_t i = 0; i < len; ++i)
				{
					c = table[(c ^ u[i]) & 0xFF] ^ (c >> 8);
				}
				return c ^ 0xFFFFFFFF;
			}
		};

		class CRC32
		{
		private:
			uint32_t table[256];
			CRC32_s crc32_s;
			uint32_t initial;
		public:
			CRC32()
				: initial(0)
			{
				crc32_s.generate_table(table);
			}

			void Update(const void* buf, size_t len)
			{
				initial = crc32_s.update(table, initial, (const void*)buf, len);
			}

			uint32_t GetValue() const
			{
				return initial;
			}
		};


		inline int calcCRC32(const void* data, size_t dataSize)
		{
			util::CRC32 crc;
			crc.Update(data, dataSize);
			return crc.GetValue();
		}

	}; // namespace util


};
