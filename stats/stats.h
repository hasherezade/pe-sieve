#pragma once

#include <windows.h>
#include <sstream>

#include "entropy.h"
#include "../utils/byte_buffer.h"
#include "../utils/format_util.h"

namespace pesieve {

	//! Base class for settings defining what type of stats should be collected.
	struct StatsSettings {
	public:
		StatsSettings() {}
		virtual bool isFilled() = 0;
	};

	//! Base class for the statistics from analyzed buffer.
	class AreaStats {
	public:
		AreaStats()
			: area_start(0), area_size(0)
		{
		}

		void setStartOffset(size_t _area_start)
		{
			area_start = _area_start;
		}

		void appendVal(BYTE val)
		{
			_appendVal(val);
			area_size++;
		}

		const virtual void fieldsToJSON(std::stringstream& outs, size_t level) = 0;

		bool isFilled() const
		{
			return area_size > 0 ? true : false;
		}

		virtual void summarize() = 0;

		virtual bool fillSettings(StatsSettings* _settings) { return false; }

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

	protected:
		virtual void _appendVal(BYTE val) = 0;

		size_t area_size;
		size_t area_start;

		friend class AreaStatsCalculator;

	}; // AreaStats


	//! A class responsible for filling in the statistics with the data from the particular buffer.
	class AreaStatsCalculator {
	public:
		AreaStatsCalculator(const util::ByteBuffer& _buffer)
			: buffer(_buffer)
		{
		}

		bool fill(AreaStats& stats, StatsSettings* settings)
		{
			const bool skipPadding = true;
			const size_t data_size = buffer.getDataSize(skipPadding);
			const BYTE* data_buf = buffer.getData(skipPadding);
			if (!data_size || !data_buf) {
				return false;
			}
			if (settings && !stats.fillSettings(settings)) {
				std::cerr << "Settings initialization failed!\n";
			}
			stats.setStartOffset(buffer.getStartOffset(skipPadding));
			BYTE lastVal = 0;
			for (size_t i = 0; i < data_size; ++i) {
				const BYTE val = data_buf[i];
				stats.appendVal(val);
			}
			stats.summarize();
			return true;
		}

	private:
		const util::ByteBuffer& buffer;
	};

}; //pesieve
