#include "stats_analyzer.h"

#define ENTROPY_DATA_TRESHOLD 1.5
#define ENTROPY_CODE_TRESHOLD ENTROPY_DATA_TRESHOLD
#define ENTROPY_ENC_TRESHOLD 6.0
#define ENTROPY_STRONG_ENC_TRESHOLD 7.0
using namespace pesieve::util;


double getValRatio(IN const AreaStats<BYTE>& stats, BYTE val)
{
	auto val_itr = stats.currArea.histogram.find(val);
	double ratio = 0;
	if (val_itr != stats.currArea.histogram.end()) {
		ratio = ((double)val_itr->second / (double)stats.currArea.size);
		//std::cout << "Val : " << std::hex << (UINT) val << " RATIO: " << ratio << "\n";
	}
	return ratio;
}

double getPrintableRatio(IN const AreaStats<BYTE>& stats)
{
	if (!stats.currArea.size) return 0;
	size_t total_size = 0;
	for (auto itr = stats.currArea.histogram.begin(); itr != stats.currArea.histogram.end(); ++itr) {
		BYTE val = itr->first;
		size_t size = itr->second;

		if (IS_PRINTABLE(val)) {
			total_size += size;
		}
	}
	return (double)total_size / (double)stats.currArea.size;
}

size_t checkRatios(IN const AreaStats<BYTE>& stats, IN std::map<BYTE, double> &ratios)
{
	size_t points = 0;

	for (auto itr = ratios.begin(); itr != ratios.end(); ++itr) {
		if (getValRatio(stats, itr->first) >= itr->second) {
			points++;
		}
	}
	return points;
}

bool pesieve::util::isSuspicious(IN const AreaStats<BYTE>& stats, OUT AreaInfo& info)
{
	if (!stats.isFilled() || !stats.currArea.size) {
		return false;
	}

	const BYTE mFreqVal = util::getMostFrequentValue<BYTE>(stats.currArea.histogram);
	double entropy = stats.currArea.entropy;

	info.fullAreaObfuscated = (mFreqVal != 0 && entropy > ENTROPY_DATA_TRESHOLD); // possible XOR obfuscation, or block cipher
	info.fullAreaEncrypted = (entropy > ENTROPY_STRONG_ENC_TRESHOLD);// strong encryption
	if (mFreqVal != 0 && entropy > ENTROPY_ENC_TRESHOLD) {
		if (stats.currArea.frequencies.size() > 1) {
			auto fItr = stats.currArea.frequencies.begin(); // first one
			auto eItr = stats.currArea.frequencies.rbegin(); // last one
			// most common - least common ratio
			double diff = ((double)(eItr->first - fItr->first)) / (double)stats.currArea.size;
			//std::cout << "RATIO : " << fItr->first << " VS " << eItr->first << " DIFF: " << diff << "\n";
			if (diff < 0.01) {
				info.fullAreaEncrypted = true;
			}
		}
	}

	if (entropy > ENTROPY_CODE_TRESHOLD) { // possible code
		size_t codePoints = 0;
		std::map<BYTE, double> ratios;
		ratios[0x00] = 0.1;
		ratios[0xFF] = 0.02;
		ratios[0x8B] = 0.02;
		ratios[0xCC] = 0.01;
		ratios[0x48] = 0.02;
		ratios[0xE8] = 0.01;
		ratios[0x0F] = 0.01;

		codePoints += checkRatios(stats, ratios);
		//std::cout << "---->>> CODE points: " << codePoints << "\n";
		if (codePoints >= (ratios.size() / 2 + 1)) {
			info.possibleCode = true;
		}
	}

	const double printRatio = getPrintableRatio(stats);
	if (printRatio > 0.8) {
		info.possibleText = true;
		info.fullAreaObfuscated = false;
	}
	//std::cout << "PRINT RATIO : " << std::dec << printRatio << "\n";
	const bool isEnc = (info.fullAreaEncrypted) ||
		info.fullAreaObfuscated || info.possibleCode;
	return isEnc;
}
