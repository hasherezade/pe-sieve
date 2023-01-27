#include "stats_analyzer.h"

#include "std_dev_calc.h"

#define ENTROPY_DATA_TRESHOLD 3.0
#define ENTROPY_CODE_TRESHOLD ENTROPY_DATA_TRESHOLD
#define ENTROPY_ENC_TRESHOLD 6.0
#define ENTROPY_STRONG_ENC_TRESHOLD 7.0

#define CHARSET_SIZE 0xFF

//#define DISPLAY_STATS
using namespace pesieve::stats;

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
		BYTE val = itr->first;
		double currRatio = getValRatio(stats, val);
		if (currRatio >= itr->second) {
#ifdef DISPLAY_STATS
			std::cout << "[+] OK " << std::hex << (UINT)val <<  std::dec << " : " << currRatio << "\n";
#endif
			points++;
		}
	}
	return points;
}

size_t countFoundStrings(IN const AreaStats<BYTE>& stats, IN std::set<std::string> neededStrings, IN size_t minOccurrence)
{
	size_t totalCount = 0;
	if (!stats.currArea.foundStrings.size()) {
		return 0;
	}
	for (auto itr = neededStrings.begin(); itr != neededStrings.end(); ++itr)
	{
		const std::string& codeStr = *itr;
		auto found = stats.currArea.foundStrings.find(codeStr);
		if (found == stats.currArea.foundStrings.end()) {
			continue;
		}
		size_t currCount = found->second;
		if (currCount >= minOccurrence) {
			totalCount++;
		}
	}
	return totalCount;
}

size_t fetchPeakValues(IN const ChunkStats<BYTE>& currArea, IN double stdDev, OUT std::set<BYTE>& peaks)
{
	if (!currArea.size) return 0;

	size_t peaksCount = 0;
	size_t peakVal = currArea.frequencies.rbegin()->first;
	size_t i = 0;
	for (auto itr1 = currArea.frequencies.rbegin(); itr1 != currArea.frequencies.rend(); ++itr1, ++i) {
		size_t counter = itr1->first;
		double diff = (double)peakVal - (double)counter;
		if (diff > (3 * stdDev)) break;

		std::set<BYTE> vals = itr1->second;
		peaksCount += vals.size();
		peaks.insert(vals.begin(), vals.end());
	}
	return peaksCount;
}

size_t pesieve::stats::valuesNotBelowMean(IN const ChunkStats<BYTE>& currArea, double mean)
{
	size_t valsCount = 0;
	for (auto itr1 = currArea.frequencies.rbegin(); itr1 != currArea.frequencies.rend(); ++itr1) {
		double counter = itr1->first;
		if (counter >= mean) {
			valsCount += itr1->second.size();
		}
		else {
			break;
		}
	}
	return valsCount;
}

//--

size_t pesieve::stats::fillCodeStrings(OUT std::set<std::string>& codeStrings)
{
	codeStrings.insert("WVS");
	codeStrings.insert("SVW");
	codeStrings.insert("D$");
	codeStrings.insert("AQ");
	codeStrings.insert("AX");
	codeStrings.insert("UWV");
	codeStrings.insert("[^_]");
	codeStrings.insert("ZX[]");
	return codeStrings.size();
}

//---
class CodeMatcher : public RuleMatcher
{
	public:
	CodeMatcher()
		: RuleMatcher(CODE_RULE) {}

	virtual bool _isMatching(IN const AreaStats<BYTE>& stats)
	{
		const size_t kMinCodePoints = 2;
		const size_t kMinStrPoints = 2;

		double entropy = stats.currArea.entropy;
		if (entropy < ENTROPY_CODE_TRESHOLD) return false;

#ifdef DISPLAY_STATS
		std::cout << "FOUND strings: " << stats.currArea.foundStrings.size() << "\n";

		for (auto itr = stats.currArea.foundStrings.begin(); itr != stats.currArea.foundStrings.end(); ++itr)
		{
			const std::string& codeStr = itr->first;
			size_t count = itr->second;
			std::cout << "---->>> FOUND Str " << codeStr << " count: " << count << "\n";
		}
#endif
		std::set<std::string> codeStrings;
		fillCodeStrings(codeStrings);

		size_t strPoints = countFoundStrings(stats, codeStrings, 1);
#ifdef DISPLAY_STATS
		std::cout << "---->>> STR points: " << strPoints << "\n";
#endif
		if (codeStrings.size() && !strPoints){
			return false;
		}
		// possible code
		size_t ratiosPoints = 0;
		std::map<BYTE, double> ratios;
		ratios[0x00] = 0.1;
		ratios[0x0F] = 0.01;
		ratios[0x48] = 0.02;
		ratios[0x8B] = 0.02;
		ratios[0xCC] = 0.01;
		ratios[0xE8] = 0.01;
		ratios[0xFF] = 0.02;

		ratiosPoints += checkRatios(stats, ratios);
#ifdef DISPLAY_STATS
		std::cout << "---->>> CODE points: " << ratiosPoints << "\n";
#endif
		if (ratiosPoints < kMinCodePoints) {
			return false;
		}
		if (ratiosPoints >= (ratios.size() / 2 + 1)) {
			return true;
		}
		if (strPoints < kMinStrPoints) {
			return false;
		}
		return true;
	}
};


class ObfuscatedMatcher : public RuleMatcher
{
public:
	ObfuscatedMatcher()
		: RuleMatcher("is_full_obfuscated") {}

	virtual bool _isMatching(IN const AreaStats<BYTE>& stats)
	{
		const BYTE mFreqVal = getMostFrequentValue<BYTE>(stats.currArea.frequencies);
		double entropy = stats.currArea.entropy;
		const size_t populationSize = stats.currArea.histogram.size();

		if (populationSize < (CHARSET_SIZE / 3)) {
			return false;
		}

		bool entropyT = (mFreqVal != 0 && entropy > ENTROPY_DATA_TRESHOLD); // possible XOR obfuscation, or block cipher
		if (!entropyT) {
			return false;
		}

		StdDeviationCalc dev(stats.currArea.histogram, populationSize);
		const double mean = dev.getMean();
		const size_t nB = valuesNotBelowMean(stats.currArea, mean);
		const double nBRatio = (double)nB / (double)populationSize;
		if (nBRatio < 0.17) {
			return false;
		}
		if (nBRatio > 0.5) {
			return true;
		}

		// filter out texts:
		const double printRatio = getPrintableRatio(stats);
		if (printRatio > 0.8) {
			return false;
		}
		/*const size_t topVal = stats.currArea.frequencies.rbegin()->first;
		const size_t bottomVal = stats.currArea.frequencies.begin()->first;
		double diff = topVal - bottomVal;
		*/
		double stDev = dev.calcSampleStandardDeviation();

		std::set<BYTE>peaks;
		size_t peaksCount = fetchPeakValues(stats.currArea, stDev, peaks);
		double peaksRatio = (double)peaksCount / (double)populationSize;
		if (peaksRatio > 0.4) {
			return true;
		}
		if (peaks.find(0) == peaks.end()) {
			// 0 is not among the peaks:
			return true;
		}
#ifdef DISPLAY_STATS
		std::cout << "0 is among peaks. All peaks: \n";
		for (auto itr = peaks.begin(); itr != peaks.end(); itr++) {
			std::cout << std::hex << (UINT)*itr << " ";
		}
		std::cout << "\n";
#endif
		return false;
	}
};


class EncryptedMatcher : public RuleMatcher
{
public:
	EncryptedMatcher()
		: RuleMatcher("is_full_encrypted") {}

	virtual bool _isMatching(IN const AreaStats<BYTE>& stats)
	{
		double entropy = stats.currArea.entropy;
		const BYTE mFreqVal = getMostFrequentValue<BYTE>(stats.currArea.frequencies);
		bool fullAreaEncrypted = (entropy > ENTROPY_STRONG_ENC_TRESHOLD);// strong encryption
		if (mFreqVal != 0 && entropy > ENTROPY_ENC_TRESHOLD) {
			if (stats.currArea.frequencies.size() > 1) {
				auto fItr = stats.currArea.frequencies.begin(); // first one
				auto eItr = stats.currArea.frequencies.rbegin(); // last one
				// most common - least common ratio
				double diff = ((double)(eItr->first - fItr->first)) / (double)stats.currArea.size;
				//std::cout << "RATIO : " << fItr->first << " VS " << eItr->first << " DIFF: " << diff << "\n";
				if (diff < 0.01) {
					fullAreaEncrypted = true;
				}
			}
		}
		return fullAreaEncrypted;
	}
};

class TextMatcher : public RuleMatcher
{
public:
	TextMatcher()
		: RuleMatcher("possible_text") {}

	virtual bool _isMatching(IN const AreaStats<BYTE>& stats)
	{
		bool possibleText = false;
		const double printRatio = getPrintableRatio(stats);
		if (printRatio > 0.8) {
			possibleText = true;
		}
		return possibleText;
	}
};

//---

void pesieve::stats::RuleMatchersSet::initRules(DWORD ruleTypes)
{
	if (ruleTypes & RuleType::RULE_CODE) {
		matchers.push_back(new CodeMatcher());
	}
	if (ruleTypes & RuleType::RULE_TEXT) {
		this->matchers.push_back(new TextMatcher());
	}
	if (ruleTypes & RuleType::RULE_ENCRYPTED) {
		matchers.push_back(new EncryptedMatcher());
	}
	if (ruleTypes & RuleType::RULE_OBFUSCATED) {
		matchers.push_back(new ObfuscatedMatcher());
	}
}

bool pesieve::stats::isSuspicious(IN const AreaStats<BYTE>& stats, IN RuleMatchersSet& matchersSet, OUT AreaInfo& info)
{
	if (!stats.isFilled() || !stats.currArea.size) {
		return false;
	}

	size_t matched = 0;
	for (auto itr = matchersSet.matchers.begin(); itr != matchersSet.matchers.end(); ++itr) {
		RuleMatcher* m = *itr;
		if (!m) continue;
		if (m->isMatching(stats)) {
			info.matchedRules.push_back(m->name);
			matched++;
		}
	}
	return (matched > 0) ? true : false;
}

