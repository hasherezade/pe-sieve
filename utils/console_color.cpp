#include "console_color.h"
#include <iostream>

namespace pesieve {
	namespace util {

		bool get_current_color(int descriptor, WORD &color) {
			CONSOLE_SCREEN_BUFFER_INFO info;
			if (!GetConsoleScreenBufferInfo(GetStdHandle(descriptor), &info))
				return false;
			color = info.wAttributes;
			return true;
		}

	}
};

void pesieve::util::print_in_color(int color, const std::string &text, bool is_error)
{
	int descriptor = is_error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE;
	std::ostream &stream = is_error ? std::cerr : std::cout;

	WORD old_color = 7; //default
	get_current_color(descriptor, old_color);

	HANDLE hConsole = GetStdHandle(descriptor);
	FlushConsoleInputBuffer(hConsole);
	SetConsoleTextAttribute(hConsole, color); // back to default color

	stream << text;

	FlushConsoleInputBuffer(hConsole);
	SetConsoleTextAttribute(hConsole, old_color); // back to default color
	FlushConsoleInputBuffer(hConsole);

	stream.flush();
}
