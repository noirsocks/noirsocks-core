/*
    NoirSocks-core : core library of NoirSocks
    Copyright (C) 2017  NoirSocks

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include "Logger.h"

namespace NoirSocks
{

void DoLog(const std::string& log_file, const char* format, ...)
{
    FILE* file = fopen(log_file.c_str(), "a");
    if (file == nullptr)
    {
        return;
    }
    va_list ap;
    va_start(ap, format);
    vfprintf(file, format, ap);
    fclose(file);
}

};
