/*
tinyTLS project

Copyright 2015 Nesterov A.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef BINARY_H_
#define BINARY_H_

#include <string.h>

namespace TinyTLS
{
	class Binary
	{
		typedef unsigned char Ty;

	public:
		Ty * data;
		unsigned length;

		Binary() { length = 0; data = NULL; }

		Binary(const Binary & b)
		{
			length = 0; data = NULL;
			alloc(b.length);
			memcpy(data, b.data, length);
		}

		Binary & operator =(const Binary & b)
		{
			clear();
			alloc(b.length);
			length = b.length;
			memcpy(data, b.data, length);

			return *this;
		}

		~Binary()
		{
			if (data)
				delete[] data;
			data = NULL;
			length = 0;
		}

		void alloc(unsigned expected)
		{
			int a = (expected | (32 - 1)) + 1;

			Ty * na = new Ty[a];
			if (length && data) {
				delete[] data;
			}
			data = na;
			length = expected;
		}

		Ty & operator [](int index)
		{
			return (data[index]);

		}
		const Ty & operator [](int index) const
		{
			return (data[index]);
		}

		bool has(int index) const
		{
			return (index >= 0 && index < (int)length);
		}

		int index(const Ty * ptr) const
		{
			if (ptr < data || ptr >= (data + length))
				return -1;
			return (int)(ptr - data);
		}

		void swap(Binary & b)
		{
			Ty * t_data = data; data = b.data; b.data = t_data;
			unsigned t_length = length; length = b.length; b.length = t_length;
		}

		void clear()
		{
			length = 0;
			if (data) delete[] data;
			data = NULL;
		}

		Ty* begin() { return data; }
		Ty* end() { return (data + length); }

		const Ty* cbegin() const { return data; }
		const Ty* cend() const { return (data + length); }
	};

} // namespace TinyTLS

#endif