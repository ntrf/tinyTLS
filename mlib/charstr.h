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

#ifndef CHARSTR_H_
#define CHARSTR_H_

#include <string.h>

class charstr
{
	char *buf;
public:
	charstr():buf(NULL){}
	~charstr(){ if(buf) delete buf; buf = NULL;  }
	charstr(int sz,char c = '\0'){
		buf = new char[sz+1]; 
		memset(buf,c,sz);
		buf[sz] = 0;
	}
///////////////////////////////////////////////////////////
	charstr(const char *b){ 
		if(b){
			size_t l = strlen(b); 
			buf = new char[l+1]; 
			memcpy(buf,b,l+1);
		}else{
			buf = NULL;
		}
	}
	charstr(const char *b,const int l){ 
		if(!l){ 
			buf = NULL; 
		}else{
			buf = new char[l+1];
			if(l && b) memcpy(buf,b,l);
			buf[l] = 0;
		}
	}
	charstr & operator=(const char *b)
	{
		if(buf) delete buf;
		if(b){
			size_t l = strlen(b); 
			buf = new char[l+1]; 
			memcpy(buf,b,l+1);
		}else{
			buf = NULL;
		}
		return *this;
	}
///////////////////////////////////////////////////////////
	charstr(charstr &b)
	{
		if(b.buf){
			size_t l = strlen(b.buf); 
			buf = new char[l+1]; 
			memcpy(buf,b.buf,l+1);
		}else{
			buf = NULL;
		}
	}
	charstr & operator=(charstr &b)
	{
		if(!b.buf){if(buf) delete buf; buf=NULL; return *this;}
		size_t l = strlen(b);
		if(buf) delete buf;
		buf = new char[l+1]; 
		memcpy(buf,b,l+1);
		return *this;
	}
///////////////////////////////////////////////////////////
	operator char*() { return buf; }
	operator const char*() const { return buf; }
	size_t length() const {
		if(!buf) 
			return 0;
		else 
			return strlen(buf);
	}
///////////////////////////////////////////////////////////
};

#endif