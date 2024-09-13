# pthread-shim

A basic implementation of a subset of pthread functions for Windows (and Mac†). The majority of the regular-use cases (entirely subjective) are covered. Define `PTHREAD_SHIM_IMPLEMENTATION` before including. Mac† and Linux is pass-thru and includes `#include <pthread.h>`.

Also includes a few (optional) extra functions for all platforms*.

```c
#infndef PTHREAD_SHIM_NO_EXTRAS
void thread_sleep(const struct timespec *timeout);
void thread_yield(void);
unsigned int processor_count(void);
struct timespec thread_timeout(unsigned int milliseconds);
#endif
```

† Mac lacks `pthread_mutex_timedlock` this library provides a version (that's everything, regular pthread.h is included)

\* Windows/Mac/Linux (BSD is untested)

## LICENSE
```
MIT License

Copyright (c) 2024 George Watson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
