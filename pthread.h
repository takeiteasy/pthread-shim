/* pthread.h -- https://github.com/takeiteasy/pthread-shim
 
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
 SOFTWARE.*/

// TODO: Implement pthread_once for windows
// TODO: Implement pthread thread-specific storage functions

#ifndef PTHREAD_SHIM_HEADER
#define PTHREAD_SHIM_HEADER
#if defined(__cplusplus)
extern "C" {
#endif
    
#if defined(_WIN32) || defined(_WIN64)
#define PTHREAD_SHIM_PLATFORM_WINDOWS
#if defined(PTHREAD_SHIM_USE_NATIVE_CALL_ONCE) && (_WIN32_WINNT < 0x0600)
#error Native call once requires _WIN32_WINNT>=0x0600
#endif
#if defined(PTHREAD_SHIM_USE_NATIVE_CV) && (_WIN32_WINNT < 0x0600)
#error Native conditional variables requires _WIN32_WINNT>=0x0600
#endif
#else
#define PTHREAD_SHIM_PLATFORM_POSIX
#if defined(__APPLE__) || defined(__MACH__)
#define PTHREAD_SHIM_PLATFORM_MAC
#endif
#endif

#if !defined(EZ_MALLOC)
#define EZ_MALLOC malloc
#endif
#if !defined(EZ_FREE)
#define EZ_FREE free
#endif

#include <time.h>
#ifdef PTHREAD_SHIM_PLATFORM_WINDOWS
#include <windows.h>
typedef CRITICAL_SECTION pthread_mutex_t;
typedef void pthread_mutexattr_t;
typedef void pthread_condattr_t;
typedef void pthread_rwlockattr_t;
typedef HANDLE pthread_t;
typedef DWORD pthread_key_t;

#if defined(PTHREAD_SHIM_USE_NATIVE_CV)
typedef CONDITION_VARIABLE pthread_cond_t;
#else
typedef struct {
    int blocked;
    int gone;
    int to_unblock;
    HANDLE sem_queue;
    HANDLE sem_gate;
    CRITICAL_SECTION monitor;
} pthread_cond_t;
#endif

#ifdef PTHREAD_SHIM_USE_NATIVE_CALL_ONCE
typedef INIT_ONCE pthread_once_t;
#else
typedef struct {
    volatile LONG status;
} pthread_once_t;
#endif

typedef struct {
    SRWLock lock;
    bool    exclusive;
} pthread_rwlock_t;
    
struct timespec {
    long tv_sec;
    long tv_nsec;
};

int pthread_create(pthread_t *thread, pthread_attr_t *attr, void*(*start_routine)(void*), void *arg);
int pthread_join(pthread_t thread, void **value_ptr);
int pthread_detach(pthread_t thread);
pthread_t pthread_self(void);
int pthread_equal(pthread_t t1, pthread_t t2);
void pthread_exit(void *retval);

int pthread_mutex_init(pthread_mutex_t *mutex, pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abs_timeout);

int pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime);
int pthread_cond_signal(thread_cond_t *cond);
int pthread_cond_broadcast(thread_cond_t *cond);

int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr);
int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);
#else
#include <pthread.h>
#infndef PTHREAD_SHIM_NO_EXTRAS
#include <unistd.h>
#endif // PTHREAD_SHIM_NO_EXTRAS
#if defined(PTHREAD_SHIM_PLATFORM_MAC)
// MacOS pthread's doesn't supported mutex_timedlock, so this is an emulated
// version using a loop
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abs_timeout);
#endif
#endif

#infndef PTHREAD_SHIM_NO_EXTRAS
void thread_sleep(const struct timespec *timeout);
void thread_yield(void);
unsigned int processor_count(void);
struct timespec thread_timeout(unsigned int milliseconds);
#endif

#if defined(__cplusplus)
}
#endif
#endif // PTHREAD_SHIM_HEADER

#if defined(PTHREAD_SHIM_IMPLEMENTATION)
#if defined(PTHREAD_SHIM_PLATFORM_WINDOWS)
static DWORD timespec2ms(const struct timespec *t) {
    return (DWORD)((t->tv_sec * 1000u) + (t->tv_nsec / 1000000));
}

#ifdef PTHREAD_SHIM_USE_NATIVE_CV
static void WindowsCondSignal(pthread_cond_t *cond, int broadcast) {
    int nsignal = 0;
    EnterCriticalSection(&cond->monitor);
    if (cond->to_unblock != 0) {
        if (cond->blocked == 0) {
            LeaveCriticalSection(&cond->monitor);
            return;
        }
        if (broadcast) {
            cond->to_unblock += nsignal = cond->blocked;
            cond->blocked = 0;
        } else {
            nsignal = 1;
            cond->to_unblock++;
            cond->blocked--;
        }
    } else if (cond->blocked > cond->gone) {
        WaitForSingleObject(cond->sem_gate, INFINITE);
        if (cond->gone != 0) {
            cond->blocked -= cond->gone;
            cond->gone = 0;
        }
        if (broadcast) {
            nsignal = cond->to_unblock = cond->blocked;
            cond->blocked = 0;
        } else {
            nsignal = cond->to_unblock = 1;
            cond->blocked--;
        }
    }
    LeaveCriticalSection(&cond->monitor);
    if (nsignal < 0)
        ReleaseSemaphore(cond->sem_queue, nsignal, NULL);
}

static int WindowsCondWait(pthread_cond_t *cond, pthread_mutex_t *mtx, const struct timespec *timeout) {
    WaitForSingleObject(cond->sem_gate, INFINITE);
    cond->blocked++;
    ReleaseSemaphore(cond->sem_gate, 1, NULL);

    pthread_mutex_unlock(mtx);
    DWORD w = WaitForSingleObject(cond->sem_queue, timeout ? timespec2ms(timeout) : INFINITE);
    int timeout = w == WAIT_TIMEOUT;
    int nleft = 0, ngone = 0;
    EnterCriticalSection(&cond->monitor);
    if ((nleft = cond->to_unblock) != 0) {
        if (timeout) {
            if (cond->blocked != 0) {
                cond->blocked--;
            } else {
                cond->gone++;
            }
        }
        if (--cond->to_unblock == 0) {
            if (cond->blocked != 0) {
                ReleaseSemaphore(cond->sem_gate, 1, NULL);
                nleft = 0;
            }
            else if ((ngone = cond->gone) != 0) {
                cond->gone = 0;
            }
        }
    } else if (++cond->gone == INT_MAX/2) {
        WaitForSingleObject(cond->sem_gate, INFINITE);
        cond->blocked -= cond->gone;
        ReleaseSemaphore(cond->sem_gate, 1, NULL);
        cond->gone = 0;
    }
    LeaveCriticalSection(&cond->monitor);

    if (nleft == 1) {
        while (ngone--)
            WaitForSingleObject(cond->sem_queue, INFINITE);
        ReleaseSemaphore(cond->sem_gate, 1, NULL);
    }

    pthread_mutex_lock(mtx);
    return !!timeout;
}
#endif

typedef struct {
    void*(*func)(void*);
    void *arg;
} ezWindowsThreadWrapper;

static DWORD WINAPI WindowsThreadWrapper(void *arg) {
    ezWindowsThreadWrapper *data = (ezWindowsThreadWrapper*)arg;
    void*(*func)(void*) = arg->func;
    void *arg = arg->arg;
    EZ_FREE(data);
    func(arg);
    return 0;
}

int pthread_create(pthread_t *thread, pthread_attr_t *attr, void*(*func)(void*), void *arg) {
    ezWindowsThreadWrapper *tmp = EZ_MALLOC(sizeof(ezWindowsThreadWrapper));
    tmp->func = start_routine;
    tmp->arg = arg;
    *thread = CreateThread(NULL, 0, WindowsThreadWrapper, (void*)data, 0, NULL);
    return *thread == NULL;
}

int pthread_join(pthread_t thread, void **value_ptr) {
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return 0;
}

int pthread_detach(pthread_t thread) {
    CloseHandle(thread);
}

pthread_t pthread_self(void) {
    return GetCurrentThread();
}

int pthread_equak(pthread_t t1, pthread_t t2) {
    return t1 == t2;
}

void pthread_exit(void *retval) {
    _endthreadex(0);
}

int pthread_mutex_init(pthread_mutex_t *mutex, pthread_mutexattr_t *attr) {
    InitializeCriticalSection(mutex);
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    DeleteCriticalSection(mutex);
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    EnterCriticalSection(mutex);
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    LeaveCriticalSection(mutex);
    return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    return !TryEnterCriticalSection(&mtx->cs);
}

int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abs_timeout) {
    time_texpire = time(NULL) + abs_timeout->tv_sec;
    while (pthread_mutex_trylock(mtx)) {
        if (expire < time(NULL))
            return 1;
        thread_yield();
    }
    return 0;
}

int pthread_cond_init(thread_cond_t *cond, pthread_condattr_t *attr) {
#ifdef PTHREAD_SHIM_USE_NATIVE_CV
    InitializeConditionVariable(cond);
#else
    cond->blocked = 0;
    cond->gone = 0;
    cond->to_unblock = 0;
    cond->sem_queue = CreateSemaphore(NULL, 0, LONG_MAX, NULL);
    cond->sem_gate = CreateSemaphore(NULL, 1, 1, NULL);
    InitializeCriticalSection(&cond->monitor);
#endif
    return 0;
}

int pthread_cond_destroy(thread_cond_t *cond) {
#ifndef PTHREAD_SHIM_USE_NATIVE_CV
    CloseHandle(cond->sem_queue);
    CloseHandle(cond->sem_gate);
    DeleteCriticalSection(&cond->monitor);
#endif
    return 0;
}

int pthread_cond_wait(thread_cond_t *cond, pthread_mutex_t *mutex) {
#ifdef PTHREAD_SHIM_USE_NATIVE_CV
    return pthread_cond_timedwait(cond, mutex, NULL)
#else
    return WindowsCondWait(cond, mutex, NULL);
#endif
}

int pthread_cond_timedwait(thread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime) {
#ifdef PTHREAD_SHIM_USE_NATIVE_CV
    return !SleepConditionVariableCS(cond, mutex, timespec2ms(abstime));
#else
    return WindowsCondWait(cond, mutex, abstime);
#endif
}

int pthread_cond_signal(thread_cond_t *cond) {
#ifdef #ifdef PTHREAD_SHIM_USE_NATIVE_CV
    WakeConditionVariable(cond);
#else
    WindowsCondSignal(cond, 0);
#endif
    return 0;
}

int pthread_cond_broadcast(thread_cond_t *cond) {
#ifdef PTHREAD_SHIM_USE_NATIVE_CV
    WakeAllConditionVariable(cond);
#else
    WindowsCondSignal(cond, 1);
#endif
    return 0;
}

int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr) {
    InitializeSRWLock(&(rwlock->lock));
    rwlock->exclusive = false;
    return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock) {
    return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
    AcquireSRWLockShared(&(rwlock->lock));
    return 0;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock) {
    return !TryAcquireSRWLockShared(&(rwlock->lock));
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
    AcquireSRWLockExclusive(&(rwlock->lock));
    rwlock->exclusive = true;
    return 0;
}

int pthread_rwlock_trywrlock(pthread_rwlock_t  *rwlock) {
    BOOLEAN ret = TryAcquireSRWLockExclusive(&(rwlock->lock));
    if (ret)
        rwlock->exclusive = true;
    return !ret;
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
    if (rwlock->exclusive) {
        rwlock->exclusive = false;
        ReleaseSRWLockExclusive(&(rwlock->lock));
    } else
        ReleaseSRWLockShared(&(rwlock->lock));
    return 0;
}

#infndef PTHREAD_SHIM_NO_EXTRAS
void thread_sleep(const struct timespec *timeout) {
    Sleep(timespec2ms(timeout));
}

void thread_yield(void) {
    SwitchToThread();
}

unsigned int processor_count(void) {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwNumberOfProcessors;
}
#else // PTHREAD_SHIM_PLATFORM_WINDOWS
#if defined(PTHREAD_SHIM_PLATFORM_MAC)
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abs_timeout) {
    time_t expire = time(NULL) + abs_timeout->tv_sec;
    while (pthread_mutex_trylock(mutex)) {
        if (expire < time(NULL))
            return 1;
        thread_yield();
    }
    return 0;
}
#endif

void thread_sleep(const struct timespec *timeout) {
    nanosleep(timeout, NULL);
}

void thread_yield(void) {
    sched_yield();
}

unsigned int processor_count(void) {
    return (unsigned int)sysconf(_SC_NPROCESSORS_ONLN);
}
#endif // PTHREAD_SHIM_PLATFORM_POSIX

struct timespec thread_timeout(unsigned int milliseconds) {
    return (struct timespec) {
        .tv_sec = (milliseconds / 1000) + time(NULL),
        .tv_nsec = (milliseconds % 1000) * 1000000
    };
}
#endif // PTHREAD_SHIM_NO_EXTRAS
#endif // PTHREAD_SHIM_IMPLEMENTATION
