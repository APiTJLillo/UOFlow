#include "Core/Bind.hpp"

#include <windows.h>

#include <atomic>
#include <functional>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

#include "Core/Config.hpp"
#include "Core/Logging.hpp"
#include "Util/OwnerPump.hpp"

namespace Core::Bind {
namespace {

constexpr UINT kOwnerWakeMessage = WM_APP + 0x3B0;

struct DispatchState {
    explicit DispatchState(DWORD ownerTid, std::string tagValue)
        : ackEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
          owner(ownerTid),
          tag(std::move(tagValue)) {}

    ~DispatchState() {
        if (ackEvent)
            CloseHandle(ackEvent);
    }

    void NoteOwnerEntry() {
        DWORD current = GetCurrentThreadId();
        if (current != owner)
            return;

        acked.store(true, std::memory_order_release);
        if (ackEvent)
            SetEvent(ackEvent);
    }

    bool AcquireExecution(bool isOwnerThread) {
        bool expected = false;
        if (!executed.compare_exchange_strong(expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
            return false;

        if (!isOwnerThread && ackEvent)
            SetEvent(ackEvent);
        return true;
    }

    HANDLE ackEvent = nullptr;
    std::atomic<bool> acked{false};
    std::atomic<bool> executed{false};
    std::atomic_flag ownerLogged = ATOMIC_FLAG_INIT;
    DWORD owner = 0;
    std::string tag;
};

struct DispatchWork {
    std::shared_ptr<std::function<void()>> task;
    std::shared_ptr<DispatchState> state;
};

thread_local const DispatchState* t_currentDispatchState = nullptr;
std::atomic<bool> g_postThreadMessageDisabled{false};

void RunTaskOnCurrentThread(const std::shared_ptr<DispatchWork>& work) {
    if (!work)
        return;

    auto state = work->state;
    if (state) {
        DWORD current = GetCurrentThreadId();
        bool isOwner = (current == state->owner);
        if (isOwner)
            state->NoteOwnerEntry();
        if (!state->AcquireExecution(isOwner))
            return;
    }

    struct DispatchScope {
        const DispatchState* previous;
        DispatchScope(const DispatchState* next) : previous(t_currentDispatchState) {
            t_currentDispatchState = next;
        }
        ~DispatchScope() {
            t_currentDispatchState = previous;
        }
    } scopeGuard(state.get());

    if (state && state->tag == "helpers") {
        DWORD current = GetCurrentThreadId();
        if (state->owner != 0 && current == state->owner) {
            if (!state->ownerLogged.test_and_set(std::memory_order_acq_rel)) {
                Log::Logf(Log::Level::Info,
                          Log::Category::Hooks,
                          "[HOOKS] helpers owner-entry tid=%u",
                          static_cast<unsigned>(current));
            }
        } else {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS] helpers remote-entry owner=%u tid=%u",
                      static_cast<unsigned>(state ? state->owner : 0),
                      static_cast<unsigned>(GetCurrentThreadId()));
        }
    }

    if (work->task && *work->task) {
        try {
            (*work->task)();
        } catch (...) {
            // Swallow to avoid destabilising caller threads.
        }
    }
}

bool QueueViaOwnerPump(DWORD ownerTid, const std::shared_ptr<DispatchWork>& work) {
    if (!work || !work->task)
        return false;

    Util::OwnerPump::RunOnOwner([work]() { RunTaskOnCurrentThread(work); });

    // For Lua helpers, avoid legacy PostThreadMessage wake and related logs.
    if (work->state && _stricmp(work->state->tag.c_str(), "helpers") == 0) {
        return TRUE;
    }

    BOOL posted = FALSE;
    DWORD gle = ERROR_INVALID_PARAMETER;
    bool attemptedPost = false;
    if (!g_postThreadMessageDisabled.load(std::memory_order_acquire) && ownerTid != 0) {
        attemptedPost = true;
        posted = PostThreadMessageW(ownerTid, kOwnerWakeMessage, 0u, 0u);
        gle = posted ? 0u : GetLastError();
        if (!posted && gle == ERROR_INVALID_THREAD_ID) {
            g_postThreadMessageDisabled.store(true, std::memory_order_release);
        }
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[CORE][Bind][POST] method=PostThreadMessage owner=%u tag=%s ok=%d gle=%lu",
              static_cast<unsigned>(ownerTid),
              work->state ? work->state->tag.c_str() : "<none>",
              posted ? 1 : 0,
              static_cast<unsigned long>(gle));

    if (!posted && attemptedPost && g_postThreadMessageDisabled.load(std::memory_order_acquire)) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[CORE][Bind] post-thread-message disabled for owner=%u (gle=%lu)",
                  static_cast<unsigned>(ownerTid),
                  static_cast<unsigned long>(gle));
    }

    return posted == TRUE;
}

struct ApcContext {
    std::shared_ptr<DispatchWork> work;
};

VOID CALLBACK ApcThunk(ULONG_PTR param) {
    std::unique_ptr<ApcContext> ctx(reinterpret_cast<ApcContext*>(param));
    if (!ctx || !ctx->work)
        return;
    RunTaskOnCurrentThread(ctx->work);
}

struct RemoteThreadContext {
    std::shared_ptr<DispatchWork> work;
};

DWORD WINAPI RemoteThreadThunk(LPVOID param) {
    std::unique_ptr<RemoteThreadContext> ctx(static_cast<RemoteThreadContext*>(param));
    if (!ctx || !ctx->work)
        return 0;
    RunTaskOnCurrentThread(ctx->work);
    return 0;
}

bool QueueApcFallback(DWORD ownerTid, const std::shared_ptr<DispatchWork>& work) {
    if (!work)
        return false;

    HANDLE thread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, ownerTid);
    if (!thread) {
        DWORD gle = GetLastError();
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[CORE][Bind][FALLBACK] method=QueueUserAPC owner=%u tag=%s ok=0 gle=%lu",
                  static_cast<unsigned>(ownerTid),
                  work->state ? work->state->tag.c_str() : "<none>",
                  static_cast<unsigned long>(gle));
        return false;
    }

    auto ctx = std::make_unique<ApcContext>();
    ctx->work = work;
    ULONG_PTR payload = reinterpret_cast<ULONG_PTR>(ctx.release());
    BOOL ok = QueueUserAPC(&ApcThunk, thread, payload);
    DWORD gle = ok ? 0u : GetLastError();
    if (!ok) {
        auto reclaim = std::unique_ptr<ApcContext>(reinterpret_cast<ApcContext*>(payload));
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[CORE][Bind][FALLBACK] method=QueueUserAPC owner=%u tag=%s ok=0 gle=%lu",
                  static_cast<unsigned>(ownerTid),
                  work->state ? work->state->tag.c_str() : "<none>",
                  static_cast<unsigned long>(gle));
    } else {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][Bind][FALLBACK] method=QueueUserAPC owner=%u tag=%s ok=1 gle=0",
                  static_cast<unsigned>(ownerTid),
                  work->state ? work->state->tag.c_str() : "<none>");
    }
    CloseHandle(thread);
    return ok == TRUE;
}

bool LaunchRemoteThreadFallback(DWORD ownerTid, const std::shared_ptr<DispatchWork>& work) {
    if (!work)
        return false;

    auto ctx = std::make_unique<RemoteThreadContext>();
    ctx->work = work;
    DWORD newTid = 0;
    HANDLE thread = CreateThread(nullptr, 0, &RemoteThreadThunk, ctx.release(), 0, &newTid);
    DWORD gle = thread ? 0u : GetLastError();
    if (!thread) {
        Log::Logf(Log::Level::Warn,
                  Log::Category::Core,
                  "[CORE][Bind][FALLBACK] method=CreateThread owner=%u tag=%s ok=0 gle=%lu",
                  static_cast<unsigned>(ownerTid),
                  work->state ? work->state->tag.c_str() : "<none>",
                  static_cast<unsigned long>(gle));
        return false;
    }

    Log::Logf(Log::Level::Warn,
              Log::Category::Core,
              "[CORE][Bind][FALLBACK] method=CreateThread owner=%u tag=%s ok=1 tid=%u",
              static_cast<unsigned>(ownerTid),
              work->state ? work->state->tag.c_str() : "<none>",
              static_cast<unsigned>(newTid));
    CloseHandle(thread);
    return true;
}

std::shared_ptr<DispatchWork> PrepareWork(DWORD ownerTid, TaskFn&& fn, const char* tag) {
    if (!fn)
        return nullptr;

    std::string label = tag ? tag : "<unnamed>";
    auto work = std::make_shared<DispatchWork>();
    work->task = std::make_shared<TaskFn>(std::move(fn));
    work->state = std::make_shared<DispatchState>(ownerTid, label);
    return work;
}

DWORD ResolveOwnerTid(DWORD requestedOwner) {
    if (requestedOwner)
        return requestedOwner;
    DWORD pumpOwner = Util::OwnerPump::GetOwnerThreadId();
    if (pumpOwner)
        return pumpOwner;
    return 0;
}

} // namespace

bool PostToOwner(std::uint32_t ownerTid, TaskFn&& fn, const char* tag) {
    DWORD resolvedOwner = ResolveOwnerTid(ownerTid);
    auto work = PrepareWork(resolvedOwner, std::move(fn), tag);
    if (!work)
        return false;

    return QueueViaOwnerPump(resolvedOwner, work);
}

bool DispatchWithFallback(std::uint32_t ownerTid, TaskFn&& fn, const char* tag) {
    DWORD resolvedOwner = ResolveOwnerTid(ownerTid);
    auto work = PrepareWork(resolvedOwner, std::move(fn), tag);
    if (!work)
        return false;

    // Primary post
    bool primaryPosted = QueueViaOwnerPump(resolvedOwner, work);

    const DWORD ackTimeout = Core::Config::HelpersPostAckTimeoutMs();
    if (primaryPosted && ackTimeout > 0 && work->state && work->state->ackEvent) {
        DWORD waitResult = WaitForSingleObject(work->state->ackEvent, ackTimeout);
        if (waitResult == WAIT_OBJECT_0 && work->state->acked.load(std::memory_order_acquire))
            return true;
    }

    if (work->state && work->state->executed.load(std::memory_order_acquire))
        return true;

    bool helpersTag = work->state && _stricmp(work->state->tag.c_str(), "helpers") == 0;
    if (helpersTag) {
        bool alreadyExecuted = work->state && work->state->executed.load(std::memory_order_acquire);
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[CORE][Bind] helpers dispatch awaiting owner drain owner=%u posted=%d executed=%d",
                  static_cast<unsigned>(resolvedOwner),
                  primaryPosted ? 1 : 0,
                  alreadyExecuted ? 1 : 0);
        // For Lua helpers, never fall back to APC or CreateThread.
        return alreadyExecuted ? true : primaryPosted;
    }

    // APC fallback
    if (Core::Config::HelpersAllowApcFallback() && resolvedOwner != 0) {
        if (QueueApcFallback(resolvedOwner, work)) {
            if (ackTimeout > 0 && work->state && work->state->ackEvent) {
                DWORD waitResult = WaitForSingleObject(work->state->ackEvent, ackTimeout);
                if (waitResult == WAIT_OBJECT_0 && work->state->acked.load(std::memory_order_acquire))
                    return true;
            }
        }
    }

    if (work->state && work->state->executed.load(std::memory_order_acquire))
        return true;

    // Remote thread fallback
    if (Core::Config::HelpersAllowRemoteThreadFallback()) {
        if (LaunchRemoteThreadFallback(resolvedOwner, work))
            return true;
    }

    return work->state && work->state->executed.load(std::memory_order_acquire);
}

bool IsCurrentDispatchTag(const char* tag) {
    if (!tag)
        return false;
    const DispatchState* state = t_currentDispatchState;
    if (!state)
        return false;
    return _stricmp(state->tag.c_str(), tag) == 0;
}

bool IsInDispatch() {
    return t_currentDispatchState != nullptr;
}

} // namespace Core::Bind
