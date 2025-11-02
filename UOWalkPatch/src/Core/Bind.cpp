#include "Core/Bind.hpp"

#include <windows.h>

#include <atomic>
#include <functional>
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
        if (!ownerLogged.test_and_set(std::memory_order_acq_rel) && tag == "helpers") {
            Log::Logf(Log::Level::Info,
                      Log::Category::Hooks,
                      "[HOOKS] helpers owner-entry tid=%u",
                      static_cast<unsigned>(current));
        }
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

    BOOL posted = FALSE;
    DWORD gle = ERROR_INVALID_PARAMETER;
    if (ownerTid != 0) {
        posted = PostThreadMessageW(ownerTid, kOwnerWakeMessage, 0u, 0u);
        gle = posted ? 0u : GetLastError();
    }

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[CORE][Bind][POST] method=PostThreadMessage owner=%u tag=%s ok=%d gle=%lu",
              static_cast<unsigned>(ownerTid),
              work->state ? work->state->tag.c_str() : "<none>",
              posted ? 1 : 0,
              static_cast<unsigned long>(gle));

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
    QueueViaOwnerPump(resolvedOwner, work);

    const DWORD ackTimeout = Core::Config::HelpersPostAckTimeoutMs();
    if (ackTimeout > 0 && work->state && work->state->ackEvent) {
        DWORD waitResult = WaitForSingleObject(work->state->ackEvent, ackTimeout);
        if (waitResult == WAIT_OBJECT_0 && work->state->acked.load(std::memory_order_acquire))
            return true;
    }

    if (work->state && work->state->executed.load(std::memory_order_acquire))
        return true;

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

} // namespace Core::Bind
