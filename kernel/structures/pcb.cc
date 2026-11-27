/* Copyright (C) 2026 Ahmed Gheith and contributors.
 *
 * Use restricted to classroom projects.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "pcb.h"
#include "kernel_main.h"

#include "ccb.h"
#include "lib/handle_queue.h"
#include "machine/machine.h"
#include "machine/x86_64.h"
#include "structures/gdt.h"

#include <coroutine>
#include <cstddef>

#include "elf.h"

// context must be first — syscallHandler_ saves into TCB* at offset 0.
static_assert(offsetof(impl::TCB, context) == 0);

namespace impl {
bool current_thread_dead() {
    auto *t = CCB::current()->current_thread;
    return t && t->zombie;
}
namespace {
SpinLock sleep_lock;
struct Sleeper {
    uint64_t deadline;
    coroutine waiter;
    Sleeper *next = nullptr;
    static Sleeper *sleepers;
    bool await_ready() { return rdtsc() >= deadline; }
    void await_suspend(std::coroutine_handle<> h) {
        LockGuard g{sleep_lock};
        waiter = make_coroutine(h);
        auto **p = &sleepers;
        while (*p && (*p)->deadline <= deadline) p = &(*p)->next;
        next = *p;
        *p = this;
    }
    void await_resume() {}
};
Sleeper *Sleeper::sleepers = nullptr;
}
sync<void> sleep_until(uint64_t deadline) { co_await Sleeper{deadline, {}}; }
void poll_sleepers() {
    LockGuard g{sleep_lock};
    uint64_t now = rdtsc();
    while (Sleeper::sleepers && Sleeper::sleepers->deadline <= now) {
        auto *s = Sleeper::sleepers;
        Sleeper::sleepers = s->next;
        auto waiter = s->waiter;
        ready_queue.add(waiter);
    }
}

ChainingHashMap<WeakRef<PCB>> PCB::process_table{1024};
uint64_t PCB::current_pid = 1;
bool PCB::has_rolled_over = false;
SpinLock PCB::pid_lock{};

void drop_to_kernel_cr3() {
  CCB *ccb = CCB::current();
  if (get_cr3() != ccb->kernel_cr3) set_cr3(ccb->kernel_cr3);
}

constexpr uint8_t KILL_VECTOR = 52;

// should only ever be awaited once
struct DrainDeadMm {
  uint64_t cr3;
  Atomic<uint64_t> pending{0};
  HandleQueue<NoLock> waiter{}; // should only ever hold one value; using full class for internal transfer

  bool await_ready() {
    if (get_cr3() == cr3) drop_to_kernel_cr3();

    auto *t = CCB::current()->current_thread;
    if (t && t->zombie) CCB::current()->current_thread = nullptr;

    return Sys::core_count == 1;
  }

  void await_suspend(std::coroutine_handle<void> h) {
    waiter.add(h);
    pending.set((1ull << Sys::core_count) - 1);
    pending.sub_fetch(1ull << CCB::current()->id);

    kill_list_lock.lock();
    kill_list = new MmKillNode{kill_list, cr3, this};
    kill_list_lock.unlock();

    asm volatile("mfence; lfence" ::: "memory");
    Msr::InterruptCommandRegister().write((3 << 18) | (1 << 14) | KILL_VECTOR);
  }

  void await_resume() {}

  static void ack_all() {
    CCB *ccb = CCB::current();
    kill_list_lock.lock();
    MmKillNode **node = &kill_list;
    while (*node)
    {
      if (get_cr3() == (*node)->kill_target_cr3) drop_to_kernel_cr3();

      uint64_t mask = 1ull << ccb->id;
      if ((*node)->kill_drain_request->pending.get() & mask)
      {
        if ((*node)->kill_drain_request->pending.sub_fetch(mask) == 0)
        {
          ready_queue.transfer((*node)->kill_drain_request->waiter);
          MmKillNode *next = (*node)->next;
          delete *node;
          *node = next;
          continue;
        }
      }
      node = &(*node)->next;
    }
    kill_list_lock.unlock();
  }
};

static async<void> free_mm(StrongRef<PCB> p) {
  co_await DrainDeadMm{p->as->cr3_phys()};
  co_await VMM::destroy(p->as);

  for (TCB *raw = p->leader; raw;) {
    StrongRef<TCB> hold{raw->self};
    raw = raw->next_process;
    hold->anchor = nullptr;
  }
  p->leader = p->tail = nullptr;
}

uint64_t PCB::provision_pid()
{
    LockGuard g{pid_lock};

    uint64_t pid = current_pid++;

    if (current_pid == 0) has_rolled_over = true;
    while (has_rolled_over && process_table.get(current_pid).has_value()) current_pid++;

    return pid;
}

SpinLock TCB::tid_lock{};
uint64_t TCB::current_tid = 1;

uint64_t TCB::provision_tid() {
  LockGuard g{tid_lock};
  return current_tid++;
}

namespace {
struct ExecFiles {
    ELF::Info mainInfo{};
    ELF::Info interpInfo{};
    StrongRef<Node> interpFile{};
};

//check both files before tearing down the old process
sync<int64_t> prepareExec(StrongRef<Node> file, StrongRef<Node> cwd, ExecFiles &files) {
    files.mainInfo = co_await ELF::parse(file);
    if (!files.mainInfo.ok) co_return Syscall::ENOEXEC;
    if (!files.mainInfo.hasInterp) co_return 0;

    auto result = co_await fs->find(cwd, files.mainInfo.interp);
    if (result.error) co_return result.error;
    if (!co_await result.file->is_file()) co_return Syscall::EACCES;

    files.interpFile = result.file;
    files.interpInfo = co_await ELF::parse(files.interpFile);
    if (!files.interpInfo.ok || !files.interpInfo.isPie || files.interpInfo.hasInterp) {
        co_return Syscall::ELIBBAD;
    }
    co_return 0;
}

struct AuxEntry {
    uint64_t type;
    uint64_t value;
};

struct StackInfo {
    uint64_t argc = 0;
    uint64_t envc = 0;
    uint64_t size = 0;
    uint64_t random[2]{};
};

//include the terminating auxv entry in the count
constexpr uint64_t AUX_COUNT = 15;

bool measureStack(const char *path, char *const argv[], char *const envp[],
                  uint64_t stackSize, StackInfo &stack) {
    //use the same aligned capacity as setup_stack
    const uint64_t capacity = stackSize & ~uint64_t(15);
    const uint64_t fixed = 3 * sizeof(uint64_t) + AUX_COUNT * sizeof(AuxEntry) + sizeof(stack.random);
    if (capacity < fixed) return false;
    uint64_t remaining = capacity - fixed;
    auto account = [&remaining](uint64_t bytes) {
        if (bytes > remaining) return false;
        remaining -= bytes;
        return true;
    };

    if (!account(strlen(path) + 1)) return false;
    while (argv[stack.argc]) {
        if (!account(sizeof(uint64_t)) || !account(strlen(argv[stack.argc]) + 1)) {
            return false;
        }
        ++stack.argc;
    }
    while (envp[stack.envc]) {
        if (!account(sizeof(uint64_t)) || !account(strlen(envp[stack.envc]) + 1)) {
            return false;
        }
        ++stack.envc;
    }

    const uint64_t bytes = capacity - remaining;
    stack.size = (bytes + 15) & ~uint64_t(15);
    return stack.size <= capacity;
}

//get real random bytes before tearing down the old process
bool fillRandom(StackInfo &stack) {
    uint32_t a, b, c, d;
    cpuid(1, 0, &a, &b, &c, &d);
    if (!(c & (1u << 30))) return false;

    for (auto &word : stack.random) {
        unsigned char ready = 0;
        for (int attempt = 0; attempt < 10 && !ready; ++attempt) {
            asm volatile("rdrand %0; setc %1" : "=&r"(word), "=qm"(ready) : : "cc");
        }
        if (!ready) return false;
    }
    return true;
}

uintptr_t writeStack(TCB *t, const char *path, char *const argv[], char *const envp[],
                     const StackInfo &stack, const ELF::Loaded &mainImage, uint64_t interpBias) {
    uintptr_t top = t->context.rsp;
    ASSERT(top >= t->stack_base && stack.size <= top - t->stack_base);
    const uintptr_t start = top - stack.size;
    auto *words = reinterpret_cast<uint64_t *>(start);

    //copy strings from the top so we can write their pointers directly below
    auto copyString = [&top](const char *str) {
        const uint64_t len = strlen(str) + 1;
        top -= len;
        memcpy(reinterpret_cast<void *>(top), str, len);
        return top;
    };

    *words++ = stack.argc;
    for (uint64_t i = 0; i < stack.argc; ++i) *words++ = copyString(argv[i]);
    *words++ = 0;
    for (uint64_t i = 0; i < stack.envc; ++i) *words++ = copyString(envp[i]);
    *words++ = 0;

    const uintptr_t execName = copyString(path);
    top -= sizeof(stack.random);
    memcpy(reinterpret_cast<void *>(top), stack.random, sizeof(stack.random));

    //this kernel has one root identity
    const AuxEntry aux[] = {
        {3, mainImage.phdr},    //at_phdr
        {4, mainImage.phent},   //at_phent
        {5, mainImage.phnum},   //at_phnum
        {6, FRAME_SIZE},        //at_pagesz
        {7, interpBias},        //at_base needs the interpreter's load bias
        {9, mainImage.entry},   //at_entry still points to the main executable
        {11, 0},               //at_uid
        {12, 0},               //at_euid
        {13, 0},               //at_gid
        {14, 0},               //at_egid
        {17, 100},             //at_clktck
        {23, 0},               //at_secure
        {25, top},             //at_random
        {31, execName},        //at_execfn keeps the path separate from argv[0]
        {0, 0}                 //at_null
    };
    static_assert(sizeof(aux) == AUX_COUNT * sizeof(AuxEntry));
    ASSERT(reinterpret_cast<uintptr_t>(words) + sizeof(aux) <= top);
    memcpy(words, aux, sizeof(aux));
    return start;
}

//map both images before choosing a spot for the stack
sync<bool> startExec(TCB *t, StrongRef<Node> file, const ExecFiles &files,
                     const char *path, char *const argv[], char *const envp[],
                     const StackInfo &stack, uint64_t stackSize) {
    CCB::current()->current_thread = t;
    auto mainImage = co_await ELF::map(file, files.mainInfo, ELF::PLACE_MAIN);
    if (!mainImage.ok) co_return false;

    uint64_t entry = mainImage.entry;
    uint64_t interpBias = 0;
    if (files.mainInfo.hasInterp) {
        auto interpImage = co_await ELF::map(files.interpFile, files.interpInfo, ELF::PLACE_INTERP);
        if (!interpImage.ok) co_return false;
        entry = interpImage.entry;
        interpBias = interpImage.bias;
    }

    int prot = VMM::PROT_READ | VMM::PROT_WRITE;
    if (files.mainInfo.stackExec) prot |= VMM::PROT_EXEC;
    if (!co_await t->setup_stack(stackSize, prot)) co_return false;

    const uintptr_t sp = writeStack(t, path, argv, envp, stack, mainImage, interpBias);
    t->context = UserContext{};
    t->context.rip = entry;
    t->context.rsp = sp;
    t->context.rflags = FORCED_FLAGS;
    co_return true;
}
} // namespace

sync<StrongRef<TCB>> PCB::create(StrongRef<Node> init, uint64_t stack_size) {
    StrongRef<PCB> pcb{new PCB{provision_pid()}};
    pcb->self = WeakRef{pcb};
    pcb->cwd = fs->root;
    { LockGuard g{pid_lock}; process_table.put(pcb->pid, WeakRef{pcb}); }

    StrongRef<TCB> thread = co_await pcb->create_thread();
    if (thread == nullptr) {
        pcb->finish(127);
        co_return StrongRef<TCB>{};
    }

    char path[] = "/sbin/init";
    char *argv[] = {path, nullptr};
    char *envp[] = {nullptr};
    ExecFiles files{};
    StackInfo stack{};
    const int64_t error = co_await prepareExec(init, pcb->get_cwd(), files);
    bool ready = !error && measureStack(path, argv, envp, stack_size, stack) && fillRandom(stack);
    if (ready) {
        ready = co_await startExec(thread.operator->(), init, files, path, argv, envp, stack, stack_size);
    }
    if (!ready) {
        thread->zombie = true;
        pcb->finish(127);
        CCB::current()->current_thread = nullptr;
        drop_to_kernel_cr3();
        co_return StrongRef<TCB>{};
    }
    co_return thread;
}

sync<StrongRef<PCB>> PCB::fork(const UserContext &ctx) {
    StrongRef<PCB> child{new PCB{provision_pid()}};
    child->self = WeakRef{child};
    child->ppid = pid;
    child->set_cwd(get_cwd());
    {
        LockGuard g{signal_lock};
        for (int i = 0; i < 16; ++i) child->actions[i] = actions[i];
    }
    child->fd_table.copy_from(fd_table);
    { LockGuard g{pid_lock}; process_table.put(child->pid, WeakRef{child}); }

    co_await VMM::copy_address_space(as, child->as);

    forkLock.lock();
    child->sibling = children;
    children = child;
    forkLock.unlock();

    StrongRef<TCB> thread{new TCB{child, ctx, TCB::provision_tid()}};
    thread->self = WeakRef{thread};
    thread->anchor = thread;
    thread->context.rax = 0;
    auto *caller = CCB::current()->current_thread;
    thread->blocked_signals = caller->blocked_signals;
    thread->signal_frame = caller->signal_frame;
    child->leader = child->tail = thread.operator->();

    auto alive = co_await child->alive_threads;
    alive.data() = 1;

    thread_queue.add(thread);
    co_return child;
}

void free_strings(char **v) {
    for (char **s = v; *s; s++) delete[] *s;
    delete[] v;
}

sync<uint64_t> PCB::exec(TCB *t, StrongRef<Node> file, const char *path, char **argv, char **envp) {
    ExecFiles files{};
    StackInfo stack{};
    int64_t error = co_await prepareExec(file, get_cwd(), files);
    if (!error && !measureStack(path, argv, envp, PROCESS_STACK_SIZE, stack)) {
        error = Syscall::E2BIG;
    }
    if (!error && !fillRandom(stack)) {
        error = Syscall::EIO;
    }
    if (error) {
        free_strings(argv);
        free_strings(envp);
        co_return error;
    }

    for (TCB *s = leader; s; s = s->next_process) {
        if (s == t || s->zombie) continue;
        co_await s->clear_tid();
        s->zombie = true;
        s->exit_code.set(0);
    }

    // no other core may still be running the old address space
    co_await DrainDeadMm{as->cr3_phys()};

    for (TCB *s = leader; s;) {
        TCB *next = s->next_process;
        if (s != t) {
            StrongRef<TCB> hold{s->self};
            s->anchor = nullptr;
        }
        s = next;
    }
    leader = tail = t;
    t->next_process = nullptr;
    t->clear_tid_addr = 0;
    t->signal_frame = 0;
    {
        LockGuard g{signal_lock};
        for (auto &a : actions) if (a.handler != 1) a = {};
    }

    auto alive = co_await alive_threads;
    alive.data() = 1;

    fd_table.exec_triggered();

    CCB::current()->current_thread = t;
    co_await VMM::reset(as);
    {
        auto mapping = co_await as->vma_list_lock;
        as->memory_areas = AddressSpace::initial_areas();
    }
    set_cr3(as->cr3_phys());

    const bool ok = co_await startExec(t, file, files, path, argv, envp, stack, PROCESS_STACK_SIZE);

    free_strings(argv);
    free_strings(envp);

    if (!ok) {
        // the old image is already gone, so the only option left is to end the process
        t->zombie = true;
        finish(127);
    }
    co_return 0;
}

sync<StrongRef<TCB>> PCB::create_thread()
{
    if (get_cr3() != as->cr3_phys()) set_cr3(as->cr3_phys());

    auto alive = co_await alive_threads;
    if (leader != nullptr && alive.data() == 0) co_return StrongRef<TCB>{};

    StrongRef pcb{self};

    StrongRef t{new TCB{pcb, TCB::provision_tid()}};
    t->self = WeakRef{t};
    t->anchor = t;

    if (leader == nullptr) leader = tail = t.operator->();
    else { tail->next_process = t.operator->(); tail = t.operator->(); }

    alive.data() += 1;

    co_return t;
}

sync<uint64_t> PCB::wait_child(uint64_t pid, bool &found)
{
    StrongRef<PCB> child;
    found = false;

    forkLock.lock();
    for (auto *link = &children; *link != nullptr; link = &(*link)->sibling) {
        if ((*link)->pid == pid) { child = *link; found = true; break; }
    }
    forkLock.unlock();
    if (!found) co_return 0;

    uint64_t code = co_await child->exit_code;

    forkLock.lock();
    for (auto *link = &children; *link != nullptr; link = &(*link)->sibling) {
        if ((*link)->pid == pid) { *link = child->sibling; break; }
    }
    forkLock.unlock();

    co_return child->death_signal ? child->death_signal : ((code & 0xff) << 8);
}

void PCB::finish(uint64_t code)
{
    {
        LockGuard g{signal_lock};
        if (finished) return;
        finished = true;
        alarm_deadline = 0;
    }
    this->exit_code.set(code);
    { LockGuard g{pid_lock}; process_table.remove(pid); }
    fd_table.destroy();
    forkLock.lock();
    for (auto child = children; child != nullptr; child = child->sibling) child->ppid = 1; // orphaned
    forkLock.unlock();
    free_mm(StrongRef{self});
}

int64_t PCB::send_signal(int64_t pid, uint32_t sig, uint32_t sender) {
    StrongRef<PCB> target;
    {
        LockGuard g{pid_lock};
        auto p = process_table.get(pid);
        if (!p.has_value()) return Syscall::ESRCH;
        target = *p;
    }
    if (target == nullptr) return Syscall::ESRCH;
    LockGuard g{target->signal_lock};
    if (target->finished) return Syscall::ESRCH;
    if (sig && target->actions[sig].handler != 1) {
        uint64_t bit = 1ull << (sig - 1);
        if (!(target->pending & bit)) target->signal_sender[sig] = sender;
        target->pending |= bit;
    }
    return 0;
}

void PCB::terminate(uint32_t sig) {
    {
        LockGuard g{signal_lock};
        if (finished) return;
        death_signal = sig;
        for (TCB *t = leader; t; t = t->next_process) t->zombie = true;
    }
    finish(0);
}

namespace {
bool signal_range(uint64_t address, uint64_t len) {
    if (address < VMM::VA_START.va() || address >= VMM::VA_END || len > VMM::VA_END - address) return false;
    return true;
}

// Linux x86-64 ucontext prefix, including the gregset indices used by handlers.
struct SignalContext {
    uint64_t flags, link, stack[3], regs[23], fpregs, reserved[8], mask, mask_padding[15];
};
struct SignalFrame {
    uint64_t restorer;
    SignalContext uc;
    alignas(8) uint8_t info[128];
    uint64_t previous;
    UserContext saved;
    uint8_t fpstate[512 + 15]; // user RSP is 8 mod 16; align the FXSAVE image separately
};
void export_regs(SignalContext &u, const UserContext &c) {
    uint64_t r[] = {c.r8,c.r9,c.r10,c.r11,c.r12,c.r13,c.r14,c.r15,c.rdi,c.rsi,c.rbp,c.rbx,
                    c.rdx,c.rax,c.rcx,c.rsp,c.rip,c.rflags,
                    (uint64_t(GDT::USER_DS)<<48)|GDT::USER_CS,0,0,0,0};
    memcpy(u.regs, r, sizeof(r));
}
void import_regs(UserContext &c, const SignalContext &u) {
    c.r8=u.regs[0]; c.r9=u.regs[1]; c.r10=u.regs[2]; c.r11=u.regs[3];
    c.r12=u.regs[4]; c.r13=u.regs[5]; c.r14=u.regs[6]; c.r15=u.regs[7];
    c.rdi=u.regs[8]; c.rsi=u.regs[9]; c.rbp=u.regs[10]; c.rbx=u.regs[11];
    c.rdx=u.regs[12]; c.rax=u.regs[13]; c.rcx=u.regs[14];
    c.rsp=u.regs[15]; c.rip=u.regs[16]; c.rflags=(u.regs[17] & USER_FLAGS)|FORCED_FLAGS;
}
}

bool TCB::deliver_signal(int forced, uintptr_t address, int code) {
    StrongRef<TCB> hold{self}; // termination may concurrently release the process-list pin
    PCB::SignalAction action;
    uint32_t sender = 0;
    int sig = forced;
    {
        LockGuard g{process->signal_lock};
        if (zombie) return false;
        if (process->alarm_deadline && rdtsc() >= process->alarm_deadline) {
            process->alarm_deadline = 0;
            process->pending |= 1ull<<13;
            process->signal_sender[14] = 0;
        }
        if (!sig) {
            uint64_t ready = process->pending & ~blocked_signals;
            while (ready) {
                sig = __builtin_ctzll(ready) + 1;
                process->pending &= ~(1ull << (sig-1));
                if (process->actions[sig].handler != 1) break;
                ready &= ~(1ull << (sig-1));
                sig = 0;
            }
        }
        if (!sig) return true;
        action = process->actions[sig];
        sender = process->signal_sender[sig];
    }
    if (action.handler <= 1 || (forced && (blocked_signals & (1ull<<(sig-1))))) {
        process->terminate(sig);
        return false;
    }
    // Preserve the ABI red zone; handler entry has RSP == 8 (mod 16).
    uint64_t sp = ((context.rsp - 128 - sizeof(SignalFrame)) & ~15ull) - 8;
    if (!signal_range(sp, sizeof(SignalFrame)) ||
        action.handler >= VMM::VA_END || action.restorer >= VMM::VA_END) {
        process->terminate(11);
        return false;
    }
    SignalFrame frame{};
    frame.restorer = action.restorer;
    frame.previous = signal_frame;
    frame.saved = context;
    frame.uc.mask = blocked_signals;
    frame.uc.fpregs = (sp + offsetof(SignalFrame, fpstate) + 15) & ~15ull;
    memcpy(reinterpret_cast<uint8_t*>(&frame) + frame.uc.fpregs - sp, context.fpu, sizeof(context.fpu));
    export_regs(frame.uc, context);
    auto *info = reinterpret_cast<int32_t*>(frame.info);
    info[0] = sig; info[2] = forced ? code : sender == 0 ? 128 : 0;
    if (forced) memcpy(frame.info + 16, &address, sizeof(address));
    else info[4] = sender;
    if (VMM::copy_user_((void*)sp, &frame, sizeof(frame))) {
        process->terminate(11);
        return false;
    }
    signal_frame = sp;
    blocked_signals |= (action.mask | (1ull<<(sig-1))) & PCB::SIGNALS;
    context.rsp = sp;
    context.rip = action.handler;
    context.rdi = sig;
    context.rsi = sp + offsetof(SignalFrame, info);
    context.rdx = sp + offsetof(SignalFrame, uc);
    context.rax = 0;
    return true;
}

bool TCB::restore_signal() {
    if (!signal_frame || !signal_range(signal_frame, sizeof(SignalFrame))) return false;
    SignalFrame frame;
    if (VMM::copy_user_(&frame, (void*)signal_frame, sizeof(frame))) return false;
    if (frame.uc.regs[15] >= VMM::VA_END || frame.uc.regs[16] >= VMM::VA_END ||
        frame.saved.fs_base >= VMM::VA_END || frame.saved.gs_base >= VMM::VA_END) return false;
    context = frame.saved;
    import_regs(context, frame.uc);
    if (frame.uc.fpregs) {
        if (!signal_range(frame.uc.fpregs, sizeof(context.fpu)) ||
            VMM::copy_user_(context.fpu, (void*)frame.uc.fpregs, sizeof(context.fpu))) return false;
    }
    blocked_signals = frame.uc.mask & PCB::SIGNALS;
    signal_frame = frame.previous;
    // fxrstor rejects reserved MXCSR bits.
    *reinterpret_cast<uint32_t*>(context.fpu + 24) &= 0x0000ffbf;
    return true;
}

[[noreturn]] void TCB::resume() {
    CCB *ccb = CCB::current();
    if (zombie) {
        ccb->current_thread = nullptr;
        drop_to_kernel_cr3();
        bounce_to_yield_();
    }
    ccb->current_thread = this;

    if (get_cr3() != process->as->cr3_phys())
      set_cr3(process->as->cr3_phys());

    if (!deliver_signal()) {
        ccb->current_thread = nullptr;
        drop_to_kernel_cr3();
        bounce_to_yield_();
    }

    wrfsbase(context.fs_base);
    Msr::KernelGSBase().write(context.gs_base);

    Msr::LVTTimerRegister().write(TIMER_VECTOR);
    Msr::DivideConfigurationRegister().write(0xB);
    Msr::InitialCountRegister().write(Sys::quantum_ticks);

    resume_user_(&context);
}

} // namespace

extern "C" void timerHandler(bool from_user) {
  Msr::EOI().write(0);
  if (!from_user) return;

  auto *ccb = impl::CCB::current();
  impl::TCB *raw = ccb->current_thread;
  ccb->current_thread = nullptr;
  impl::drop_to_kernel_cr3();
  if (raw->zombie) return;
  raw->preempted = true;
  impl::thread_queue.add(StrongRef<impl::TCB>{raw->self});
}

extern "C" bool killHandler(bool from_user) {
  Msr::EOI().write(0);

  impl::DrainDeadMm::ack_all();

  auto *ccb = impl::CCB::current();
  bool bounce = from_user && ccb->current_thread && ccb->current_thread->zombie;
  if (bounce) {
    ccb->current_thread = nullptr;
    impl::drop_to_kernel_cr3();
  }

  return bounce;
}
