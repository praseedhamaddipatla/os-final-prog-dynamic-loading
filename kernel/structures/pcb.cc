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
// Eight auxiliary values, followed by AT_NULL, 0.
constexpr uint64_t AUX_PAIRS = 9;
struct ExecPlan {
    ELF::Info mainInfo{}, interpInfo{};
    StrongRef<Node> interpFile{};
    uint64_t argc = 0, envc = 0;
    uint8_t random[16]{};
};

// Use CPU entropy rather than predictable timestamps for AT_RANDOM. A CPU
// without RDRAND (or a temporarily exhausted generator) fails before teardown.
bool exec_random(uint8_t (&bytes)[16]) {
    uint32_t eax, ebx, ecx, edx;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if (!(ecx & (1u << 30))) return false;
    for (unsigned i = 0; i < sizeof(bytes); i += sizeof(uint64_t)) {
        uint64_t value = 0;
        unsigned char ready = 0;
        for (int tries = 0; tries < 64 && !ready; ++tries)
            asm volatile("rdrand %0; setc %1" : "=&r"(value), "=qm"(ready) : : "cc");
        if (!ready) return false;
        memcpy(bytes + i, &value, sizeof(value));
    }
    return true;
}

// Validate everything we can while the caller's old image is still intact.
sync<int64_t> prepareExec(StrongRef<Node> file, StrongRef<Node> cwd,
                          const char *path, const char *const *argv,
                          const char *const *envp, uint64_t stack_size,
                          ExecPlan &plan) {
    plan.mainInfo = co_await ELF::parse(file);
    if (!plan.mainInfo.ok) co_return Syscall::ENOEXEC;
    if (plan.mainInfo.hasInterp) {
        auto found = co_await fs->find(cwd, plan.mainInfo.interp);
        if (found.error) co_return found.error;
        plan.interpFile = found.file;
        if (!co_await plan.interpFile->is_file()) co_return Syscall::EACCES;
        plan.interpInfo = co_await ELF::parse(plan.interpFile);
        if (!plan.interpInfo.ok || !plan.interpInfo.isPie || plan.interpInfo.hasInterp)
            co_return Syscall::ENOEXEC;
    }

    // argc, argv NULL, envp NULL, auxv, random bytes, and worst-case alignment.
    uint64_t remaining = stack_size & ~uint64_t(15);
    const uint64_t fixed = (3 + AUX_PAIRS * 2) * sizeof(uint64_t) + 16 + 15;
    if (remaining < fixed) co_return Syscall::E2BIG;
    remaining -= fixed;
    auto account = [&remaining](uint64_t n) {
        if (n > remaining) return false;
        remaining -= n;
        return true;
    };
    if (!account(strlen(path) + 1)) co_return Syscall::E2BIG;
    while (argv[plan.argc]) {
        if (!account(sizeof(uint64_t)) || !account(strlen(argv[plan.argc]) + 1))
            co_return Syscall::E2BIG;
        ++plan.argc;
    }
    while (envp[plan.envc]) {
        if (!account(sizeof(uint64_t)) || !account(strlen(envp[plan.envc]) + 1))
            co_return Syscall::E2BIG;
        ++plan.envc;
    }
    if (!exec_random(plan.random)) co_return Syscall::EAGAIN;
    co_return 0;
}

uint64_t build_stack(TCB *t, const ExecPlan &plan, const char *path,
                     const char *const *argv, const char *const *envp,
                     const ELF::Loaded &mainImage, const ELF::Loaded &interpImage) {
    uint64_t p = t->context.rsp;
    auto copy = [&p](const void *src, uint64_t n) {
        p -= n;
        memcpy((void *)p, src, n);
        return p;
    };
    const uint64_t execfn = copy(path, strlen(path) + 1);
    const uint64_t random = copy(plan.random, sizeof(plan.random));
    const uint64_t count = plan.argc + plan.envc;
    auto *ptrs = new uint64_t[count];
    for (uint64_t i = count; i-- > 0;) {
        const char *s = i < plan.argc ? argv[i] : envp[i - plan.argc];
        ptrs[i] = copy(s, strlen(s) + 1);
    }

    const uint64_t words = count + 3 + AUX_PAIRS * 2;
    auto *sp = (uint64_t *)((p - words * sizeof(uint64_t)) & ~uint64_t(15));
    ASSERT((uint64_t)sp >= t->stack_base);
    uint64_t n = 0;
    sp[n++] = plan.argc;
    for (uint64_t i = 0; i < plan.argc; ++i) sp[n++] = ptrs[i];
    sp[n++] = 0;
    for (uint64_t i = 0; i < plan.envc; ++i) sp[n++] = ptrs[plan.argc + i];
    sp[n++] = 0;
    delete[] ptrs;

    auto aux = [sp, &n](uint64_t type, uint64_t value) {
        sp[n++] = type;
        sp[n++] = value;
    };
    aux(9, mainImage.entry);  // AT_ENTRY always names the executable.
    aux(3, mainImage.phdr);  // AT_PHDR
    aux(4, mainImage.phent); // AT_PHENT
    aux(5, mainImage.phnum); // AT_PHNUM
    aux(7, interpImage.bias); // AT_BASE is the interpreter's load bias.
    aux(6, FRAME_SIZE);      // AT_PAGESZ
    aux(31, execfn);         // AT_EXECFN is independent of argv[0].
    aux(25, random);         // AT_RANDOM
    aux(0, 0);               // AT_NULL
    ASSERT(n == words);
    return (uint64_t)sp;
}

// Shared by boot and exec: images first, then the stack, then user registers.
sync<bool> start_image(TCB *t, StrongRef<Node> file, const ExecPlan &plan,
                       const char *path, const char *const *argv,
                       const char *const *envp, uint64_t stack_size) {
    CCB::current()->current_thread = t;
    auto mainImage = co_await ELF::map(file, plan.mainInfo, ELF::PLACE_MAIN);
    if (!mainImage.ok) co_return false;
    ELF::Loaded interpImage{};
    if (plan.mainInfo.hasInterp) {
        interpImage = co_await ELF::map(plan.interpFile, plan.interpInfo, ELF::PLACE_INTERP);
        if (!interpImage.ok) co_return false;
    }
    int prot = VMM::PROT_READ | VMM::PROT_WRITE;
    if (plan.mainInfo.hasStack && plan.mainInfo.stackExec) prot |= VMM::PROT_EXEC;
    if (!co_await t->setup_stack(stack_size, prot)) co_return false;
    const uint64_t sp = build_stack(t, plan, path, argv, envp, mainImage, interpImage);
    t->context = UserContext{};
    t->context.rip = plan.mainInfo.hasInterp ? interpImage.entry : mainImage.entry;
    t->context.rsp = sp;
    t->context.rflags = FORCED_FLAGS;
    co_return true;
}
} // namespace

sync<StrongRef<TCB>> PCB::create(StrongRef<Node> init, uint64_t stack_size) {
  const char *argv[] = {"/sbin/init", nullptr};
  const char *envp[] = {nullptr};
  ExecPlan plan;
  if (co_await prepareExec(init, fs->root, "/sbin/init", argv, envp, stack_size, plan))
    co_return StrongRef<TCB>{};

  StrongRef<PCB> pcb{new PCB{provision_pid()}};
  pcb->self = WeakRef{pcb};
  pcb->cwd = fs->root;
  { LockGuard g{pid_lock}; process_table.put(pcb->pid, WeakRef{pcb}); }

  StrongRef<TCB> thread = co_await pcb->create_thread(0);
  if (!co_await start_image(thread.operator->(), init, plan, "/sbin/init", argv, envp, stack_size)) {
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
    ExecPlan plan;
    const int64_t error = co_await prepareExec(file, get_cwd(), path, argv, envp, PROCESS_STACK_SIZE, plan);
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

    const bool ok = co_await start_image(t, file, plan, path, argv, envp, PROCESS_STACK_SIZE);

    free_strings(argv);
    free_strings(envp);

    if (!ok) {
        // the old image is already gone, so the only option left is to end the process
        t->zombie = true;
        finish(127);
    }
    co_return 0;
}

sync<StrongRef<TCB>> PCB::create_thread(uint64_t stack_size)
{
    if (get_cr3() != as->cr3_phys()) set_cr3(as->cr3_phys());

    auto alive = co_await alive_threads;
    if (leader != nullptr && alive.data() == 0) co_return StrongRef<TCB>{};

    StrongRef pcb{self};

    StrongRef t{new TCB{pcb, TCB::provision_tid()}};
    t->self = WeakRef{t};
    // Boot defers stack allocation until both ELF images have been mapped.
    if (stack_size && !co_await t->setup_stack(stack_size)) co_return StrongRef<TCB>{};
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
