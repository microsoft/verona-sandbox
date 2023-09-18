// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#include <cctype>
#ifdef __FreeBSD__
#  include "../callback_numbers.h"

#  include <array>
#  include <sys/syscall.h>
#  include <ucontext.h>
#  include <utility>
#  ifdef __aarch64__
#    include <machine/armreg.h>
#  endif

namespace sandbox::platform
{
#  ifdef __x86_64__
  struct MContextFreeBSD
  {
  public:
    /**
     * The system call registers, according to the x86-64 System-V ABI
     * specification.
     */
    static constexpr std::array<register_t mcontext_t::*, 6> syscallArgRegs{
      &mcontext_t::mc_rdi,
      &mcontext_t::mc_rsi,
      &mcontext_t::mc_rdx,
      &mcontext_t::mc_r10,
      &mcontext_t::mc_r8,
      &mcontext_t::mc_r9,
    };
    /**
     * Returns the system call argument in argument register `index`.
     */
    static register_t syscall_arg(ucontext_t& ctx, int index)
    {
      return ctx.uc_mcontext.*syscallArgRegs.at(index);
    }

    /**
     * Set a successful error return value.  FreeBSD returns this in the first
     * return register.  On x86, it clears the carry flag to indicate a
     * successful return.  This does not need to update the program counter
     * because this is set to the syscall return by Capsicum.
     */
    static void set_success_return(ucontext_t& ctx, intptr_t r)
    {
      // Clear the carry flag to indicate success
      ctx.uc_mcontext.mc_rflags &= ~1;
      // Set the return value
      ctx.uc_mcontext.mc_rax = static_cast<register_t>(r);
    }

    /**
     * Set an unsuccessful error return value.  FreeBSD returns this in the
     * first return register.  On x86, it sets the carry flag to indicate an
     * unsuccessful return.  This does not need to update the program counter
     * because this is set to the syscall return by Capsicum.
     */
    static void set_error_return(ucontext_t& ctx, int e)
    {
      // Indicate that this is an error return by setting the carry flag
      ctx.uc_mcontext.mc_rflags |= 1;
      // Store the errno value in the return register
      ctx.uc_mcontext.mc_rax = static_cast<register_t>(e);
    }
  };

#  elif defined(__aarch64__)
  struct MContextFreeBSD
  {
    /**
     * AArch64 sustem call arguments are passed in registers X0-X5.  Returns the
     * register corresponding to argument `index`.
     */
    static register_t syscall_arg(ucontext_t& ctx, int index)
    {
      return ctx.uc_mcontext.mc_gpregs.gp_x[index];
    }

    /**
     * Set a successful error return value.  FreeBSD returns this in the first
     * return register.  On x86, it clears the carry flag to indicate a
     * successful return.  This does not need to update the program counter
     * because this is set to the syscall return by Capsicum.
     */
    static void set_success_return(ucontext_t& ctx, intptr_t r)
    {
      // Clear the carry flag to indicate success
      ctx.uc_mcontext.mc_gpregs.gp_spsr &= ~PSR_C;
      // Set the return value
      ctx.uc_mcontext.mc_gpregs.gp_x[0] = static_cast<register_t>(r);
    }

    /**
     * Set an unsuccessful error return value.  FreeBSD returns this in the
     * first return register.  On x86, it sets the carry flag to indicate an
     * unsuccessful return.  This does not need to update the program counter
     * because this is set to the syscall return by Capsicum.
     */
    static void set_error_return(ucontext_t& ctx, int e)
    {
      // Indicate that this is an error return by setting the carry flag
      // Clear the carry flag to indicate success
      ctx.uc_mcontext.mc_gpregs.gp_spsr |= PSR_C;
      // Store the errno value in the return register
      ctx.uc_mcontext.mc_gpregs.gp_x[0] = static_cast<register_t>(e);
    }
  };
#  else
#    error Your architecture is not yet supported
#  endif

  /**
   * Machine-independent FreeBSD system call information.  Takes one of the
   * above classes that understands the platform-specific mcontext_t as a
   * template parameter.
   */
  template<typename MContext>
  class SyscallFrameFreeBSDMI
  {
    /**
     * The siginfo structure passed to the signal handler.
     */
    siginfo_t& info;

    /**
     * The context structure containing the complete register contents where
     * the system call was delivered.
     */
    ucontext_t& ctx;

    /**
     * Is this a `syscall` instruction?  This is a special system call that
     * takes the system call number in the first argument register and so every
     * argument is one later.
     */
    bool is_syscall()
    {
      // This check works only on newer FreeBSD systems that provide si_syscall.
      // Once support for this is MFC'd to all supporting branches and a release
      // has happened from them then the fallback codepaths should all be
      // deleted from here.  At the time of writing, it is in 14, not yet merged
      // back to 12.x or 13.x.
#  ifdef si_syscall
      return (info.si_syscall == SYS_syscall) ||
        (info.si_syscall == SYS___syscall);
#  else
      return false;
#  endif
    }

    /**
     * FreeBSD system call numbers.  These must be kept in the same order as
     * the callback numbers.  Each entry is a pair of the callback number
     * followed by the corresponding system-call number.  This is accessed only
     * by a wrapper that provides a compile-tine check that the entries are in
     * the correct order.
     */
    static constexpr std::
      array<std::pair<CallbackKind, int>, SyscallCallbackCount>
        SyscallNumbers{
          std::make_pair(Open, SYS_open),
          {Stat, SYS_freebsd11_stat},
          {Access, SYS_access},
          {OpenAt, SYS_openat},
          {Bind, SYS_bind},
          {Connect, SYS_connect},
        };

  public:
    /**
     * Compile-time lookup of a system call number that corresponds to a given
     * callback.  May return -1 if there is no matching system call.
     */
    template<CallbackKind K>
    static constexpr int syscall_number()
    {
      static_assert(
        K < SyscallNumbers.size(), "Callback number is out of range");
      static_assert(
        SyscallNumbers[K].first == K,
        "SyscallNumbers array layout is incorrect!");
      return SyscallNumbers[K].second;
    }

    /**
     * The signal delivered for a Capsicum-disallowed system call.
     */
    static constexpr int syscall_signal =
#  ifdef SIGCAP
      SIGCAP
#  else
      SIGTRAP
#  endif
      ;

    /**
     * Constructor.  Takes the arguments to a signal handler.
     */
    SyscallFrameFreeBSDMI(siginfo_t& i, ucontext_t& c) : info(i), ctx(c) {}

    /**
     * Get the syscall argument at index `Arg`, cast to type `T`.
     */
    template<int Arg, typename T = uintptr_t>
    T get_arg()
    {
      static_assert(
        Arg < 5,
        "Unable to access more than 6 arguments, including the syscall number "
        "for the 'syscall' system call");
      static_assert(
        std::is_integral_v<T> || std::is_pointer_v<T>,
        "Syscall arguments can only be accessed as integers or pointers");
      auto cast = [](register_t val) {
        if constexpr (std::is_integral_v<T>)
        {
          return static_cast<T>(val);
        }
        if constexpr (std::is_pointer_v<T>)
        {
          return reinterpret_cast<T>(static_cast<intptr_t>(val));
        }
      };
      return cast(MContext::syscall_arg(ctx, Arg + is_syscall()));
    }

    /**
     * Set a successful error return value.  FreeBSD returns this in the first
     * return register.  On x86, it clears the carry flag to indicate a
     * successful return.  This does not need to update the program counter
     * because this is set to the syscall return by Capsicum.
     */
    void set_success_return(intptr_t r)
    {
      MContext::set_success_return(ctx, r);
    }

    /**
     * Set an unsuccessful error return value.  FreeBSD returns this in the
     * first return register.  On x86, it sets the carry flag to indicate an
     * unsuccessful return.  This does not need to update the program counter
     * because this is set to the syscall return by Capsicum.
     */
    void set_error_return(int e)
    {
      MContext::set_error_return(ctx, e);
    }

    /**
     * Get the system call number.  This is passed into the signal handler, but
     * if this is a `syscall` system call then we need to access it from the
     * first argument.
     */
    int get_syscall_number()
    {
#  ifdef si_syscall
      return is_syscall() ? MContext::syscall_arg(ctx, 0) : info.si_syscall;
#  else
      return MContext::syscall_arg(ctx, 0);
#  endif
    }

    /**
     * Is this a Capsicum violation?
     */
    bool is_sandbox_policy_violation()
    {
      return info.si_code == TRAP_CAP;
    }
  };

  /**
   * Expose this as the FreeBSD syscall frame handler.
   */
  using SyscallFrameFreeBSD = SyscallFrameFreeBSDMI<MContextFreeBSD>;
} // namespace sandbox::platform
#endif
