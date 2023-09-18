// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include "snmalloc/backend_helpers/defaultpagemapentry.h"

#include <snmalloc/snmalloc_core.h>

namespace sandbox
{
  /**
   * Pagemap entry.  Extends the front-end's version to use one bit to identify
   * pagemap entries as owned by the child.
   */
  class SandboxMetaEntry
  : public snmalloc::FrontendMetaEntry<snmalloc::DefaultSlabMetadata>
  {
    /**
     * Bit set if this metaentry is owned by the sandbox.
     */
    static constexpr snmalloc::address_t SANDBOX_BIT = 1 << 3;

    /**
     * Helper type for the superclass that we inherit from.
     */
    using Super = snmalloc::FrontendMetaEntry<snmalloc::DefaultSlabMetadata>;

  public:
    /**
     * Inherit all constructors.
     */
    using Super::FrontendMetaEntry;

    /**
     * Does this metaentry correspond to sandbox-owned memory
     */
    bool is_sandbox_owned() const
    {
      return (Super::meta & SANDBOX_BIT) == SANDBOX_BIT;
    }

    /**
     * Claim this entry for the sandbox.
     */
    void claim_for_sandbox()
    {
      Super::meta |= SANDBOX_BIT;
    }

    [[nodiscard]] bool is_unowned() const
    {
      auto m = Super::meta & ~SANDBOX_BIT;
      return ((m == 0) || (m == Super::META_BOUNDARY_BIT)) &&
        (Super::remote_and_sizeclass == 0);
    }

    [[nodiscard]] SNMALLOC_FAST_PATH snmalloc::DefaultSlabMetadata*
    get_slab_metadata() const
    {
      SNMALLOC_ASSERT(Super::get_remote() != nullptr);
      auto m = Super::meta & ~(SANDBOX_BIT | Super::META_BOUNDARY_BIT);
      return snmalloc::unsafe_from_uintptr<snmalloc::DefaultSlabMetadata>(m);
    }
  };
}
