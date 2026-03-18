---
default: patch
---

# Add contract not found error

#391 by @chris124567

Re: https://github.com/SiaFoundation/coreutils/issues/405

Will need to update hostd to use this error instead of `go.sia.tech/hostd/host/contracts.ErrNotFound`
