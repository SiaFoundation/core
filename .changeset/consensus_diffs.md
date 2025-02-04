---
default: major
---

# Consensus diffs

#270 by @lukechampine

This replaces the `ForEach` update API with slices of "diffs" -- new types wrapping the various element types. This was originally intended as an ergonomics improvement (since it's annoying to e.g. break out of a `ForEach` callback), but it ended up significantly simplifying most `MidState`-related code: it consolidated the interrelated maps within `MidState`, and enabled a much saner rewrite of the update JSON types.

I originally left the `ForEach` methods in place (with a `// Deprecated` warning), but later removed them entirely; we're going to update all the callsites in `coreutils` anyway, so there's little reason to keep them around. (`ForEachTreeNode` remains, though, since it's used by `explored`.)
