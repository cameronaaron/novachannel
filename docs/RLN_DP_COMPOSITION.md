# RLN and cover traffic: composition claim withdrawn

The previous analysis incorrectly applied pure differential-privacy composition
to `DummyScheduler`. Its premise fails before RLN enters the analysis.

With `q = exp(-epsilon)`, silence has probability `1-q` in an empty slot
and zero in a real slot. For positive epsilon, the DP inequality for this
ordered pair is `1-q <= exp(epsilon) * 0`, which is false. Bounding only
the send event in the opposite direction does not prove DP. See
[Dwork and Roth, Definition 2.4](https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf).

`sequential_epsilon`, `advanced_composition_epsilon`, and `Budget` therefore
cannot account for this scheduler's privacy loss. RLN rate limiting and
independent random draws do not repair the missing single-slot guarantee.

At epsilon zero, every slot transmits. This hides the presence bit only if
real and dummy packets are indistinguishable in size, framing, and timing.
The caller must keep its transmission grid independent of arrivals, queue
state, budget exhaustion, and application responses. This is not an
end-to-end anonymity or unlinkability proof.

A positive-epsilon replacement requires a different mechanism and explicit
latency/delivery semantics, with both directions and both observable outcomes
tested. The existing always-deliver behavior is retained; it must not be
marketed as pure differential privacy.
