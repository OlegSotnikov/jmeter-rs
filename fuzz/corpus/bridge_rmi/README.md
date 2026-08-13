# `bridge_rmi` corpus

These are small, hand-authored byte seeds for the pure Rust RMI codec/state
target. They are original inputs, not captured JMeter/RMI traffic and contain
no credentials, plans, JVM artifacts, or network data. The target derives
bounded deterministic lifecycle traces from each seed, so the text seeds are
also useful for exercising overload, sender-mode, replay/gap, credit/ack, and
limit branches without starting a Java helper or transport.
