# Pinned CLI resources

`help.txt` is the Apache JMeter 5.6.3 help resource from pinned source
revision `34a2785748e9e0b14702595e8682c387869deda3`:

<https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/resources/org/apache/jmeter/help.txt>

It is retained under the Apache License, Version 2.0, for deterministic CLI
output. No generated JMeter distribution or binary is included.

`jmeter_as_ascii_art.txt` is the matching launcher resource from the same
revision:

<https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/launcher/src/main/resources/org/apache/jmeter/jmeter_as_ascii_art.txt>

The upstream `@VERSION@` and `@YEAR@` build placeholders are expanded by the
application to the pinned release values (`5.6.3` and `2024`) at render time.
