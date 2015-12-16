
import re

TUPLES = [
    ("kprobe::sys_read:entry", ("kprobe", "", "sys_read", "entry")),
    ("::sys_read:", ("", "", "sys_read", "")),
    ("sys_read", ("", "", "sys_read", "")),
]

for (t, grps) in TUPLES:
    m = re.match(r"(([a-zA-Z0-9_*]*):?){0,3}(
