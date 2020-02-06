#!/bin/sh

total_fails=0

fail()
{
    echo "  FAIL $case expected \"$1\", got \"$2\""
    total_fails=$(($total_fails + 1))
}

ply_simple()
{
    stdout=$(ply -c true "tracepoint:sched/sched_process_exit { ${1} }")
    code=$?
}


case=exit && ply_simple 'exit(42);' && \
    [ $code -eq 42 ] || fail 42 $code

case=if-stmt && ply_simple 'if (pid > 1) exit(0); else exit(1);' && \
    [ $code -eq 0 ] || fail 0 $code

case=print && ply_simple 'print("test"); exit(0);' && \
    [ $stdout = test ] || fail test "$stdout"


exit $total_fails
