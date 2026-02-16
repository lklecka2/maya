set pagination off
set confirm off
set $count = 0

starti

printf "Skipping %d instructions...\n", $skip
while ($count < $skip)
    stepi
    set $count = $count + 1
end

set logging file trace.log
set logging overwrite on
set logging enabled on

while ($count < $max)
    if $_thread == 0
        loop_break
    end
    printf "Inst %d | PC: %p | ", $count, $pc
    x/i $pc
    stepi
    set $count = $count + 1
end

set logging enabled off
quit
