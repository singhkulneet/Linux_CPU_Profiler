# Linux_CPU_Profiler
Introduction
------------

The goal of this project is to design a CPU profiling tool. The tool
will be designed as a kernel module which when loaded keeps track, for
each task, the time spent on CPU and the call stack of each task. The
module will display profiling result using the `proc` file system.


Recommended Background Reading
------------------------------

- `How to set up Kernel/QEMU <https://piazza.com/class/jzr3pguspxp6bp?cid=46>`__
- Kprobe: `documentation <https://github.com/torvalds/linux/blob/master/Documentation/kprobes.txt>`__, `examples <https://github.com/torvalds/linux/tree/master/samples/kprobes>`__
- x86_64 calling convention: `documentation <https://en.wikipedia.org/wiki/x86_calling_conventions>`__
- stack trace: `source code <https://github.com/torvalds/linux/blob/master/kernel/stacktrace.c>`__, `example <https://github.com/torvalds/linux/blob/master/mm/kmemleak.c>`__
- spinlock: `API <https://github.com/torvalds/linux/blob/master/include/linux/spinlock.h>`__
- Jenkins hash: `API <https://github.com/torvalds/linux/blob/master/include/linux/jhash.h>`__
- Time measurement (rdtsc): `API <https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/msr.h>`__
- Symbol look up: `API <https://github.com/torvalds/linux/blob/master/include/linux/kallsyms.h>`__


Part 1. Counting per task scheduling
------------------------------------

[3%] In part 1, you have to design a kernel module
which will count the number of times a task has been
scheduled into the CPU. To count the number of time a task
has been scheduled, you will use Kprobe, a debugging tool in
linux kernel which allows you to break at any kernel address.
Kprobes can programmed to be triggered when a certain function
is executed which in turn will will transfer the control to a
event handler routine.

Part 1.1. Setup procfs
~~~~~~~~~~~~~~~~~~~~~~

[1%] The results of the profiler tool will be displayed using
procfs. So first task is to setup a proc file for the profiler

Tasks:

- Write a kernel module named `perftop`
- `perftop` should create a proc file named `perftop`
- `cat /proc/perftop` should display "Hello World"

Deliverables:

- Load `perftop` module
- Invoke `cat /proc/perftop`
- Add screenshot of the output


Part 1.2. Setup Kprobe
~~~~~~~~~~~~~~~~~~~~~~

[1%] We will count the number of times the proc file we
created in the previous part is open using kprobe

Tasks:

- Understand API for Kprobe
- Kprobe should call a event handler every time `cat /proc/perftop` is invoked
- The event handler should increment a counter
- The counter should be displayed by `cat /proc/perftop`

Deliverables:

- Load `perftop` module
- Invoke `cat /proc/perftop` 3 times
- Add the screenshot of the three invocation in the same window


Part 1.3. Count number of times a PID is scheduled in
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

[1%] We will count the number of times a PID has been scheduled

Tasks:

- Setup a hash table with key as PIDs and value as number of schedules
- Setup kprobe hook to `pick_next_task_fair` function
- Using the register calling convention get the pointer of `task_struct`
- Using the `task_struct` get PID of the task
- If pid exists then increment the value in hash table otherwise
  create a new entry and set the value to 1
- Modify the open fuction of proc file to print the PIDs and corresponding
  number of schedules

Deliverables:

- Load `perftop` module
- Invoke `cat /proc/perftop`
- Add screenshot of the output
- Upload the source code tarball



Part 2. Print 20 most scheduleod kernel call stack with return address
----------------------------------------------------------------------

[6%] In part 2, you will modify the `perftop` to keep track
of time each kernel task spends on CPU and print the 20 most
scheduled tasks with the call stack using `proc`


Part 2.1. Storing stack trace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

[2%] Modify the module in previous part to count the number
of schedule of each task instead of each PID. Here task is defined as
a unique kernel stack.

Tasks:

- In the kprobe event handler, get the task's stack trace

   + Use `stack_trace_save` function for a kernel task
   + Use `save_stack_trace_user` function for a user task

- Modify hash table to store stack trace instead of PID
- Increment schedule count of stack trace in the hash table
- Modify the open function of proc file to print the stack trace
  and corresponding number of schedules

Deliverables:

- Load `perftop` module
- Invoke `cat /proc/perftop`
- Add screenshot of the output


Part 2.2. Store schedule time
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

[2%] Calculate the time spent by each task on CPU
and store it.

Task:

- Modify the kprobe event handler to measure time spent by task on CPU
  - Modify the hash table to store task and corresponding time spent on CPU
  - Measure time using `rdtsc` counter
  - When event handler is invoked:
    - A task is scheduled out and a new task is scheduled in
    - Calculate the time spent of CPU for scheduled out task and update
      hash table
    - Start the timer for the new task scheduled in
- Modify the open function proc file to print the stack trace and the accumulative
  time spent by the task on cpu. The time can be in rdtsc ticks.

Deliverables:

- Load `perftop` module
- Invoke `cat /proc/perftop`
- Add screenshot of the output


Part 2.3. Use rb-Tree to get 20 most scheduled tasks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

[2%] Modify the module to print the 20 most scheduled tasks

Tasks:

- Maintain a rb-Tree with key as the accumulative time spent by task
  on CPU and value as the stack trace
- When a task is scheduled out, remove the old entry of task from
  rb-tree and add the new acculmulative time spend and stack trace to
  rb-tree
- Modify the open function of proc file to print the top 20 most
  scheduled tasks. Print the stack trace and the time spent on CPU.

Deliverables:

- Load `perftop` module
- Invoke `cat /proc/perftop`
- Add screenshot of the output
- Upload the source code tarball


Part 3. Print 20 most scheduled tasks with function name
--------------------------------------------------------

[11%] Modify the module to print the 20 most scheduled tasks
with function names for kernel tasks

Task:

- Modify the open function of proc file to print the function name of
  each function in a stack trace instead of return address

Deliverables:

- Load `perftop` module
- Invoke `cat /proc/perftop`
- Add screenshot of the output
- Upload the source code tarball
