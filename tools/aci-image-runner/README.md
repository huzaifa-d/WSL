# ACI image runner

The runner forwards guest stdout and stderr separately, without modifying their
bytes. The agent uses a shared output pump: if either host output consumer stops
reading and the buffers fill, output on both streams and the guest command can
pause until that consumer resumes. Backpressure does not cause the runner to
discard output.
