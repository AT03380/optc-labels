# Errata

## Invalid correlations

The provided `tasks.json` file contains several entries that are labeled as
`invalid`.

Because of both missing data in the original dataset and the errors in the
reconstructed process tree, some processes were incorrectly identified as
malicious.  The proposed labeling method unconditionally propagates the
malicious label from the parent to all children. Incorrect parent-child
associations can lead to a large number of incorrectly labeled processes. To
prevent this from happening, the security analyst manually overrode the
assigned label from `malicious` to `benign` and `invalid` during the labelling
process.

These entries should be ignored during raw event matching. They represent
additional events that should not affect the accuracy of the labels.

## conhost.exe process labeling

The `conhost.exe` process executions were labeled inconsistently.

According to Windows documentation, the Windows Console Host is a helper
process that provides the user interface for command-line client applications.
It is spawned by Windows OS for every execution of the `cmd.exe` process.

In the OpTC dataset, most of the red team attacks start with a PowerShell and
`cmd.exe` script execution, which results in the creation of the `conhost.exe`
process.  In this case, it inherits the label from its parent process and is
labelled as malicious.

However, the provided `tasks.json` file includes several entries where the
`conhost.exe` labeled as `benign` child of a `malicious` process.  Notably, in
cases where it is incorrectly identified as a child process of `PING.EXE` (see
the previous section).

If this inconsistent labeling negatively affects the performance of the model,
it is recommended to filter out the `conhost.exe` process events from the
evaluation set.  As a byproduct of the design of the Windows Console Subsystem,
by itself, it does not represent the malicious red team activity.

## Event matching granularity

The original labeling method proposed in the article is performed at the
process level. This *granularity* is appropriate for labeling because it
provides a security analyst with a rich context and allows automatic label
propagation from parent to child processes.

However, when the resulting labels are translated back to event-level
granularity, they may incorrectly label large chunks of system activity as
malicious.

Consider the following entry from the ground truth document on Day 1:

```
09/23/19 13:24:36 -- On Sysclient0201 agent LUAVR71T, pivoted to Sysclient0402 using invoke_wmi
```

In the available telemetry, this corresponds to a `FLOW` event started by the
`svchost.exe -k RPCSS` system service. If the malicious label of this event is
applied to the whole process, it will result in incorrectly identifying every
network connection of this host as malicious.

To prevent this, we introduce an additional fifth label class `granularity`, in
addition to the four originally proposed in the article.

This class is used by the `matcher.go` script. If the task contains the
`process` label, all events associated with that process will be marked as
`malicious`.  Alternatively, if the task contains the `event` label, only that
specific event will be included in the output, and the overall process will be
considered benign.
