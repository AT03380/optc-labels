# How to use this repository

This repository contains the implementation of the method described in the
article, as well as the final output of the labelling process that identifies
malicious events in the OpTC dataset.

## Repository structure

### labeler/

The `labeler/` path contains the full source code of the original implementation.

The final output of the labeling process is included in the repository, so
running this code is **not necessary**. It is provided for completeness only.
However, if you want to view the complete event context, or modify the labels,
place the `tasks.json` file in the working directory of the process.

### labels/

The `labels/` path contains a subset of raw events with assigned labels.

Each file in this directory corresponds to one label. For example, all events
included in the `malicious.zip` file are labeled as *malicious*. All other events
from the OpTC dataset not included in this file are therefore labeled as
benign.

### tasks/

The `tasks.json` file is used by the `labeler` script to track the state. It
contains the original raw events, parts of the reconstructed process tree,
entries from the ground truth document, and the assigned labels.

The version included in the repository is the final output with the labels
assigned by the security analyst.

Each task in this file indicates the raw event ID and the process object ID, so
it can be directly used to assign labels to the raw events of the OpTC dataset.
This can be done with the help of the `matcher.go` script:

```bash
find /path/to/optc/ecar/ -name "*.json.gz" -exec zcat {} \; | go run labeler/matcher/matcher.go -label malicious > malicious.json
```

The output of this command is already provided in the `labels/` directory.

## Using labels for evalution

Extract all Zip archives in the `labels/` and use the following code to load them into a dataframe:

```python
def load_optc_labels_to_pandas(filename):
    import json
    import pandas as pd

    columns = ('timestamp', 'hostname', 'id', 'object', 'action', 'actorID', 'objectID')
    data = []
    with open(filename) as f:
        for line in f:
            j = json.loads(line)
            data.append((j[i] for i in columns))

    return pd.DataFrame(data, columns=columns)


def load_optc_labels_to_polars(filename):
    import json
    import polars as pl

    columns = ('timestamp', 'hostname', 'id', 'object', 'action', 'actorID', 'objectID')
    data = {k: [] for k in columns}
    with open(filename) as f:
        for line in f:
            j = json.loads(line)
            for k in columns:
                data[k].append(j[k])

    return pl.DataFrame(data)
```

The `id` column contains a unique UUID of each event. In the simplest use case,
you can count true positives and false positives by checking if the event ID
exists in the dataframe. In more complex detection scenarios, you will need to
aggregate and transform the dataframe to suit your needs.

The `malicious` label contains the most complete set of events.

The other files in the `labels/` directory are more specific subsets and do not
include extra events that are not present in the `malicious` file.
