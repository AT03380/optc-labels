# Description of assigned labels

Due to the complexity and richness of the OpTC dataset it is not enough to
assign a single label to an event.

In this work, we provide **five classes** of labels for each event.  Their
purpose and meaning are documented below.

## Event outcome

- `malicious` | **Malicious**: the event is identified as part of an attack.
- `benign` | **Benign**: the complement set of events.  All events that are not marked as malicious are considered benign.

## Event source

- `ground` | **Ground truth**: the event is directly mentioned in the ground truth document of the red team activity.
- `correlated` | **Correlated event**: the event is correlated with another malicious process through the labeling process outlined in the article.
- `anomaly` | **Major anomaly**: the event represents a strong deviation from the baseline activity of the dataset. See the explanation below.
- `invalid` | **Invalid correlation**: an extra event that was incorrectly correlated with a malicious process because of missing data or an error in the reconstructed process tree. These events should be disregarded.

## Actor

- `red` | **Red team**: the malicious event was attributed to the red team.
- `admin` | **Administrator**: the malicious event that was *NOT* attributed to the red team.  See the explanation below.

## Timeline

- `prior` | **Prior to red team campaign**: the event occurs before the official start of the red team campaign.
- `day1` | **Campaign day 1**.
- `day2` | **Campaign day 2**.
- `day3` | **Campaign day 3**.

## Granularity

- `process` | **Process**: the full process execution is considered malicious.
- `event` | **Event**: a single malicious event of an otherwise benign process.

## Major anomalies

To start our labeling process, we use two types of seed events: malicious red
team activity directly mentioned in the ground truth document, and major
outlier events identified by our baseline anomaly detection models, as
described in the article. We use the *event source* label class to distinguish
between the two types of events.

## Administrator activity

During our analysis, we identified several process executions that show clear
indicators of malicious behaviour, but do not intersect in time with the
documented red team activity. This raises a question about how to label them:
as *benign*, since they are not mentioned in the ground truth document; or
*malicious*, since they closely resemble the real malicious activity of the red
team.

To resolve this problem, we introduce an additional class indicating whether a
malicious event can be traced back to the ground truth document. If this is not
possible, we conclude that the malicious action was performed by the system
administrator (the authors of the OpTC dataset).

This additional information should contribute to the creation of explainable
IDS that can not only identify malicious activity with precision, but also
reduce the number of false positives by correctly attributing events to normal
administrative activity.
