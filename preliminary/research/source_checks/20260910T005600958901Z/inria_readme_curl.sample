This README file was generated on 2026-01-20 by Frédéric Majorczyk.
Last updated: 2026-01-20.
 
# GENERAL INFORMATION
 
## Dataset title: Corrected version of the DARPA OpTC dataset
 
## DOI: 10.57745/UXCWOC
 
## Contact email: frederic.majorczyk@irisa.fr
 
# METHODOLOGICAL INFORMATION 
 
## Description of sources and methods used to collect and generate data:

Before processing the original dataset to fix the errors, we split the logs by
client and sort them by timestamp. We also split the logs by day. After the
preprocessing, there is only one file by client and by day that contains the
logs of that client for that day.

For fixing the errors, we use the scripts provided in the directory
"corrections" of the gitlab:

https://gitlab.inria.fr/fmajorcz/a_new_hope_for_darpa_optc

The labels for the original and corrected versions of the dataset are also
available on this gitlab in the directory "labelling".

# DATA & FILE OVERVIEW
 
## File naming convention:

Each file in the dataset is an archive named "YYYY-MM-DD.tar" and contains the
logs for the different clients for the day specified in the file name. Contrary
to the original dataset, the logs are split for each client and are sorted by
timestamp. So there is only one file by day and by client (named
AIA-XXX-YYY.ecar-YYYY-MM-DD-sysclient0ZZZ.json.gz with ZZZ the id of the client
and XXX and YYY explained just after). The files are grouped by 25 clients in
each subdirectory of the archive file. Each subdirectory is named "AIA-XXX-YYY"
with XXX the id of the first client in the subdirectory and YYY (= XXX + 24) the
id of the last client in the subdirectory.
