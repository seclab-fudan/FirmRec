# FirmRec Pipeline

## Run FirmRec

FirmRec involves multiple steps to perform end-to-end recurring vulnerability detection. To ease the use, we tend to integrate all the steps into this nutshell module, i.e., `firmrec.pipeline`. 

Following command runs all steps in order

```
python -m firmrec.pipeline all
```

You can see the steps by running `python -m firmrec.pipeline`, which ask for the index of the step to run. Each step of pipeline will first generate a command lists named after the step name under `inout/cmds` directory, and then generate a log file during runing, which records output and error messages. The internal results of each step will also be recorded under the inout directory accordingly.

You can also run each steps separately:

1. Run prepare steps

```
python -m firmrec.pipeline 1.1 1.2 1.3 1.4 1.5
```

2. Run input entry analysis

```
python -m firmrec.pipeline 2.1 2.2 2.3 2.4
```

3. Run signature generation
```
python -m firmrec.pipeline 3.1 3.2 3.3
```

4. Run vulnerability detection and show results
```
python -m firmrec.pipeline 4.1 4.2 4.3 4.4
```

## Interpreting Results

The vulnerability detection results will be presented in CSV format after running step 4.4. Except the header line, each result line represents a vulnerability alarm. Here is the meaning of each field in the CSV data sheet.

|Fields      | Description |
|------------|-------------|
|firmware_id | Alarmed firmware name|
|vendor      | Alarmed firmware vendor|
|bin_path    | Alarmed binary path relative to the extracted filesystem |
|entry_addr  | Alarmed function address |
|source      | The vulnerable input reading function name |
|keyword     | The keyword used to read malicious input |
|sink        | The function where the vulnerability can be triggered |
|vuln_reason | The vulnerability type |
|run_time    | Duration (in seconds) of concolic execution |

Among these `fields`, `firmware_id`, `vendor`, `bin_path`, entry_addr will help to locate the alarmed function, where `source` and `keyword` further indicate an exploitable input entry; The `sink` and `vuln_reason` fields demonstrate where and why the vulnerability is detected by concolic execution.
These alarms should be further verified to find real vulnerabilities. For example, manually inspect the alarmed sites or leverage directed fuzzing to trigger the vulnerability.

## Updating Code

If any modification is made to FirmRec source code, you can update the Docker container with `make build` and then execute `make start` to respawn a docker shell.
There is no need to rerun all previously finished steps after the update, but just rerun `python -m firmrec.pipeline 2.1` in the docker shell to restore the input entry database.
